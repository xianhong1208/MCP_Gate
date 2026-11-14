#!/usr/bin/env bash
# End-to-end check of the Docker image. From the repository root:
#
#   bash scripts/docker_smoke.sh                        # builds mcp-gate:smoke first
#   IMAGE=mcp-gate:local SKIP_BUILD=1 bash scripts/docker_smoke.sh
#
# Starts the image on two fresh volumes, checks health, discovery and the console, signs in and verifies a token it
# issues, checks the generated secrets landed in their own volume (not in the data volume), then restarts and
# recreates the container and checks the same secrets and signing key are still in use, then starts it on an empty
# secrets volume (a lost volume) and checks it refuses to start instead of generating a new key. Everything it creates
# is removed on exit.
# SMOKE_PREFIX / SMOKE_PORT change the container and volume names and the published port.
set -euo pipefail

IMAGE="${IMAGE:-mcp-gate:smoke}"
PREFIX="${SMOKE_PREFIX:-mcp-gate-smoke}"
NAME="$PREFIX"
DATA_VOLUME="$PREFIX-data"
SECRETS_VOLUME="$PREFIX-secrets"
LOST_VOLUME="$PREFIX-secrets-lost"
PORT="${SMOKE_PORT:-4598}"
BASE="http://localhost:$PORT"
EMAIL="smoke@example.com"
PASSWORD="Smoke-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"

cleanup() {
    status=$?
    if [ $status -ne 0 ]; then
        echo "---- container log (last 100 lines) ----"
        docker logs --tail 100 "$NAME" 2>&1 || true
    fi
    docker rm -fv "$NAME" >/dev/null 2>&1 || true
    docker volume rm "$DATA_VOLUME" "$SECRETS_VOLUME" "$LOST_VOLUME" >/dev/null 2>&1 || true
    exit $status
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {}, {'d': d}))" "$1"; }
# Runs a command in a throwaway container of the same image with both volumes mounted read-only
inspect_volumes() {
    docker run --rm --entrypoint sh -v "$DATA_VOLUME:/vol/data:ro" -v "$SECRETS_VOLUME:/vol/secrets:ro" \
        "$IMAGE" -c "$1"
}

if [ "${SKIP_BUILD:-0}" != "1" ]; then
    docker build -t "$IMAGE" .
fi

docker rm -fv "$NAME" >/dev/null 2>&1 || true
docker volume rm "$DATA_VOLUME" "$SECRETS_VOLUME" "$LOST_VOLUME" >/dev/null 2>&1 || true
docker volume create "$DATA_VOLUME" >/dev/null
docker volume create "$SECRETS_VOLUME" >/dev/null

# start [secrets volume]: the secrets volume defaults to $SECRETS_VOLUME
start() {
    docker run -d --name "$NAME" -p "127.0.0.1:$PORT:4568" \
        -v "$DATA_VOLUME:/app/data" -v "${1:-$SECRETS_VOLUME}:/app/secrets" \
        -e OAUTH_ISSUER="$BASE" -e ADMIN_EMAIL="$EMAIL" -e ADMIN_PASSWORD="$PASSWORD" \
        --health-interval 2s --health-start-period 60s \
        "$IMAGE" >/dev/null
}

wait_healthy() {
    for _ in $(seq 1 90); do
        state="$(docker inspect -f '{{.State.Health.Status}}' "$NAME" 2>/dev/null || echo missing)"
        [ "$state" = healthy ] && return 0
        [ "$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)" = true ] || fail "the container exited"
        sleep 1
    done
    fail "the container did not become healthy (last state: $state)"
}

kid() { curl -fsS "$BASE/.well-known/jwks.json" | json "','.join(sorted(k['kid'] for k in d['keys']))"; }
secrets_digest() { inspect_volumes 'sha256sum /vol/secrets/secrets.json' | cut -d' ' -f1; }

# Signs in, issues a personal access token and verifies its signature against the JWKS (inside the container,
# which has PyJWT); prints the kid that signed it
signed_kid() { docker exec -i "$NAME" python - "$BASE" "$EMAIL" "$PASSWORD" < scripts/docker_smoke_token.py; }

login() {
    curl -fsS -o /dev/null -w '%{http_code}' -X POST "$BASE/api/session/login" \
        -H 'Content-Type: application/json' -H "Origin: $BASE" \
        -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}"
}

start
wait_healthy
echo "ok: container is healthy (Docker HEALTHCHECK on /health)"

[ "$(docker exec "$NAME" id -u)" = 10001 ] || fail "the server does not run as uid 10001"
echo "ok: runs as the unprivileged user (uid 10001)"

[ "$(curl -fsS "$BASE/health" | json "d['status']")" = ok ] || fail "/health is not ok"
issuer="$(curl -fsS "$BASE/.well-known/oauth-authorization-server" | json "d['issuer']")"
[ "$issuer" = "$BASE" ] || fail "discovery issuer is $issuer, expected $BASE"
echo "ok: discovery issuer is $issuer"

code="$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/login")"
[ "$code" = 200 ] || fail "the console login page answered $code"
echo "ok: console login page 200"

[ "$(login)" = 200 ] || fail "the owner from ADMIN_EMAIL / ADMIN_PASSWORD cannot sign in"
echo "ok: the owner created from ADMIN_EMAIL / ADMIN_PASSWORD signs in"

token_kid="$(signed_kid)" || fail "could not issue and verify a personal access token"
[ "$token_kid" = "$(kid)" ] || fail "the token was signed by $token_kid, not the published key"
echo "ok: a personal access token verifies against the JWKS (kid $token_kid)"

# The generated secrets live in the secrets volume, never next to the database (#29)
inspect_volumes 'test -s /vol/secrets/secrets.json' || fail "secrets.json is not in the secrets volume"
inspect_volumes 'test ! -e /vol/data/secrets.json' || fail "secrets.json was written into the data volume"
inspect_volumes 'test -s /vol/data/mcp_gate.db' || fail "the database is not in the data volume"
mode="$(inspect_volumes 'stat -c %a /vol/secrets /vol/secrets/secrets.json' | tr '\n' ' ')"
[ "$mode" = "700 600 " ] || fail "secrets directory / file modes are $mode, expected 700 600"
echo "ok: secrets.json in its own volume (modes $mode), database in the data volume"

# The file logs are off in the image: nothing may pile up in the container's writable layer
docker exec "$NAME" test ! -e /app/logs || fail "/app/logs exists: file logging is on in the image"
echo "ok: logs go to the console only"

kid_before="$(kid)"
digest_before="$(secrets_digest)"

docker restart "$NAME" >/dev/null
wait_healthy
[ "$(kid)" = "$kid_before" ] || fail "the signing key changed after a restart"
[ "$(secrets_digest)" = "$digest_before" ] || fail "secrets.json changed after a restart"
echo "ok: after a restart the same signing key ($kid_before) and secrets are in use"

# An upgrade replaces the container: everything must come back from the two volumes
docker rm -fv "$NAME" >/dev/null
start
wait_healthy
[ "$(kid)" = "$kid_before" ] || fail "the signing key changed after recreating the container"
[ "$(secrets_digest)" = "$digest_before" ] || fail "secrets.json changed after recreating the container"
[ "$(login)" = 200 ] || fail "the owner cannot sign in after recreating the container"
[ "$(signed_kid)" = "$kid_before" ] || fail "no token signed by the same key after recreating the container"
echo "ok: after recreating the container the same key and secrets are in use, the owner signs in, a new token verifies"

# A lost secrets volume: the database still holds signing keys encrypted with the old ENCRYPTION_KEY. The server must
# exit with a clear error, not generate a new key, start healthy and then answer every token request with a 500
docker rm -fv "$NAME" >/dev/null
docker volume create "$LOST_VOLUME" >/dev/null
start "$LOST_VOLUME"
for _ in $(seq 1 90); do
    [ "$(docker inspect -f '{{.State.Running}}' "$NAME")" = true ] || break
    [ "$(docker inspect -f '{{.State.Health.Status}}' "$NAME")" = healthy ] && fail "started healthy on a lost secrets volume"
    sleep 1
done
[ "$(docker inspect -f '{{.State.Running}}' "$NAME")" = false ] || fail "still running on a lost secrets volume"
exit_code="$(docker inspect -f '{{.State.ExitCode}}' "$NAME")"
[ "$exit_code" != 0 ] || fail "exited with code 0 on a lost secrets volume"
docker logs "$NAME" 2>&1 | grep -q "The encryption key does not match the database" \
    || fail "the log does not say the encryption key does not match the database"
docker run --rm --entrypoint sh -v "$LOST_VOLUME:/vol/secrets:ro" "$IMAGE" \
    -c '! grep -qs ENCRYPTION_KEY /vol/secrets/secrets.json' || fail "a new ENCRYPTION_KEY was generated"
echo "ok: on a lost secrets volume the container exits ($exit_code) saying the key does not match; no key generated"

# Restoring the secrets volume brings it back with the same key
docker rm -fv "$NAME" >/dev/null
docker volume rm "$LOST_VOLUME" >/dev/null
start
wait_healthy
[ "$(signed_kid)" = "$kid_before" ] || fail "no token signed by the same key after restoring the secrets volume"
echo "ok: with the secrets volume restored it starts healthy and signs with the same key"

docker rm -fv "$NAME" >/dev/null

# docker-compose.yml as shipped (no .env): the issuer defaults to the published port, and the database and the
# secrets get one named volume each
export COMPOSE_PROJECT_NAME="$PREFIX-compose" MCP_GATE_IMAGE="$IMAGE" MCP_GATE_PORT="$PORT"
compose_down() { docker compose down -v --remove-orphans >/dev/null 2>&1 || true; }
trap 'docker compose logs --tail 100 2>/dev/null || true; compose_down; cleanup' EXIT
docker compose up -d --no-build >/dev/null
for _ in $(seq 1 90); do
    curl -fsS "$BASE/health" >/dev/null 2>&1 && break
    sleep 1
done
issuer="$(curl -fsS "$BASE/.well-known/oauth-authorization-server" | json "d['issuer']")"
[ "$issuer" = "$BASE" ] || fail "compose: discovery issuer is $issuer, expected $BASE"
for volume in data secrets; do
    docker volume inspect "${COMPOSE_PROJECT_NAME}_mcp-gate-$volume" >/dev/null || fail "compose: no $volume volume"
done
docker compose exec -T mcp-gate test -s /app/secrets/secrets.json || fail "compose: secrets.json not in /app/secrets"
docker compose exec -T mcp-gate test ! -e /app/data/secrets.json || fail "compose: secrets.json in /app/data"
echo "ok: docker compose up serves issuer $issuer with separate data and secrets volumes"
compose_down
trap cleanup EXIT

echo "docker smoke test passed"
