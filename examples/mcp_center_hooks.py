"""MCPCenterVerifier: FastMCP's JWTVerifier plus MCP Center's revocation feed and usage reports.

A plain ``JWTVerifier`` checks tokens offline against the JWKS, which is fast but has two gaps: a token the
owner revoked keeps working until it expires, and MCP Center never learns that the token was used. This
verifier closes both without introspecting every request:

* every ``poll_interval`` seconds it fetches ``POST <issuer>/oauth/revoked`` (revoked, not yet expired
  tokens) and rejects those jtis locally;
* every ``flush_interval`` seconds it reports how often each jti was verified to
  ``POST <issuer>/oauth/usage``, which feeds the token's "last used" and the dashboard statistics.

Both endpoints require a *confidential* client registered in the MCP Center console (OAuth Clients ->
Register trusted client). Give the verifier either that client's secret or, for ``private_key_jwt``
clients, the private key PEM and its kid.

Usage::

    from fastmcp.server.auth import RemoteAuthProvider
    from mcp_center_hooks import MCPCenterVerifier

    auth = RemoteAuthProvider(
        token_verifier=MCPCenterVerifier(
            jwks_uri="https://auth.example.com/.well-known/jwks.json",
            issuer="https://auth.example.com",
            audience="https://mcp.example.com/mcp",
            client_id="mcpc_...", client_secret="...",
        ),
        authorization_servers=[AnyHttpUrl("https://auth.example.com")],
        base_url="https://mcp.example.com",
    )

Copy this single file next to your server; it needs only ``fastmcp`` and ``httpx`` (``pyjwt`` and
``cryptography`` as well when using ``private_key_pem``).
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from typing import Any, Optional

import httpx
from fastmcp.server.auth.providers.jwt import JWTVerifier

ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
logger = logging.getLogger("mcp_center_hooks")


class MCPCenterVerifier(JWTVerifier):
    def __init__(
        self,
        *,
        client_id: str,
        client_secret: Optional[str] = None,
        private_key_pem: Optional[str] = None,
        kid: Optional[str] = None,
        assertion_alg: str = "RS256",
        poll_interval: float = 15.0,
        flush_interval: float = 30.0,
        http_client: Optional[httpx.AsyncClient] = None,
        **jwt_verifier_kwargs: Any,
    ):
        if not client_secret and not private_key_pem:
            raise ValueError("MCPCenterVerifier needs client_secret or private_key_pem")
        if not jwt_verifier_kwargs.get("issuer") or isinstance(jwt_verifier_kwargs["issuer"], list):
            raise ValueError("MCPCenterVerifier needs a single issuer (the MCP Center URL)")
        super().__init__(http_client=http_client, **jwt_verifier_kwargs)
        self.center = str(jwt_verifier_kwargs["issuer"]).rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.private_key_pem = private_key_pem
        self.kid = kid
        self.assertion_alg = assertion_alg
        self.poll_interval = poll_interval
        self.flush_interval = flush_interval
        self._http = http_client or httpx.AsyncClient(timeout=10.0)
        self._revoked: dict[str, int] = {}       # jti -> exp
        self._pending: dict[str, list] = {}      # jti -> [count, last_seen]
        self._last_poll: Optional[int] = None
        self._task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------ verification
    async def verify_token(self, token: str):
        self._ensure_running()
        result = await super().verify_token(token)
        if result is None:
            return None
        jti = (result.claims or {}).get("jti")
        if jti and jti in self._revoked:
            logger.info("Bearer token rejected for client %s: revoked (jti %s)", result.client_id, jti)
            return None
        if jti:
            entry = self._pending.setdefault(jti, [0, 0])
            entry[0] += 1
            entry[1] = int(time.time())
        return result

    # ------------------------------------------------------------------ background sync
    def _ensure_running(self) -> None:
        if self._task is None or self._task.done():
            try:
                self._task = asyncio.get_running_loop().create_task(self._run())
            except RuntimeError:
                pass  # no loop yet (verifier constructed at import time); the first request will start it

    async def _run(self) -> None:
        next_poll = 0.0
        next_flush = time.monotonic() + self.flush_interval
        while True:
            now = time.monotonic()
            try:
                if now >= next_poll:
                    await self.poll_revoked()
                    next_poll = now + self.poll_interval
                if now >= next_flush:
                    await self.flush_usage()
                    next_flush = now + self.flush_interval
            except Exception as e:  # keep the loop alive; the next tick retries
                logger.warning("MCP Center sync failed: %s", e)
            await asyncio.sleep(max(0.5, min(next_poll, next_flush) - time.monotonic()))

    async def close(self) -> None:
        if self._task:
            self._task.cancel()
        try:
            await self.flush_usage()
        finally:
            await self._http.aclose()

    async def sync_once(self) -> None:
        """Poll the feed and flush usage right now (tests, shutdown hooks)."""
        await self.poll_revoked()
        await self.flush_usage()

    async def poll_revoked(self) -> None:
        form = {"since": str(self._last_poll)} if self._last_poll is not None else {}
        data = await self._post("/oauth/revoked", form)
        now = int(data.get("now", time.time()))
        for item in data.get("revoked", []):
            self._revoked[item["jti"]] = int(item.get("exp", now + 3600))
        # forget entries once the token would have expired anyway
        for jti in [j for j, exp in self._revoked.items() if exp < now]:
            self._revoked.pop(jti, None)
        # overlap the window by a few seconds so a revocation racing the previous poll is not missed
        self._last_poll = max(0, now - 5)

    async def flush_usage(self) -> None:
        async with self._lock:
            batch, self._pending = self._pending, {}
        if not batch:
            return
        events = [{"jti": jti, "count": count, "last_seen": last_seen} for jti, (count, last_seen) in batch.items()]
        try:
            await self._post("/oauth/usage", {"events": json.dumps(events)})
        except Exception:
            async with self._lock:  # put the batch back so nothing is lost on a transient failure
                for jti, (count, last_seen) in batch.items():
                    entry = self._pending.setdefault(jti, [0, 0])
                    entry[0] += count
                    entry[1] = max(entry[1], last_seen)
            raise

    # ------------------------------------------------------------------ client authentication
    def _auth_fields(self) -> dict:
        if self.private_key_pem:
            import jwt  # pyjwt, only needed for private_key_jwt clients

            now = int(time.time())
            assertion = jwt.encode(
                {"iss": self.client_id, "sub": self.client_id, "aud": f"{self.center}/oauth/token",
                 "iat": now, "exp": now + 60, "jti": uuid.uuid4().hex},
                self.private_key_pem, algorithm=self.assertion_alg, headers={"kid": self.kid} if self.kid else None,
            )
            return {"client_assertion_type": ASSERTION_TYPE, "client_assertion": assertion}
        return {"client_id": self.client_id, "client_secret": self.client_secret}

    async def _post(self, path: str, form: dict) -> dict:
        r = await self._http.post(f"{self.center}{path}", data={**self._auth_fields(), **form})
        r.raise_for_status()
        return r.json()
