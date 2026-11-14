"""OAuth signing keys (RS256).

The private key lives only in MCP Gate (stored AES-256-GCM encrypted in the DB); the public key is published via
/.well-known/jwks.json and FastMCP's JWTVerifier uses it to verify signatures. kid = RFC 7638 JWK thumbprint, so
several keys can coexist.

Life of a key (#30):

1. **Published** (pending): made by a rotation -- automatic every ``oauth.signing_key_rotation_days`` (90), or
   "Rotate now" in the console -- and put in the JWKS ``oauth.signing_key_prepublish_minutes`` (one day) before it
   signs anything, so resource servers that cache the JWKS already hold it when its first token arrives.
2. **Active**: the only key that signs. The switch happens at the first token issued after ``activates_at`` (and
   in the scheduler's key job), never in the middle of a grant.
3. **Retired**: verify-only. It stays in the JWKS while a token it signed can still be presented to a resource
   server (the access-token lifetime after retirement, or longer while a live access token / PAT it signed is
   recorded); MCP Gate keeps the key itself until every token it signed has expired -- ``signed_until``, the
   latest expiry it signed, raised atomically with each recorded token -- and then deletes it.
4. **Revoked** (emergency): out of the JWKS at once, its private key wiped, every token record it signed revoked
   (so the revocation feed tells resource servers), and nothing it signed verifies here any more. A revoked
   active key is replaced at once (by the published key if there is one).

Tokens record the kid that signed them. Tokens from before #30 have none and are attributed to the key that was
active when they were issued.
"""

import base64
import hashlib
import json
import logging
from datetime import datetime, timedelta
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy.orm import Session

from db.database import make_session
from db.models import OAuthSigningKey, local_now
from src.adapters import OAuthKeyAdapter, OAuthTokenAdapter
from src.config import Config
from src.utils import public_cache
from src.utils.crypto import decrypt_token, encrypt_token

DEFAULT_ALG = "RS256"
# Lifetime of the unrecorded tokens MCP Gate signs for itself (src/oauth/service.py SCANNER_TOKEN_TTL_SECONDS)
SCANNER_TOKEN_TTL_SECONDS = 120

logger = logging.getLogger(__name__)


def _b64url_uint(value: int) -> str:
    length = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode()


def _thumbprint(n_b64: str, e_b64: str) -> str:
    canonical = json.dumps({"e": e_b64, "kty": "RSA", "n": n_b64}, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(hashlib.sha256(canonical).digest()).rstrip(b"=").decode()


def generate_key_material(bits: Optional[int] = None, alg: str = DEFAULT_ALG) -> dict:
    bits = bits or Config.get_oauth_config().signing_key_bits
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    numbers = private_key.public_key().public_numbers()
    n_b64, e_b64 = _b64url_uint(numbers.n), _b64url_uint(numbers.e)
    kid = _thumbprint(n_b64, e_b64)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return {
        "kid": kid,
        "alg": alg,
        "public_jwk": {"kty": "RSA", "use": "sig", "alg": alg, "kid": kid, "n": n_b64, "e": e_b64},
        "private_pem_enc": encrypt_token(private_pem),
    }


def create_signing_key(db: Session, make_active: bool = True,
                       activates_at: Optional[datetime] = None) -> OAuthSigningKey:
    material = generate_key_material()
    return OAuthKeyAdapter.create(
        db, kid=material["kid"], alg=material["alg"],
        public_jwk=json.dumps(material["public_jwk"], separators=(",", ":")),
        private_pem_enc=material["private_pem_enc"], make_active=make_active, activates_at=activates_at,
    )


def _prepublish() -> timedelta:
    return timedelta(minutes=Config.get_oauth_config().signing_key_prepublish_minutes)


def activate_due_key(db: Session, now: Optional[datetime] = None) -> Optional[OAuthSigningKey]:
    """Promote the published key once its activates_at has come (or at once if no key is active). May commit."""
    pending = OAuthKeyAdapter.get_pending(db)
    if pending is None:
        return None
    now = now or local_now()
    if OAuthKeyAdapter.get_active(db) is not None and pending.activates_at is not None and pending.activates_at > now:
        return None
    key = OAuthKeyAdapter.activate(db, pending.kid)
    if key is not None:
        logger.info(f"Signing key {key.kid[:12]}… is now the active signer")
        from src.audit import AuditAction
        from src.audit.audit_service import record_key_event
        record_key_event(db, AuditAction.OAUTH_KEY_ACTIVATE, key.kid)
    return key


def ensure_active_signing_key(db: Session) -> OAuthSigningKey:
    """The active key, after promoting a published key that is due; a first key is created when there is none.
    May commit, so grants call it before they open their own transaction (see _sign)."""
    activate_due_key(db)
    key = OAuthKeyAdapter.get_active(db)
    if key is None:
        key = create_signing_key(db, make_active=True)
    return key


def current_signer(db: Session) -> OAuthSigningKey:
    """The active key without promoting a due one (no commit unless there is no key at all)."""
    return OAuthKeyAdapter.get_active(db) or ensure_active_signing_key(db)


def schedule_rotation(db: Session, *, activates_at: Optional[datetime] = None) -> OAuthSigningKey:
    """Publish a new key now; it starts signing at ``activates_at`` (default: now + the pre-publish window).
    Raises KeyRotationPending when a published key is already waiting. A zero window activates it at once."""
    pending = OAuthKeyAdapter.get_pending(db)
    if pending is not None:
        raise KeyRotationPending(pending)
    now = local_now()
    when = activates_at or now + _prepublish()
    if when <= now:
        return create_signing_key(db, make_active=True)
    key = create_signing_key(db, make_active=False, activates_at=when)
    logger.info(f"Signing key {key.kid[:12]}… published; it starts signing at {when.isoformat(timespec='seconds')}")
    return key


def rotate_signing_key(db: Session) -> OAuthSigningKey:
    """Rotate now: the same publish-then-activate schedule as the automatic rotation."""
    return schedule_rotation(db)


class KeyRotationPending(Exception):
    def __init__(self, key: OAuthSigningKey):
        super().__init__("a rotation is already scheduled")
        self.key = key


def next_rotation_at(db: Session) -> Optional[datetime]:
    """When the automatic rotation publishes the next key (None: disabled, or a key is already published)."""
    days = Config.get_oauth_config().signing_key_rotation_days
    active = OAuthKeyAdapter.get_active(db)
    if days <= 0 or active is None or OAuthKeyAdapter.get_pending(db) is not None:
        return None
    return active.activated_at + timedelta(days=days) - _prepublish()


def run_key_maintenance(db: Session, now: Optional[datetime] = None) -> dict:
    """The scheduler's key job: promote a due key, publish the next one when the rotation period is up, delete
    retired keys nothing needs any more. Returns what it did."""
    now = now or local_now()
    done = {"activated": None, "published": None, "deleted": []}
    activated = activate_due_key(db, now)
    if activated is not None:
        done["activated"] = activated.kid
    due = next_rotation_at(db)
    if due is not None and now >= due:
        active = OAuthKeyAdapter.get_active(db)
        # Keep the cadence (activated_at + N days) unless MCP Gate was down past it: then a full window from now
        when = max(active.activated_at + timedelta(days=Config.get_oauth_config().signing_key_rotation_days),
                   now + _prepublish())
        done["published"] = schedule_rotation(db, activates_at=when).kid
    for key in OAuthKeyAdapter.list_all(db):
        if is_deletable(db, key, now):
            OAuthKeyAdapter.delete(db, key.kid)
            done["deleted"].append(key.kid)
            logger.info(f"Signing key {key.kid[:12]}… deleted: nothing it signed can still be valid")
    return done


def get_key_by_kid(db: Session, kid: str) -> Optional[OAuthSigningKey]:
    return OAuthKeyAdapter.get_by_kid(db, kid)


def load_private_pem(key: OAuthSigningKey) -> str:
    return decrypt_token(key.private_pem_enc)


def note_signed(db: Session, key: OAuthSigningKey, expires_at: datetime) -> None:
    """Record that ``key`` signed a token valid until ``expires_at`` (left for the caller's commit)."""
    OAuthKeyAdapter.note_signed(db, key.kid, expires_at)


def public_jwk_of(key: OAuthSigningKey) -> dict:
    return json.loads(key.public_jwk)


CLOCK_SKEW = timedelta(minutes=5)


def retired_key_grace() -> timedelta:
    cfg = Config.get_oauth_config()
    if cfg.retired_key_publish_minutes is not None:
        return timedelta(minutes=max(0, cfg.retired_key_publish_minutes))
    return timedelta(minutes=cfg.access_expire_minutes) + CLOCK_SKEW


def token_window(key: OAuthSigningKey) -> tuple:
    """When ``key`` was the signer, for tokens from before #30 that do not record their kid."""
    end = key.rotated_at or local_now()
    return key.activated_at - CLOCK_SKEW, end + CLOCK_SKEW


def is_published(db: Session, key: OAuthSigningKey) -> bool:
    """Whether resource servers should still accept tokens signed by ``key`` (it is in the JWKS)."""
    if key.revoked_at is not None:
        return False
    if key.is_active or key.is_pending:
        return True
    retired = key.rotated_at or key.created_at
    if retired is None or retired > local_now() - retired_key_grace():
        return True
    # A long-lived token it signed (a PAT, or an access token with a custom lifetime) keeps it published until that
    # token expires or is revoked.
    return OAuthTokenAdapter.any_live_signed_by(db, key.kid, *token_window(key))


def unrecorded_token_bound() -> timedelta:
    """How long after retirement a token that was never recorded (scanner / "Inspect as" tokens, which do not raise
    signed_until) can still be valid."""
    return max(retired_key_grace(), timedelta(seconds=SCANNER_TOKEN_TTL_SECONDS) + CLOCK_SKEW)


def legacy_signed_until(key: OAuthSigningKey) -> datetime:
    """For a key retired before #30 (no signed_until): the longest any token could live after its retirement."""
    cfg = Config.get_oauth_config()
    longest = max(timedelta(days=cfg.refresh_expire_days), timedelta(days=cfg.pat_max_days),
                  timedelta(minutes=cfg.access_expire_minutes))
    return (key.rotated_at or key.created_at) + longest


def is_deletable(db: Session, key: OAuthSigningKey, now: Optional[datetime] = None) -> bool:
    """A retired or revoked key that nothing needs any more:

    - it is out of the JWKS and past the window in which an unrecorded token it signed could be valid;
    - every token it signed has expired: ``signed_until`` (raised in the same commit as each recorded token), or the
      longest token lifetime for a key retired before #30 -- a revoked key skips this, nothing it signed verifies;
    - no recorded, unrevoked, unexpired token of any kind (refresh tokens included) is attributed to it.
    """
    now = now or local_now()
    if key.is_active or key.is_pending:
        return False
    stopped = key.rotated_at or key.revoked_at or key.created_at
    if now < stopped + unrecorded_token_bound() or is_published(db, key):
        return False
    if key.revoked_at is None:
        until = key.signed_until if key.signed_until is not None else legacy_signed_until(key)
        if now < until + CLOCK_SKEW:
            return False
    return not OAuthTokenAdapter.any_live_signed_by(db, key.kid, *token_window(key), kinds=None)


def live_token_count(db: Session, key: OAuthSigningKey) -> int:
    """Unexpired, unrevoked recorded tokens (every kind) signed by ``key``: what revoking it stops."""
    if key.revoked_at is not None:
        return 0
    return OAuthTokenAdapter.count_live_signed_by(db, key.kid, *token_window(key))


def revoke_signing_key(db: Session, key: OAuthSigningKey) -> tuple[int, Optional[OAuthSigningKey]]:
    """Emergency revocation (see the module docstring). Returns (tokens revoked, the key that took over if the
    revoked key was the signer)."""
    was_active = key.is_active
    count = OAuthKeyAdapter.revoke(db, key, token_window=token_window(key))
    replacement = None
    if was_active:
        pending = OAuthKeyAdapter.get_pending(db)
        replacement = (OAuthKeyAdapter.activate(db, pending.kid) if pending is not None
                       else create_signing_key(db, make_active=True))
    logger.warning(f"Signing key {key.kid[:12]}… revoked; {count} unexpired token(s) it signed revoked")
    return count, replacement


def published_keys(db: Session) -> list[OAuthSigningKey]:
    return [k for k in OAuthKeyAdapter.list_all(db) if is_published(db, k)]


def get_jwks(db: Session) -> dict:
    return {"keys": [public_jwk_of(k) for k in published_keys(db)]}


# How long a cached JWKS may be served at most. A retired key kept only by a live token it signed drops out when
# that token expires or is revoked, which the cache cannot foresee; this bounds that delay.
JWKS_CACHE_MAX_SECONDS = 30.0


def _seconds_until_next_retirement(db: Session) -> float:
    """Seconds until the next retired key leaves the JWKS on schedule (its grace period ends)."""
    now, grace = local_now(), retired_key_grace()
    ends = [(k.rotated_at or k.created_at) + grace for k in OAuthKeyAdapter.list_all(db)
            if not k.is_active and not k.is_pending and k.revoked_at is None
            and (k.rotated_at or k.created_at) is not None]
    upcoming = [(end - now).total_seconds() for end in ends if end > now]
    return min(upcoming, default=JWKS_CACHE_MAX_SECONDS)


def cached_jwks() -> dict:
    """The JWKS served at /.well-known/jwks.json, from memory; opens a session only on a cache miss.

    Invalidated by OAuthKeyAdapter whenever a key is created or deleted (rotation), and expires on its own at the
    next scheduled retirement or after JWKS_CACHE_MAX_SECONDS, whichever comes first, so a retired key leaves the
    JWKS on time."""

    def build():
        db = make_session()
        try:
            ttl = min(JWKS_CACHE_MAX_SECONDS, max(_seconds_until_next_retirement(db), 0.0))
            return get_jwks(db), ttl
        finally:
            db.close()

    return public_cache.get_or_build_expiring("jwks", build)
