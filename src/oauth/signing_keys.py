"""OAuth signing keys (RS256).

The private key lives only in MCP Gate (stored AES-256-GCM encrypted in the DB); the public key is published via
/.well-known/jwks.json and FastMCP's JWTVerifier uses it to verify signatures. kid = RFC 7638 JWK thumbprint, so
several keys can coexist: on rotation the old key is retired (no longer signs) but stays in the JWKS while tokens it
signed can still be valid -- the access-token lifetime after rotation (``oauth.retired_key_publish_minutes``), or
longer while a live access token / PAT it signed is still recorded. After that it is dropped from the JWKS, so a
leaked old key stops minting tokens resource servers accept. MCP Gate keeps the key itself to verify the refresh
tokens it signed (they are only ever presented to MCP Gate).
"""

import base64
import hashlib
import json
from datetime import timedelta
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


def create_signing_key(db: Session, make_active: bool = True) -> OAuthSigningKey:
    m = generate_key_material()
    return OAuthKeyAdapter.create(
        db, kid=m["kid"], alg=m["alg"],
        public_jwk=json.dumps(m["public_jwk"], separators=(",", ":")),
        private_pem_enc=m["private_pem_enc"], make_active=make_active,
    )


def ensure_active_signing_key(db: Session) -> OAuthSigningKey:
    key = OAuthKeyAdapter.get_active(db)
    if key is None:
        key = create_signing_key(db, make_active=True)
    return key


def rotate_signing_key(db: Session) -> OAuthSigningKey:
    """Generate a new key and make it active; old keys are retired but kept for verification."""
    return create_signing_key(db, make_active=True)


def get_key_by_kid(db: Session, kid: str) -> Optional[OAuthSigningKey]:
    return OAuthKeyAdapter.get_by_kid(db, kid)


def load_private_pem(key: OAuthSigningKey) -> str:
    return decrypt_token(key.private_pem_enc)


def public_jwk_of(key: OAuthSigningKey) -> dict:
    return json.loads(key.public_jwk)


CLOCK_SKEW = timedelta(minutes=5)


def retired_key_grace() -> timedelta:
    cfg = Config.get_oauth_config()
    if cfg.retired_key_publish_minutes is not None:
        return timedelta(minutes=max(0, cfg.retired_key_publish_minutes))
    return timedelta(minutes=cfg.access_expire_minutes) + CLOCK_SKEW


def is_published(db: Session, key: OAuthSigningKey) -> bool:
    """Whether resource servers should still accept tokens signed by ``key``."""
    if key.is_active:
        return True
    retired = key.rotated_at or key.created_at
    if retired is None or retired > local_now() - retired_key_grace():
        return True
    # A long-lived token it signed (a PAT, or an access token with a custom lifetime) keeps it published until that
    # token expires or is revoked. Tokens are attributed to the key that was active when they were issued.
    return OAuthTokenAdapter.any_live_issued_between(db, key.created_at - CLOCK_SKEW, retired + CLOCK_SKEW)


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
            if not k.is_active and (k.rotated_at or k.created_at) is not None]
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
