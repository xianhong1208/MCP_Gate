"""OAuth signing keys (RS256).

The private key lives only in MCP Center (stored AES-256-GCM encrypted in the DB); the public key is published via
/.well-known/jwks.json and FastMCP's JWTVerifier uses it to verify signatures. kid = RFC 7638 JWK thumbprint, so
several keys can coexist: on rotation the old key is retired (no longer signs) but stays in the JWKS, so old tokens
that have not yet expired still verify.
"""

import base64
import hashlib
import json
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy.orm import Session

from db.models import OAuthSigningKey
from src.adapters import OAuthKeyAdapter
from src.config import Config
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


def get_jwks(db: Session) -> dict:
    return {"keys": [public_jwk_of(k) for k in OAuthKeyAdapter.list_all(db)]}
