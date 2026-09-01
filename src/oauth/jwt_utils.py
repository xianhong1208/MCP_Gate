"""RS256 JWT sign / verify primitives."""

import json
from typing import Optional

import jwt


class JWTVerifyError(Exception):
    pass


def sign_rs256(payload: dict, private_pem: str, kid: str, typ: str = "at+jwt") -> str:
    """Issue a JWT; the header carries kid (so verifiers can pick the matching public key from the JWKS) and typ
    (RFC 9068)."""
    return jwt.encode(payload, private_pem, algorithm="RS256", headers={"kid": kid, "typ": typ})


def unverified_header(token: str) -> dict:
    try:
        return jwt.get_unverified_header(token)
    except jwt.InvalidTokenError as e:
        raise JWTVerifyError(f"malformed token: {e}")


def decode_rs256(token: str, public_jwk: dict, *, issuer: Optional[str] = None,
                 audience: Optional[str] = None, leeway: int = 10) -> dict:
    """Verify signature + exp with the public JWK (+ iss / aud when specified)."""
    try:
        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(public_jwk))
        options = {}
        kwargs = {"algorithms": ["RS256"], "leeway": leeway}
        if audience is not None:
            kwargs["audience"] = audience
        else:
            options["verify_aud"] = False
        if issuer is not None:
            kwargs["issuer"] = issuer
        return jwt.decode(token, public_key, options=options, **kwargs)
    except jwt.ExpiredSignatureError:
        raise JWTVerifyError("token expired")
    except jwt.InvalidTokenError as e:
        raise JWTVerifyError(f"invalid token: {e}")


def unverified_claims(token: str) -> dict:
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except jwt.InvalidTokenError:
        return {}
