"""private_key_jwt client authentication (RFC 7523 / RFC 7521).

A client proves possession of a private key by sending a short-lived JWT as ``client_assertion`` with
``client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer``. We verify it against the
public keys the client registered (inline ``jwks`` or a ``jwks_uri`` fetched and cached), then check the
claims RFC 7523 §3 requires: ``iss`` and ``sub`` are the client_id, ``aud`` names this token endpoint (the
issuer itself is also accepted, as RFC 7523bis recommends), ``exp`` is present and near, and ``jti`` has not
been seen before.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import threading
import time
from typing import Optional
from urllib.parse import urlsplit

import httpx
import jwt
from loguru import logger

from .errors import OAuthError

CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
ASSERTION_ALGS = ["RS256", "ES256"]
MAX_ASSERTION_LIFETIME = 300          # seconds; an assertion is meant to be minted per request
JWKS_CACHE_TTL = 300                  # seconds
JWKS_FETCH_TIMEOUT = 5.0              # seconds
JWKS_FORCED_REFETCH_INTERVAL = 60     # seconds between cache-bypassing refetches of one jwks_uri

_lock = threading.Lock()
_jwks_cache: dict[str, tuple[float, dict]] = {}          # jwks_uri -> (fetched_at, document)
_last_forced: dict[str, float] = {}                       # jwks_uri -> monotonic time of the last forced refetch
_seen_jti: dict[tuple[str, str], float] = {}              # (client_id, jti) -> expires_at


def validate_jwks_document(doc) -> dict:
    """A JWKS is an object with a non-empty ``keys`` array of public JWKs usable for one of ASSERTION_ALGS."""
    if not isinstance(doc, dict) or not isinstance(doc.get("keys"), list) or not doc["keys"]:
        raise OAuthError("invalid_client_metadata", "jwks must be an object with a non-empty keys array")
    for k in doc["keys"]:
        if not isinstance(k, dict) or k.get("kty") not in ("RSA", "EC"):
            raise OAuthError("invalid_client_metadata", "jwks keys must be RSA or EC public keys")
        if k.get("kty") == "RSA" and ("d" in k or not k.get("n")):
            raise OAuthError("invalid_client_metadata", "jwks must contain public RSA keys only")
        if k.get("kty") == "EC" and ("d" in k or not k.get("x")):
            raise OAuthError("invalid_client_metadata", "jwks must contain public EC keys only")
        try:  # the key must actually parse, not just look like one
            jwt.PyJWK(k, algorithm="RS256" if k["kty"] == "RSA" else "ES256")
        except (jwt.PyJWKError, jwt.InvalidKeyError, ValueError) as e:
            raise OAuthError("invalid_client_metadata", f"jwks key {k.get('kid') or ''} could not be parsed: {e}")
    return doc


LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _resolve_host(host: str) -> list[str]:
    """Every address ``host`` resolves to (a literal IP resolves to itself). Separate so tests can stub it."""
    try:
        return sorted({info[4][0] for info in socket.getaddrinfo(host, None)})
    except socket.gaierror:
        return []


def _is_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Globally routable unicast only: excludes private, loopback, link-local, carrier-grade NAT
    (100.64.0.0/10, where some cloud metadata services live), documentation, reserved and multicast ranges."""
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                                 or ip.is_multicast or ip.is_unspecified)


def _pinned_address(jwks_uri: str, *, allow_loopback: bool) -> str:
    """Validate ``jwks_uri`` (see validate_jwks_uri) and return the one address the fetch must connect to."""
    parts = urlsplit(jwks_uri)
    host = (parts.hostname or "").rstrip(".").lower()
    if parts.username or parts.password or not host:
        raise OAuthError("invalid_client_metadata", "jwks_uri must be an absolute URL without credentials")
    loopback = host in LOOPBACK_HOSTS or host.endswith(".localhost")
    if loopback:
        if not allow_loopback:
            raise OAuthError("invalid_client_metadata", "jwks_uri may not point at this machine")
        if parts.scheme not in ("http", "https"):
            raise OAuthError("invalid_client_metadata", "jwks_uri must be http(s)")
    elif parts.scheme != "https":
        raise OAuthError("invalid_client_metadata", "jwks_uri must be https")
    addresses = _resolve_host(host)
    if not addresses:
        raise OAuthError("invalid_client_metadata", f"jwks_uri host {host} does not resolve")
    for addr in addresses:
        ip = ipaddress.ip_address(addr.split("%")[0])
        if loopback and not ip.is_loopback:
            raise OAuthError("invalid_client_metadata", f"jwks_uri host {host} does not resolve to this machine")
        if not loopback and not _is_public(ip):
            raise OAuthError("invalid_client_metadata", f"jwks_uri host {host} resolves to a non-public address")
    return addresses[0].split("%")[0]


def validate_jwks_uri(jwks_uri: str, *, allow_loopback: bool) -> str:
    """A ``jwks_uri`` MCP Gate will fetch server-side. https to a public address only; plain http is accepted
    solely for loopback hosts and only when the deployment itself runs over http (development). The host is
    resolved here and again right before each fetch, and the fetch connects to the address that passed that
    second check (see _get_pinned), so a DNS record cannot be pointed at an internal address later (SSRF via
    rebinding)."""
    _pinned_address(jwks_uri, allow_loopback=allow_loopback)
    return jwks_uri


def _get_pinned(jwks_uri: str, address: str) -> httpx.Response:
    """GET ``jwks_uri`` over a connection to ``address`` instead of whatever the name resolves to now.

    Only the connection target changes: the Host header is the original authority, and TLS sends the original
    hostname as SNI and verifies the certificate against it (httpcore's ``sni_hostname`` extension is used as
    ``server_hostname`` for the handshake). The environment's proxy settings are ignored, since a proxy would
    resolve the name itself."""
    parts = urlsplit(jwks_uri)
    ip_host = f"[{address}]" if ":" in address else address
    netloc = f"{ip_host}:{parts.port}" if parts.port else ip_host
    pinned_url = parts._replace(netloc=netloc).geturl()
    with httpx.Client(verify=True, trust_env=False, follow_redirects=False, timeout=JWKS_FETCH_TIMEOUT) as c:
        return c.get(pinned_url, headers={"Host": parts.netloc},
                     extensions={"sni_hostname": parts.hostname})


def fetch_jwks(jwks_uri: str, *, force: bool = False, allow_loopback: bool = False) -> dict:
    """The JWKS at ``jwks_uri``, cached for JWKS_CACHE_TTL; ``force`` bypasses the cache (unknown kid), at most
    once per JWKS_FORCED_REFETCH_INTERVAL per uri so a stream of unknown kids cannot make every request fetch."""
    now = time.monotonic()
    with _lock:
        hit = _jwks_cache.get(jwks_uri)
        if hit and force:
            if now - _last_forced.get(jwks_uri, float("-inf")) < JWKS_FORCED_REFETCH_INTERVAL:
                return hit[1]
            _last_forced[jwks_uri] = now
    if hit and not force and now - hit[0] < JWKS_CACHE_TTL:
        return hit[1]
    try:  # re-check: the DNS answer may have changed since registration
        address = _pinned_address(jwks_uri, allow_loopback=allow_loopback)
    except OAuthError as e:
        logger.warning("jwks_uri {uri} refused at fetch time: {err}", uri=jwks_uri, err=e.description)
        raise OAuthError("invalid_client", "client keys could not be fetched", 401)
    try:
        r = _get_pinned(jwks_uri, address)
        r.raise_for_status()
        doc = validate_jwks_document(r.json())
    except OAuthError:
        raise
    except Exception as e:  # network, TLS, JSON
        logger.warning("jwks_uri {uri} could not be fetched: {err}", uri=jwks_uri, err=e)
        if hit:
            return hit[1]
        raise OAuthError("invalid_client", "client keys could not be fetched", 401)
    with _lock:
        _jwks_cache[jwks_uri] = (now, doc)
    return doc


def reset_caches() -> None:
    with _lock:
        _jwks_cache.clear()
        _last_forced.clear()
        _seen_jti.clear()


def _remember_jti(client_id: str, jti: str, exp: float) -> bool:
    """False when the jti was already used by this client (replay)."""
    now = time.time()
    with _lock:
        for key, until in [(k, v) for k, v in _seen_jti.items() if v < now]:
            _seen_jti.pop(key, None)
        key = (client_id, jti)
        if key in _seen_jti:
            return False
        _seen_jti[key] = exp
        return True


def _pick_key(keys: list[dict], kid: Optional[str], alg: str) -> Optional[dict]:
    kty = "RSA" if alg == "RS256" else "EC"
    candidates = [k for k in keys if k.get("kty") == kty and (kid is None or k.get("kid") == kid)]
    if kid is None and len(candidates) > 1:
        return None
    return candidates[0] if candidates else None


def _client_keys(client, kid: Optional[str], alg: str, *, allow_loopback: bool) -> dict:
    if client.jwks:
        key = _pick_key(json.loads(client.jwks)["keys"], kid, alg)
    elif client.jwks_uri:
        key = _pick_key(fetch_jwks(client.jwks_uri, allow_loopback=allow_loopback)["keys"], kid, alg)
        if key is None and kid is not None:  # rotation: refetch for an unknown kid (throttled in fetch_jwks)
            key = _pick_key(fetch_jwks(client.jwks_uri, force=True, allow_loopback=allow_loopback)["keys"], kid, alg)
    else:
        raise OAuthError("invalid_client", "client has no registered keys", 401)
    if key is None:
        raise OAuthError("invalid_client", "no registered key matches the assertion", 401)
    return key


def unverified_issuer(assertion: str) -> Optional[str]:
    """The ``iss`` claim without verifying anything; used only to look the client up before verification."""
    try:
        claims = jwt.decode(assertion, options={"verify_signature": False})
    except jwt.InvalidTokenError:
        return None
    iss = claims.get("iss")
    return iss if isinstance(iss, str) else None


def verify_client_assertion(client, assertion: str, *, token_endpoint: str, issuer: str) -> dict:
    """Verify a private_key_jwt assertion for ``client``; return its claims or raise invalid_client.

    May fetch the client's jwks_uri synchronously, so async callers run it off the event loop."""
    allow_loopback = issuer.startswith("http://")  # a plain-http issuer means a development deployment
    try:
        header = jwt.get_unverified_header(assertion)
    except jwt.InvalidTokenError as e:
        raise OAuthError("invalid_client", f"malformed client_assertion: {e}", 401)
    alg = header.get("alg")
    if alg not in ASSERTION_ALGS:
        raise OAuthError("invalid_client", f"unsupported client_assertion alg: {alg}", 401)
    jwk = _client_keys(client, header.get("kid"), alg, allow_loopback=allow_loopback)
    try:
        public_key = jwt.PyJWK(jwk, algorithm=alg).key
        claims = jwt.decode(
            assertion, public_key, algorithms=[alg], audience=[token_endpoint, issuer],
            options={"require": ["iss", "sub", "aud", "exp"]}, leeway=10,
        )
    except jwt.ExpiredSignatureError:
        raise OAuthError("invalid_client", "client_assertion expired", 401)
    except jwt.InvalidAudienceError:
        raise OAuthError("invalid_client", "client_assertion aud must be the token endpoint", 401)
    except jwt.InvalidTokenError as e:
        raise OAuthError("invalid_client", f"invalid client_assertion: {e}", 401)
    if claims.get("iss") != client.client_id or claims.get("sub") != client.client_id:
        raise OAuthError("invalid_client", "client_assertion iss and sub must be the client_id", 401)
    exp = float(claims["exp"])
    if exp - time.time() > MAX_ASSERTION_LIFETIME + 10:
        raise OAuthError("invalid_client", f"client_assertion lifetime exceeds {MAX_ASSERTION_LIFETIME}s", 401)
    jti = claims.get("jti")
    if not isinstance(jti, str) or not jti:
        raise OAuthError("invalid_client", "client_assertion must carry a jti", 401)
    if not _remember_jti(client.client_id, jti, exp):
        raise OAuthError("invalid_client", "client_assertion replayed", 401)
    return claims
