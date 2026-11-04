"""Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document-03; MCP authorization 2026-07-28,
"Client Registration").

A client with no prior relationship to MCP Gate uses an https URL as its ``client_id``. The JSON document served
at that URL is the client's metadata (RFC 7591 names): MCP Gate fetches it when the client shows up at
``/oauth/authorize`` or ``/oauth/token``, validates it, and keeps the result in an ``oauth_clients`` row keyed by the
URL (``created_via = cimd``), so tokens, consents, the audit log and revocation work exactly as for registered
clients. The row is refreshed from the document whenever the cached copy is stale.

What is checked (section numbers are the draft's):

- the URL (§3): https, a host, no userinfo, a path other than ``/`` without dot segments, no fragment, at most 255
  characters; never a URL of MCP Gate itself (§10.1); optionally only on ``oauth.cimd.allowed_hosts`` (§10.8);
- the fetch (§6, §10.7): the host must resolve to public addresses only and the connection is pinned to the
  address that was checked (no DNS rebinding); no redirects; ``Accept: application/json``; no cookies, no proxy;
  a deadline for the whole exchange; at most ``max_document_bytes``; HTTP 200 with a JSON media type;
- the document (§4, §4.1, §5, MCP): a JSON object whose ``client_id`` equals the URL by simple string comparison;
  ``client_name`` and ``redirect_uris`` present; no ``client_secret``; no shared-secret authentication method; the
  authentication method is chosen from ``token_endpoint_auth_methods_supported`` (falling back to the singular
  ``token_endpoint_auth_method``, then ``none``): ``private_key_jwt`` when declared (with exactly one of ``jwks`` /
  ``jwks_uri``), else ``none`` with PKCE; ``grant_types`` / ``response_types`` are cut down to what MCP Gate
  supports and must keep ``authorization_code`` / ``code``.

Caching (§6.2): a valid document is reused for its HTTP ``max-age`` bounded by ``cache_min_seconds`` and
``cache_max_seconds``. Errors are never stored as metadata; after a failed fetch the URL is not fetched again for
``failure_backoff_seconds`` (a rate limit) and the same error is returned. Failures (§6.1): a transient one
(network, timeout, 429, 5xx) at the token endpoint falls back to the last valid document; any failure aborts an
authorization request; a document whose ``client_id`` no longer matches its URL revokes the client's tokens.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import threading
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import unquote, urlsplit

import httpx
from loguru import logger
from sqlalchemy.orm import Session

from db.models import CLIENT_ID_LENGTH, OAuthAuthorizationRequest, OAuthClient
from src.adapters import OAuthClientAdapter, OAuthTokenAdapter
from src.audit import AuditAction, AuditStatus, record_oauth_event
from src.config import Config
from src.oauth import client_assertion
from src.oauth.errors import OAuthError
from src.utils.field_limits import clip, column_limit
from src.version import __version__

CREATED_VIA = "cimd"
DEFAULT_CACHE_SECONDS = 300          # a document served without Cache-Control max-age
MAX_TRACKED_URLS = 10_000            # bound on the in-memory freshness / failure tables
SHARED_SECRET_METHODS = {"client_secret_basic", "client_secret_post", "client_secret_jwt"}
SUPPORTED_AUTH_METHODS = ("private_key_jwt", "none")      # preference order (§5: private_key_jwt must be used
                                                          # whenever it is declared and supported)
SUPPORTED_GRANTS = ("authorization_code", "refresh_token")  # client_credentials stays console-only
DEFAULT_GRANTS = ["authorization_code", "refresh_token"]    # as for dynamic registration
TRANSIENT_STATUSES = {408, 425, 429, 500, 502, 503, 504}
LOOPBACK_NAMES = {"localhost", "127.0.0.1", "::1"}


class MetadataError(OAuthError):
    """A metadata document (or its URL) cannot be used: ``invalid_client``.

    ``transient``: the fetch failed in a way that says nothing about the client (network, timeout, 429, 5xx).
    ``mismatch``: the document's ``client_id`` is not its URL (§6.1: invalidate what the client holds)."""

    def __init__(self, description: str, *, transient: bool = False, mismatch: bool = False):
        super().__init__("invalid_client", f"client metadata document: {description}", 400)
        self.reason = description
        self.transient = transient
        self.mismatch = mismatch

    def copy(self) -> "MetadataError":
        """A fresh instance to raise again (a remembered failure is raised by concurrent requests)."""
        return MetadataError(self.reason, transient=self.transient, mismatch=self.mismatch)


def _cfg():
    return Config.get_oauth_config().cimd


def _issuer() -> str:
    return Config.get_oauth_config().issuer.rstrip("/")


def is_metadata_url(client_id: Optional[str]) -> bool:
    """A client_id that names a metadata document. MCP Gate never generates one starting with https:// (§9.1)."""
    return isinstance(client_id, str) and client_id.startswith("https://")


def enabled() -> bool:
    return _cfg().enabled


# ---------------------------------------------------------------------------
# the URL
# ---------------------------------------------------------------------------
def _host_matches(host: str, patterns) -> bool:
    """Exact names, or ``*.example.com`` for any subdomain of example.com (not example.com itself)."""
    for pattern in patterns:
        if pattern.startswith("*.") and host.endswith(pattern[1:]) and host != pattern[2:]:
            return True
        if host == pattern:
            return True
    return False


def validate_client_id_url(url: str) -> str:
    """§3 and the server-side policy; returns the host. Raises MetadataError."""
    if len(url) > CLIENT_ID_LENGTH:
        raise MetadataError(f"client_id URL is too long (maximum {CLIENT_ID_LENGTH} characters)")
    if any(ord(c) <= 0x20 or ord(c) >= 0x7F for c in url):
        raise MetadataError("client_id URL must be plain ASCII without spaces or control characters")
    if "#" in url:
        raise MetadataError("client_id URL must not contain a fragment")
    try:
        parts = urlsplit(url)
        parts.port  # noqa: B018 -- raises on a malformed port
    except ValueError:
        raise MetadataError("client_id is not a valid URL")
    if parts.scheme != "https":
        raise MetadataError("client_id URL must use https")
    if "@" in parts.netloc:
        raise MetadataError("client_id URL must not contain credentials")
    host = (parts.hostname or "").lower()
    if not host:
        raise MetadataError("client_id URL must have a host")
    if not parts.path or parts.path == "/":
        raise MetadataError("client_id URL must have a path")
    if any(unquote(segment) in (".", "..") for segment in parts.path.split("/")):
        raise MetadataError("client_id URL must not contain dot path segments")
    issuer = urlsplit(_issuer())
    if parts.netloc.lower() == issuer.netloc.lower():
        raise MetadataError("client_id URL must not point at this authorization server")
    allowed = _cfg().allowed_hosts
    if allowed and not _host_matches(host.rstrip("."), allowed):
        raise MetadataError(f"clients from {host} are not accepted here")
    return host


# ---------------------------------------------------------------------------
# fetching (SSRF-hardened)
# ---------------------------------------------------------------------------
def _resolve_host(host: str) -> list[str]:
    """Every address ``host`` resolves to (a literal IP resolves to itself). Separate so tests can stub it."""
    try:
        return sorted({info[4][0] for info in socket.getaddrinfo(host, None)})
    except (socket.gaierror, UnicodeError):
        return []


def _issuer_on_loopback() -> bool:
    host = (urlsplit(_issuer()).hostname or "").lower()
    if host in LOOPBACK_NAMES or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _pinned_address(url: str) -> str:
    """Resolve the URL's host and return the address to connect to. Every address must be public (RFC 6890
    special-use ranges, loopback, private, link-local -- cloud metadata at 169.254.169.254 -- carrier-grade NAT,
    multicast and reserved ones are refused, §10.7). Hosts on ``private_network_hosts`` may resolve to private
    addresses; to loopback only while MCP Gate itself runs on loopback (a development setup)."""
    host = (urlsplit(url).hostname or "").rstrip(".").lower()
    private_ok = _host_matches(host, _cfg().private_network_hosts)
    addresses = _resolve_host(host)
    if not addresses:
        raise MetadataError(f"host {host} does not resolve", transient=True)
    for addr in addresses:
        ip = ipaddress.ip_address(addr.split("%")[0])
        if ip.version == 6 and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        if client_assertion._is_public(ip):
            continue
        if not private_ok or ip.is_unspecified or ip.is_multicast:
            raise MetadataError(f"host {host} resolves to a non-public address")
        if ip.is_loopback and not _issuer_on_loopback():
            raise MetadataError(f"host {host} resolves to this machine")
    return addresses[0].split("%")[0]


class _TooLarge(Exception):
    pass


@dataclass
class _Response:
    status_code: int
    headers: httpx.Headers
    body: bytes


def _make_client(timeout: float) -> httpx.Client:
    """No redirects, no proxy from the environment (a proxy would resolve the name itself), no cookie jar."""
    return httpx.Client(verify=True, trust_env=False, follow_redirects=False, timeout=timeout)


def _http_get(url: str, address: str, *, timeout: float, max_bytes: int) -> _Response:
    """GET ``url`` over a connection to ``address`` (already validated) instead of whatever the name resolves to
    now. The Host header is the original authority; TLS sends the original host name as SNI and verifies the
    certificate against it. The body is streamed and abandoned past ``max_bytes`` (decoded, so a compressed bomb
    is cut too), and the whole exchange must finish within ``timeout``."""
    parts = urlsplit(url)
    ip_host = f"[{address}]" if ":" in address else address
    netloc = f"{ip_host}:{parts.port}" if parts.port else ip_host
    pinned_url = parts._replace(netloc=netloc).geturl()
    headers = {"Host": parts.netloc, "Accept": "application/json", "User-Agent": f"MCP-Gate/{__version__}"}
    deadline = time.monotonic() + timeout
    with _make_client(timeout) as http:
        with http.stream("GET", pinned_url, headers=headers, extensions={"sni_hostname": parts.hostname}) as r:
            if r.status_code != 200:
                return _Response(r.status_code, r.headers, b"")
            declared = r.headers.get("content-length", "")
            if declared.isdigit() and int(declared) > max_bytes:
                raise _TooLarge()
            body = bytearray()
            for chunk in r.iter_bytes():
                body.extend(chunk)
                if len(body) > max_bytes:
                    raise _TooLarge()
                if time.monotonic() > deadline:
                    raise httpx.ReadTimeout("metadata document took too long")
            return _Response(r.status_code, r.headers, bytes(body))


def _is_json_media_type(content_type: str) -> bool:
    media = content_type.split(";")[0].strip().lower()
    return media == "application/json" or (media.startswith("application/") and media.endswith("+json"))


def cache_seconds(headers) -> int:
    """How long a fetched document stays fresh: Cache-Control max-age (minus Age), no-store / no-cache = as short
    as allowed, nothing = DEFAULT_CACHE_SECONDS; always within [cache_min_seconds, cache_max_seconds]. Expires is
    not consulted (§6.2 allows ignoring it)."""
    cfg = _cfg()
    directives = {}
    for item in (headers.get("cache-control") or "").lower().split(","):
        name, _, value = item.strip().partition("=")
        if name:
            directives[name] = value.strip().strip('"')
    if "no-store" in directives or "no-cache" in directives:
        ttl = 0
    elif directives.get("max-age", "").isdigit():
        age = (headers.get("age") or "").strip()
        ttl = int(directives["max-age"]) - (int(age) if age.isdigit() else 0)
    else:
        ttl = DEFAULT_CACHE_SECONDS
    upper = max(cfg.cache_max_seconds, cfg.cache_min_seconds)
    return min(max(ttl, cfg.cache_min_seconds), upper)


def fetch_document(url: str) -> tuple[dict, int]:
    """Fetch and parse the document at ``url``: (JSON object, seconds it stays fresh). Raises MetadataError."""
    cfg = _cfg()
    address = _pinned_address(url)
    try:
        response = _http_get(url, address, timeout=cfg.fetch_timeout_seconds, max_bytes=cfg.max_document_bytes)
    except _TooLarge:
        raise MetadataError(f"document is larger than {cfg.max_document_bytes} bytes")
    except (httpx.HTTPError, OSError) as e:
        logger.warning("client metadata document {url} could not be fetched: {err}", url=url, err=e)
        raise MetadataError("document could not be fetched", transient=True)
    status = response.status_code
    if status != 200:
        if 300 <= status < 400:
            raise MetadataError(f"HTTP {status}: redirects are not followed, serve the document at its client_id")
        raise MetadataError(f"HTTP {status}", transient=status in TRANSIENT_STATUSES)
    if not _is_json_media_type(response.headers.get("content-type", "")):
        raise MetadataError("document must be served as application/json")
    try:
        doc = json.loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise MetadataError("document is not valid JSON")
    return doc, cache_seconds(response.headers)


# ---------------------------------------------------------------------------
# the document
# ---------------------------------------------------------------------------
def _string_list(doc: dict, name: str) -> Optional[list]:
    value = doc.get(name)
    if value is None:
        return None
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise MetadataError(f"{name} must be an array of strings")
    return value


def _auth_method(doc: dict) -> str:
    """§5: the plural ``token_endpoint_auth_methods_supported`` first, the singular one as a fallback (and, when
    both are present, a member of the plural), ``none`` when neither is given. No shared-secret method may
    appear (§4.1). The first of SUPPORTED_AUTH_METHODS the client declared wins."""
    plural = _string_list(doc, "token_endpoint_auth_methods_supported")
    singular = doc.get("token_endpoint_auth_method")
    if singular is not None and not isinstance(singular, str):
        raise MetadataError("token_endpoint_auth_method must be a string")
    if plural is not None and not plural:
        raise MetadataError("token_endpoint_auth_methods_supported must not be empty")
    if plural is not None and singular is not None and singular not in plural:
        raise MetadataError("token_endpoint_auth_method must be one of token_endpoint_auth_methods_supported")
    declared = plural if plural is not None else [singular or "none"]
    secret_based = sorted(set(declared) & SHARED_SECRET_METHODS)
    if secret_based:
        raise MetadataError(f"shared-secret authentication is not allowed: {' '.join(secret_based)}")
    for method in SUPPORTED_AUTH_METHODS:
        if method in declared:
            return method
    raise MetadataError(f"no supported token endpoint authentication method (supported: "
                        f"{' '.join(SUPPORTED_AUTH_METHODS)})")


def _keys(doc: dict, method: str) -> tuple[Optional[str], Optional[str]]:
    """(jwks as JSON text, jwks_uri) for private_key_jwt, validated; (None, None) for any other method."""
    jwks, jwks_uri = doc.get("jwks"), doc.get("jwks_uri")
    if jwks is not None and jwks_uri is not None:
        raise MetadataError("jwks and jwks_uri must not both be present")
    if method != "private_key_jwt":
        return None, None
    if jwks is None and jwks_uri is None:
        raise MetadataError("private_key_jwt requires jwks or jwks_uri")
    try:
        if jwks is not None:
            client_assertion.validate_jwks_document(jwks)
            return json.dumps(jwks), None
        if not isinstance(jwks_uri, str) or len(jwks_uri) > column_limit(OAuthClient.jwks_uri):
            raise MetadataError("jwks_uri must be a URL of at most "
                                f"{column_limit(OAuthClient.jwks_uri)} characters")
        # an anonymous document must never aim our fetcher at this machine
        return None, client_assertion.validate_jwks_uri(jwks_uri, allow_loopback=False)
    except MetadataError:
        raise
    except OAuthError as e:
        raise MetadataError(e.description)


def _display_uri(doc: dict, name: str, column) -> Optional[str]:
    """client_uri / logo_uri: informative only (§4.4), so an unusable value is dropped, not fatal. https only."""
    value = doc.get(name)
    if not isinstance(value, str) or not value or len(value) > column_limit(column):
        return None
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    return value if parts.scheme == "https" and parts.hostname and "@" not in parts.netloc else None


def validate_document(url: str, doc) -> dict:
    """Check a fetched document against §4 / §5 and MCP's required fields; return the oauth_clients column
    values it maps to. Raises MetadataError."""
    from src.oauth.service import MAX_REDIRECT_URIS, _valid_redirect_uri

    if not isinstance(doc, dict):
        raise MetadataError("document must be a JSON object")
    if doc.get("client_id") != url:
        raise MetadataError("client_id in the document does not match the URL it was fetched from", mismatch=True)
    for forbidden in ("client_secret", "client_secret_expires_at"):
        if forbidden in doc:
            raise MetadataError(f"{forbidden} must not be present")

    name = doc.get("client_name")
    if not isinstance(name, str) or not name.strip():
        raise MetadataError("client_name is required")

    redirect_uris = _string_list(doc, "redirect_uris")
    if not redirect_uris:
        raise MetadataError("redirect_uris is required")
    if len(redirect_uris) > MAX_REDIRECT_URIS:
        raise MetadataError(f"at most {MAX_REDIRECT_URIS} redirect_uris")
    limit = column_limit(OAuthAuthorizationRequest.redirect_uri)  # every authorization request stores one
    for uri in redirect_uris:
        if len(uri) > limit or not _valid_redirect_uri(uri):
            raise MetadataError(f"invalid redirect_uri: {clip(uri, 80)}")

    declared_grants = _string_list(doc, "grant_types")
    grants = [g for g in SUPPORTED_GRANTS if g in (DEFAULT_GRANTS if declared_grants is None else declared_grants)]
    if "authorization_code" not in grants:
        raise MetadataError("grant_types must include authorization_code")
    response_types = _string_list(doc, "response_types")
    if response_types is not None and "code" not in response_types:
        raise MetadataError("response_types must include code")

    method = _auth_method(doc)
    jwks, jwks_uri = _keys(doc, method)

    software_id = doc.get("software_id")
    if not isinstance(software_id, str) or len(software_id) > column_limit(OAuthClient.software_id):
        software_id = None
    return {
        "client_name": clip(name.strip(), column_limit(OAuthClient.client_name)),
        "client_uri": _display_uri(doc, "client_uri", OAuthClient.client_uri),
        "logo_uri": _display_uri(doc, "logo_uri", OAuthClient.logo_uri),
        "software_id": software_id or None,
        "redirect_uris": json.dumps(redirect_uris),
        "grant_types": json.dumps(grants),
        "response_types": json.dumps(["code"]),
        # A portable document may name scopes of other servers: it does not restrict what is requested here
        "scope": None,
        "token_endpoint_auth_method": method,
        "jwks": jwks,
        "jwks_uri": jwks_uri,
        "client_secret_hash": None,
        "require_pkce": True,
        "default_resource": None,
        "resource_audience": None,
    }


# ---------------------------------------------------------------------------
# freshness / failure tables (per process)
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_fresh_until: dict[str, float] = {}                         # url -> monotonic time the stored metadata expires
_failures: dict[str, tuple[float, MetadataError]] = {}      # url -> (retry not before, the error)


def _prune(table: dict, now: float) -> None:
    if len(table) < MAX_TRACKED_URLS:
        return
    for key in [k for k, v in table.items() if (v[0] if isinstance(v, tuple) else v) <= now]:
        table.pop(key, None)
    if len(table) >= MAX_TRACKED_URLS:  # still full of live entries: forget them all (only costs refetches)
        table.clear()


def _mark_fresh(url: str, ttl: int) -> None:
    now = time.monotonic()
    with _lock:
        _prune(_fresh_until, now)
        _fresh_until[url] = now + ttl
        _failures.pop(url, None)


def _mark_failed(url: str, err: MetadataError) -> None:
    backoff = _cfg().failure_backoff_seconds
    now = time.monotonic()
    with _lock:
        _fresh_until.pop(url, None)
        if backoff > 0:
            _prune(_failures, now)
            _failures[url] = (now + backoff, err)


def forget(url: str) -> None:
    """Drop what this process knows about ``url`` (the next request fetches the document again)."""
    with _lock:
        _fresh_until.pop(url, None)
        _failures.pop(url, None)


def reset_caches() -> None:
    with _lock:
        _fresh_until.clear()
        _failures.clear()


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------
def _on_mismatch(db: Session, url: str, client: OAuthClient) -> None:
    """§6.1: a document that no longer names itself is a terminal failure; what the client holds is revoked."""
    revoked = OAuthTokenAdapter.revoke_by_client(db, url, reason="metadata_mismatch")
    logger.warning("client metadata document {url} no longer matches its URL: {n} token(s) revoked", url=url,
                   n=revoked)
    record_oauth_event(db, AuditAction.OAUTH_CLIENT_REVOKE, status=AuditStatus.FAILURE, client_id=url,
                       client_name=client.client_name,
                       error_message="client_id in the metadata document does not match its URL",
                       details={"created_via": CREATED_VIA, "tokens_revoked": revoked})


def resolve_client(db: Session, url: str, *, stale_ok: bool = False) -> OAuthClient:
    """The client identified by the metadata document at ``url``: fetched, validated and stored when the cached
    copy is stale, otherwise the stored row. ``stale_ok`` (token endpoint) keeps using the stored row when a
    refetch fails transiently. A client the owner revoked is returned without fetching (callers refuse it).
    Raises MetadataError."""
    validate_client_id_url(url)
    existing = OAuthClientAdapter.get(db, url)
    if existing is not None and (not existing.is_active or existing.created_via != CREATED_VIA):
        return existing
    now = time.monotonic()
    with _lock:
        fresh_until = _fresh_until.get(url)
        failure = _failures.get(url)
    if existing is not None and fresh_until is not None and now < fresh_until:
        return existing
    if failure is not None and now < failure[0]:
        err = failure[1]
        if stale_ok and existing is not None and err.transient:
            return existing
        raise err.copy()

    try:
        doc, ttl = fetch_document(url)
        fields = validate_document(url, doc)
    except MetadataError as err:
        _mark_failed(url, err)
        if err.mismatch and existing is not None:
            _on_mismatch(db, url, existing)
        if stale_ok and existing is not None and err.transient:
            logger.warning("client metadata document {url} unavailable, using the stored copy: {err}", url=url,
                           err=err.description)
            return existing
        raise

    client, changed, forgotten = OAuthClientAdapter.store_metadata_client(
        db, url, fields, is_approved=_cfg().auto_approve)
    _mark_fresh(url, ttl)
    if existing is None:
        logger.info(f"CIMD: new client {url} ({client.client_name}) approved={client.is_approved}")
        record_oauth_event(db, AuditAction.OAUTH_CLIENT_CREATE, client_id=url, client_name=client.client_name,
                           details={"created_via": CREATED_VIA, "approved": client.is_approved,
                                    "redirect_uris": client.redirect_uri_list(),
                                    "token_endpoint_auth_method": client.token_endpoint_auth_method})
    elif changed:
        logger.info(f"CIMD: metadata of {url} changed ({', '.join(changed)}); {forgotten} remembered consent(s) "
                    f"forgotten")
    return client
