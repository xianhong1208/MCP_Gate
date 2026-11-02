"""Validation of the operator-supplied parts of an MCP server URL: protocol, host and path.

The scanner pins every outbound request to an IP address it has already checked (see
`src.discovery.scanner._resolve_validated_ip`). That only holds if the rest of the URL cannot move the
authority somewhere else. With plain string concatenation it could: a path of ``@169.254.169.254/x``
turns the pinned IP into userinfo, and a protocol of ``http://169.254.169.254/#`` does the same from the
other end. So every component is checked against a strict allow-list here, the URL is assembled only from
checked components, and the result is parsed back to confirm it names the intended host and port.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional
from urllib.parse import urlsplit

ALLOWED_PROTOCOLS = ("http", "https")

# Matches the `services.mcp_path` column.
MAX_MCP_PATH_LENGTH = 128

# RFC 3986 path characters (unreserved, sub-delims, ':' and percent-escapes) minus '@', which is legal
# in a path but is exactly what turns "host + path" into "userinfo@host" when a URL is concatenated.
# '?', '#', '\', whitespace and control characters are excluded by not being listed.
_PATH_CHARS = re.compile(r"[A-Za-z0-9\-._~!$&'()*+,;=:/%]*")
_BAD_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
# DNS names (underscores tolerated for intranet names); no userinfo, port, path or whitespace.
_HOSTNAME = re.compile(r"[A-Za-z0-9_](?:[A-Za-z0-9_.-]{0,251}[A-Za-z0-9_.])?")


class InvalidTargetError(ValueError):
    """A component of an MCP server URL is not acceptable.

    Carries the console error code and an English fallback, like the adapter errors, so routes can
    return the usual `{error, fallback}` envelope.
    """

    def __init__(self, code: str, fallback: str):
        super().__init__(fallback)
        self.code = code
        self.fallback = fallback


def validate_protocol(protocol: Optional[str]) -> str:
    """Return the protocol in lower case; only ``http`` and ``https`` are accepted."""
    value = protocol.lower() if isinstance(protocol, str) else ""
    if value not in ALLOWED_PROTOCOLS:
        raise InvalidTargetError("service.invalid_protocol", "Protocol must be http or https.")
    return value


def validate_mcp_path(path: Optional[str]) -> str:
    """Return the path unchanged if it is a plain absolute path, otherwise raise InvalidTargetError.

    Accepted: a single leading '/', followed by RFC 3986 path characters and well-formed percent-escapes.
    Rejected: an empty or relative path, a leading '//' (a network-path reference names a new host),
    '@', '?', '#', '\\', whitespace, control characters, a scheme and anything over 128 characters.
    """
    if (not isinstance(path, str) or not path.startswith("/") or path.startswith("//")
            or len(path) > MAX_MCP_PATH_LENGTH or not _PATH_CHARS.fullmatch(path)
            or _BAD_PERCENT_ESCAPE.search(path)):
        raise InvalidTargetError(
            "service.invalid_mcp_path",
            "MCP path must start with a single '/' and may not contain '@', '?', '#', '\\' or whitespace.",
        )
    return path


def validate_host(host: Optional[str]) -> str:
    """Return the host unchanged if it is a bare DNS name or IP literal, otherwise raise InvalidTargetError.

    IPv6 literals may be given with or without brackets. Anything carrying userinfo, a port, a path,
    a scope id or whitespace is rejected.
    """
    if isinstance(host, str) and host and "%" not in host:
        literal = host[1:-1] if host.startswith("[") and host.endswith("]") else host
        try:
            ipaddress.ip_address(literal)
            return host
        except ValueError:
            pass
        if _HOSTNAME.fullmatch(host) and ".." not in host:
            return host
    raise InvalidTargetError("service.invalid_host", "Host must be a bare host name or IP address.")


def validate_port(port) -> int:
    """Return the port if it is an integer in 1-65535, otherwise raise InvalidTargetError."""
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise InvalidTargetError("service.invalid_port", "Port must be between 1 and 65535.")
    return port


def _url_host(host: str) -> str:
    literal = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        if ipaddress.ip_address(literal).version == 6:
            return f"[{literal}]"
    except ValueError:
        pass
    return host


def build_mcp_url(protocol: Optional[str], host: Optional[str], port: int, path: Optional[str]) -> str:
    """Build ``protocol://host:port/path`` from validated components.

    A missing or empty stored path means the server root (the request line is ``/`` either way). The port
    is always written out so the URL matches the audience stored for the service (`Service.get_mcp_url`).
    """
    scheme = validate_protocol(protocol)
    clean_host = validate_host(host)
    clean_path = validate_mcp_path(path or "/")
    clean_port = validate_port(port)
    url = f"{scheme}://{_url_host(clean_host)}:{clean_port}{clean_path}"
    # Belt and braces: the assembled URL must parse back to exactly the host and port we were given.
    parts = urlsplit(url)
    expected = _url_host(clean_host).strip("[]").lower()
    if parts.hostname != expected or parts.port != clean_port or parts.username or parts.password:
        raise InvalidTargetError("service.invalid_mcp_path", "MCP server URL does not parse back to its host.")
    return url
