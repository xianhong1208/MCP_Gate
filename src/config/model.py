"""Configuration model definitions."""

from typing import Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class DatabaseConfig(BaseModel):
    """Database configuration.

    Defaults to a single SQLite file (zero dependencies); set DATABASE_URL to postgresql://... to switch to PostgreSQL.
    """
    url: str = "sqlite:///data/mcp_gate.db"
    echo: bool = False
    pool_size: int = 5
    max_overflow: int = 10


class ServerConfig(BaseModel):
    host: str = "0.0.0.0"
    # 0 = derive from oauth.issuer (see ConfigModel.effective_port)
    port: int = 0


class SessionConfig(BaseModel):
    """Admin console login session (an HS256 JWT inside an httpOnly cookie).

    When secret_key is empty, the secrets store generates one and persists it (secrets/secrets.json).
    """
    secret_key: str = ""
    expire_hours: int = 12
    idle_timeout_minutes: int = 30


def _split_list(value):
    """Accept a YAML list or one comma-separated string (``"${VAR:-}"`` in config.yaml)."""
    if isinstance(value, str):
        return [v.strip() for v in value.split(",") if v.strip()]
    return value


class ClientMetadataConfig(BaseModel):
    """Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document, MCP authorization 2026-07-28):
    a client uses an https URL as its client_id and MCP Gate fetches the client's metadata from that URL instead of
    the client registering. Works alongside dynamic client registration."""
    enabled: bool = True
    # Whether a client first seen through its metadata document is usable without review (as dcr_auto_approve;
    # the consent page is still shown for every authorization)
    auto_approve: bool = True
    # Trust policy: when non-empty, only client_id URLs on these hosts are accepted ("example.com" exact,
    # "*.example.com" any subdomain). Empty = any public https host.
    allowed_hosts: List[str] = []
    # SSRF override for development / intranet clients: hosts whose metadata may be fetched although they resolve
    # to a private address. Loopback is honoured only while the issuer itself is on loopback. Never for production.
    private_network_hosts: List[str] = []
    fetch_timeout_seconds: float = Field(5.0, gt=0, le=30)
    # The draft recommends 5 KB; an inline jwks with a few keys still fits
    max_document_bytes: int = Field(5120, ge=512, le=65536)
    # Bounds on how long a fetched document is cached (HTTP Cache-Control max-age is honoured within them)
    cache_min_seconds: int = Field(60, ge=0)
    cache_max_seconds: int = Field(86400, ge=1)
    # After a failed fetch the URL is not fetched again for this long (rate limit; the error itself is not cached
    # as metadata). 0 disables.
    failure_backoff_seconds: int = Field(30, ge=0)

    @field_validator("allowed_hosts", "private_network_hosts", mode="before")
    @classmethod
    def _split_hosts(cls, value):
        return [h.lower() for h in (_split_list(value) or [])]


class OAuthConfig(BaseModel):
    """OAuth 2.1 Authorization Server settings.

    issuer is written into the iss claim of every issued JWT and into the discovery metadata; it is the trust
    anchor every MCP server uses to verify tokens. For public deployments it must be the public URL (changing it
    invalidates all existing tokens).
    """
    issuer: str = "http://localhost:4568"
    signing_key_bits: int = 2048
    # OAuth access tokens (authorization_code / refresh_token / client_credentials grants). Short, because a
    # server that verifies offline without the revocation feed accepts a revoked one until it expires; clients
    # renew with their refresh token. Personal access tokens are not affected (their lifetime is chosen per token).
    access_expire_minutes: int = 15
    refresh_expire_days: int = 30
    auth_code_ttl_seconds: int = 120
    # Personal-project default: dynamically registered (DCR) clients are usable immediately; the human consent
    # page is the real gate.
    dcr_auto_approve: bool = True
    # Maximum lifetime (days) allowed for Personal Access Tokens issued directly from the admin console
    pat_max_days: int = 365
    # Dynamically registered clients, and active clients first seen through their metadata document, that never
    # obtained a token are deleted this many days after they were created (anyone can create one, so they would
    # otherwise pile up). 0 disables the purge.
    dcr_unused_client_days: int = 30
    # How long (minutes) a rotated-out signing key stays in the published JWKS after rotation. Unset = the access
    # token lifetime plus 5 minutes of clock skew. A retired key also stays published while any live access token
    # or PAT it signed is still recorded (PATs can outlive this by months).
    retired_key_publish_minutes: Optional[int] = None
    # #30: a new signing key is made every this many days (0 = only by hand, "Rotate now" in the console) ...
    signing_key_rotation_days: int = Field(90, ge=0)
    # ... and published in the JWKS this long before it signs anything, so resource servers cache it first
    signing_key_prepublish_minutes: int = Field(1440, ge=0)
    # Client ID Metadata Documents (an https URL as client_id, no registration)
    cimd: ClientMetadataConfig = ClientMetadataConfig()


class OAuthLoginProviderConfig(BaseModel):
    """Admin console third-party login (GitHub / Google) provider settings. An empty client_id disables it."""
    client_id: str = ""
    client_secret: str = ""


class IdentityConfig(BaseModel):
    """Admin console authentication: local email/password plus pluggable third-party login."""
    local_enabled: bool = True
    github: OAuthLoginProviderConfig = OAuthLoginProviderConfig()
    google: OAuthLoginProviderConfig = OAuthLoginProviderConfig()
    # Email allowlist for third-party login (empty = only already-existing accounts may log in)
    allowed_emails: List[str] = []
    # Owner account created automatically on first start (only when both are set; otherwise use the /setup page)
    bootstrap_admin_email: str = ""
    bootstrap_admin_password: str = ""


class RateLimitConfig(BaseModel):
    enabled: bool = True
    requests_per_minute: int = 120
    requests_per_hour: int = 2000
    whitelist: List[str] = ["127.0.0.1", "localhost", "::1"]
    path_limits: Dict[str, int] = {}


class SecurityConfig(BaseModel):
    trusted_proxies: List[str] = ["127.0.0.1", "::1"]
    # Host names MCP Gate answers to besides the OAUTH_ISSUER host, localhost / *.localhost and IP literals
    # (DNS-rebinding protection, see src/middleware/trusted_host.py). Exact names, "*.suffix", or "*" for any.
    allowed_hosts: List[str] = []
    # Secure flag on cookies; set to true when deploying over HTTPS
    secure_cookie: bool = False
    cookie_samesite: str = "lax"

    @field_validator("allowed_hosts", mode="before")
    @classmethod
    def _split_hosts(cls, value):
        return _split_list(value)


class CORSConfig(BaseModel):
    """Credentialed CORS for the console API. The console itself is same-origin and needs none of it, so the
    default is empty: every origin listed here can read and drive the admin API from the owner's browser.
    ``allowed_origins`` also accepts one comma-separated string (``${CORS_ALLOWED_ORIGINS:-}`` in config.yaml)."""
    allowed_origins: List[str] = []
    allow_methods: List[str] = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    allow_headers: List[str] = ["Content-Type", "Authorization", "X-Requested-With", "X-Session-Binding"]
    allow_credentials: bool = True

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def _split_origins(cls, value):
        return _split_list(value)


class LoggingConfig(BaseModel):
    level: str = "INFO"
    format: str = "colorized"
    log_dir: str = "logs"
    rotation: str = "00:00"
    rotation_max_size: str = "50 MB"
    retention: str = "30 days"
    compression: str = "zip"


class SchedulerConfig(BaseModel):
    """In-process background jobs: expiry purges, retention, health checks (src/scheduler/cleanup_scheduler.py)."""
    # Expired OAuth codes / requests / tokens and console sessions are purged this often
    oauth_cleanup_hours: int = Field(6, ge=1)
    # Token events (dashboard statistics) and audit log entries older than this are deleted daily
    usage_retention_days: int = Field(30, ge=1)
    audit_retention_days: int = Field(90, ge=1)
    health_check_enabled: bool = True
    health_check_seconds: int = Field(30, ge=5)
    # Services checked at the same time, and how long one check may take before it counts as failed
    health_check_concurrency: int = Field(8, ge=1, le=64)
    health_check_timeout_seconds: float = Field(10.0, gt=0, le=300)
    # A health row is rewritten when the status changes; otherwise at most this often
    health_write_interval_minutes: int = Field(5, ge=1)


DEFAULT_PORT = 4568


class ConfigModel(BaseModel):
    database: DatabaseConfig = DatabaseConfig()
    server: ServerConfig = ServerConfig()
    session: SessionConfig = SessionConfig()
    oauth: OAuthConfig = OAuthConfig()
    identity: IdentityConfig = IdentityConfig()
    rate_limit: RateLimitConfig = RateLimitConfig()
    security: SecurityConfig = SecurityConfig()
    cors: CORSConfig = CORSConfig()
    logging: LoggingConfig = LoggingConfig()
    scheduler: SchedulerConfig = SchedulerConfig()

    @property
    def effective_port(self) -> int:
        """The port actually bound: explicit setting > port in OAUTH_ISSUER > 4568.

        When the issuer is an https domain (reverse proxy) the URL has no port; return 4568 so nginx can forward to it.
        """
        if self.server.port and self.server.port > 0:
            return self.server.port
        from urllib.parse import urlparse
        try:
            explicit = urlparse(self.oauth.issuer).port
        except ValueError:
            explicit = None
        return explicit or DEFAULT_PORT
