"""Configuration model definitions."""

from typing import Dict, List

from pydantic import BaseModel


class DatabaseConfig(BaseModel):
    """Database configuration.

    Defaults to a single SQLite file (zero dependencies); set DATABASE_URL to postgresql://... to switch to PostgreSQL.
    """
    url: str = "sqlite:///data/mcp_center.db"
    echo: bool = False
    pool_size: int = 5
    max_overflow: int = 10


class ServerConfig(BaseModel):
    host: str = "0.0.0.0"
    # 0 = derive from oauth.issuer (see ConfigModel.effective_port)
    port: int = 0


class SessionConfig(BaseModel):
    """Admin console login session (an HS256 JWT inside an httpOnly cookie).

    When secret_key is empty, the secrets store generates one and persists it (data/secrets.json).
    """
    secret_key: str = ""
    expire_hours: int = 12
    idle_timeout_minutes: int = 30


class OAuthConfig(BaseModel):
    """OAuth 2.1 Authorization Server settings.

    issuer is written into the iss claim of every issued JWT and into the discovery metadata; it is the trust
    anchor every MCP server uses to verify tokens. For public deployments it must be the public URL (changing it
    invalidates all existing tokens).
    """
    issuer: str = "http://localhost:4568"
    signing_key_bits: int = 2048
    access_expire_minutes: int = 60
    refresh_expire_days: int = 30
    auth_code_ttl_seconds: int = 120
    # Personal-project default: dynamically registered (DCR) clients are usable immediately; the human consent
    # page is the real gate.
    dcr_auto_approve: bool = True
    # Maximum lifetime (days) allowed for Personal Access Tokens issued directly from the admin console
    pat_max_days: int = 365


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
    # Secure flag on cookies; set to true when deploying over HTTPS
    secure_cookie: bool = False
    cookie_samesite: str = "lax"


class CORSConfig(BaseModel):
    allowed_origins: List[str] = ["http://localhost:4568", "http://localhost:5173"]
    allow_methods: List[str] = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    allow_headers: List[str] = ["Content-Type", "Authorization", "X-Requested-With"]
    allow_credentials: bool = True


class LoggingConfig(BaseModel):
    level: str = "INFO"
    format: str = "colorized"
    log_dir: str = "logs"
    rotation: str = "00:00"
    rotation_max_size: str = "50 MB"
    retention: str = "30 days"
    compression: str = "zip"


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
