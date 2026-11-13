"""Data-access adapter layer (middle layer of the three-tier architecture)

    API routes / service layer  ─▶  Adapter (this layer)  ─▶  db.crud (data layer)

Upper layers always `from src.adapters import XAdapter` and never import db.crud directly.
Invariant (guarded by tests/test_architecture_layering.py): only src/adapters/* imports db.crud.
"""

from db.crud import normalize_audience, normalize_service_host  # pure utility functions, re-exported via this layer

from src.adapters.admin_adapter import AdminSessionAdapter, AdminUserAdapter
from src.adapters.encryption_adapter import EncryptedColumnAdapter
from src.adapters.managed_adapter import (
    BYODefinitionAdapter,
    ManagedMcpProcessAdapter,
    MCPToolAdapter,
)
from src.adapters.oauth_adapter import (
    AuditLogAdapter,
    OAuthAuthRequestAdapter,
    OAuthClientAdapter,
    OAuthCodeAdapter,
    OAuthConsentAdapter,
    ServiceScopeAdapter,
    OAuthKeyAdapter,
    OAuthScopeAdapter,
    OAuthTokenAdapter,
    TokenUsageAdapter,
)
from src.adapters.service_adapter import (
    ServiceAdapter, describe_server, fallback_service_description, fallback_service_name, sanitize_server_name,
)

__all__ = [
    "EncryptedColumnAdapter",
    "ServiceAdapter",
    "MCPToolAdapter",
    "AdminUserAdapter",
    "AdminSessionAdapter",
    "BYODefinitionAdapter",
    "ManagedMcpProcessAdapter",
    "TokenUsageAdapter",
    "AuditLogAdapter",
    "OAuthKeyAdapter",
    "OAuthClientAdapter",
    "OAuthAuthRequestAdapter",
    "OAuthCodeAdapter",
    "OAuthScopeAdapter",
    "OAuthTokenAdapter",
    "OAuthConsentAdapter",
    "ServiceScopeAdapter",
    "normalize_service_host",
    "fallback_service_name",
    "fallback_service_description",
    "describe_server",
    "sanitize_server_name",
    "normalize_audience",
]
