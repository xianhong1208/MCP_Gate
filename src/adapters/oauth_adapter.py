"""OAuth domain adapter (signing keys / clients / codes / tokens / consents / scopes) + event stats + audit cleanup."""

from db.crud import (
    AuditLogCRUD,
    OAuthAuthRequestCRUD,
    OAuthClientCRUD,
    OAuthCodeCRUD,
    OAuthConsentCRUD,
    ServiceScopeCRUD,
    OAuthScopeCRUD,
    OAuthSigningKeyCRUD,
    OAuthTokenCRUD,
    TokenUsageCRUD,
)
from src.adapters.exceptions import NotFoundError
from src.utils import public_cache


class OAuthKeyAdapter(OAuthSigningKeyCRUD):
    """Signing keys. Writes drop the cached JWKS (src/utils/public_cache.py)."""

    @classmethod
    def create(cls, db, **kwargs):
        key = super().create(db, **kwargs)
        public_cache.invalidate()
        return key

    @classmethod
    def delete(cls, db, kid):
        deleted = super().delete(db, kid)
        public_cache.invalidate()
        return deleted


class OAuthClientAdapter(OAuthClientCRUD):

    @classmethod
    def get_existing(cls, db, client_id):
        client = cls.get(db, client_id)
        if not client:
            raise NotFoundError(code="oauth.client_not_found", fallback="OAuth client not found")
        return client


class OAuthAuthRequestAdapter(OAuthAuthRequestCRUD):
    """Requests that came in via /authorize and are awaiting consent."""


class OAuthCodeAdapter(OAuthCodeCRUD):
    """Authorization codes."""


class OAuthScopeAdapter(OAuthScopeCRUD):
    """Scope registry. Writes drop the cached discovery metadata (scopes_supported)."""

    @classmethod
    def upsert(cls, db, **kwargs):
        scope = super().upsert(db, **kwargs)
        public_cache.invalidate()
        return scope

    @classmethod
    def delete(cls, db, name):
        deleted = super().delete(db, name)
        public_cache.invalidate()
        return deleted


class OAuthTokenAdapter(OAuthTokenCRUD):
    """Tokens. A live token keeps the retired key that signed it in the JWKS, so revoking or purging tokens drops
    the cached JWKS (src/utils/public_cache.py)."""

    @classmethod
    def get_existing(cls, db, jti):
        token = cls.get(db, jti)
        if not token:
            raise NotFoundError(code="oauth.token_not_found", fallback="Token not found")
        return token

    @classmethod
    def revoke(cls, db, token, reason="revoked"):
        out = super().revoke(db, token, reason)
        public_cache.invalidate()
        return out

    @classmethod
    def revoke_family(cls, db, parent_jti, reason):
        out = super().revoke_family(db, parent_jti, reason)
        public_cache.invalidate()
        return out

    @classmethod
    def revoke_by_client(cls, db, client_id, reason="client_revoked"):
        out = super().revoke_by_client(db, client_id, reason)
        public_cache.invalidate()
        return out

    @classmethod
    def delete_expired(cls, db, **kwargs):
        out = super().delete_expired(db, **kwargs)
        public_cache.invalidate()
        return out


class OAuthConsentAdapter(OAuthConsentCRUD):
    """Consents the user has granted."""


class TokenUsageAdapter(TokenUsageCRUD):
    """Token events / statistics."""


class AuditLogAdapter(AuditLogCRUD):
    """Audit log cleanup."""


class ServiceScopeAdapter(ServiceScopeCRUD):
    """Scopes declared by one MCP server. Writes drop the cached discovery metadata (scopes_supported)."""

    @classmethod
    def upsert(cls, db, service_id, **kwargs):
        scope = super().upsert(db, service_id, **kwargs)
        public_cache.invalidate()
        return scope

    @classmethod
    def delete(cls, db, service_id, name):
        deleted = super().delete(db, service_id, name)
        public_cache.invalidate()
        return deleted
