"""OAuth domain adapter (signing keys / clients / codes / tokens / consents / scopes) + event stats + audit cleanup."""

from db.crud import (
    AuditLogCRUD,
    OAuthAuthRequestCRUD,
    OAuthClientCRUD,
    OAuthCodeCRUD,
    OAuthConsentCRUD,
    OAuthScopeCRUD,
    OAuthSigningKeyCRUD,
    OAuthTokenCRUD,
    TokenUsageCRUD,
)
from src.adapters.exceptions import NotFoundError


class OAuthKeyAdapter(OAuthSigningKeyCRUD):
    """Signing keys."""


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
    """Scope registry."""


class OAuthTokenAdapter(OAuthTokenCRUD):

    @classmethod
    def get_existing(cls, db, jti):
        token = cls.get(db, jti)
        if not token:
            raise NotFoundError(code="oauth.token_not_found", fallback="Token not found")
        return token


class OAuthConsentAdapter(OAuthConsentCRUD):
    """Consents the user has granted."""


class TokenUsageAdapter(TokenUsageCRUD):
    """Token events / statistics."""


class AuditLogAdapter(AuditLogCRUD):
    """Audit log cleanup."""
