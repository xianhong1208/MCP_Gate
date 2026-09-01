"""Auth resolution for health checks / tool fetching.

The actual periodic health check lives in src/scheduler/cleanup_scheduler.py (_health_check_task);
the one-off check lives in src/api/routes.py (check_service_health). Only the logic shared by both lives here.
"""

import logging
from typing import Optional

from sqlalchemy.orm import Session

from db.models import Service
from src.utils.crypto import decrypt_token

logger = logging.getLogger(__name__)


def resolve_service_auth_token(db: Session, service: Service) -> Optional[str]:
    """The Bearer token to send for health checks / tool fetching.

    1. Service is protected by MCP Center's own OAuth (requires_auth and no static token) -> self-sign a
       short-lived token with aud=that service on the spot; nothing to store, nothing to expire.
    2. Service has its own static Bearer (auth_token_encrypted) -> decrypt and use it.
    3. No authentication required -> None.
    """
    if service.auth_token_encrypted:
        try:
            return decrypt_token(service.auth_token_encrypted)
        except Exception as e:
            logger.warning(f"Failed to decrypt auth token for {service.name}: {e}")
            return None
    if service.requires_auth:
        try:
            from src.oauth import service as oauth_service
            return oauth_service.mint_scanner_token(db, service)
        except Exception as e:
            logger.warning(f"Failed to mint scanner token for {service.name}: {e}")
    return None
