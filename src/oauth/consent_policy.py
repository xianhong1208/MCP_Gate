"""Consent-page policy: when the user does not need to be asked again.

The OAuth consent page is the gate where a human decides "what may this client do on my behalf". Asking every time
is safest, but Claude / Cursor popping a consent page on every reconnect is annoying; never asking means any
DCR-registered client could silently obtain a token. The trade-off is defined in one place here.
"""

from __future__ import annotations

from typing import Iterable, Optional

from sqlalchemy.orm import Session

from db.models import AdminUser, OAuthClient
from src.adapters import OAuthConsentAdapter


def should_skip_consent(
    db: Session,
    user: AdminUser,
    client: OAuthClient,
    audience: Optional[str],
    requested_scopes: Iterable[str],
) -> bool:
    """Returns True when the authorization code can be issued directly without showing the consent page.

    Default rules:
      1. Clients created manually in the admin console (created_via=manual) are considered trusted by the user
         themselves -> skip.
      2. Other clients: the user previously chose "remember" for the same client + same audience, and the scope
         requested now does not exceed what was granted then -> skip; otherwise show the consent page.
    """
    requested = set(requested_scopes)
    if client.created_via == "manual":
        return True
    consent = OAuthConsentAdapter.get(db, user.id, client.client_id, audience)
    if consent is None:
        return False
    granted = set((consent.scope or "").split())
    return requested <= granted
