"""The one-time token that guards first-run setup.

Until an owner exists, /api/session/setup creates one. Without a credential that
is whoever reaches the server first, and it listens on every interface by default.
So while no owner exists a random token is generated, printed in the startup log
and kept in secrets/secrets.json as SETUP_TOKEN (mode 0600, readable only by the
account running MCP Gate); setup requires it and discards it once the owner exists.
Jenkins guards its setup wizard the same way.

MCP_GATE_SETUP_TOKEN sets the token instead, for deployments that cannot read the
log. ADMIN_EMAIL / ADMIN_PASSWORD create the owner at startup and skip all of this.
"""

from __future__ import annotations

import hmac
from pathlib import Path

from src.utils import secrets_store

NAME = "SETUP_TOKEN"
ENV_VAR = "MCP_GATE_SETUP_TOKEN"


def current() -> str:
    """The setup token, generated and stored on first use."""
    return secrets_store.get_secret(NAME, env_var=ENV_VAR, length=24)


def matches(candidate: str | None) -> bool:
    """Whether `candidate` is the setup token (constant-time; surrounding spaces from a paste are ignored)."""
    if not candidate:
        return False
    return hmac.compare_digest(candidate.strip().encode(), current().encode())


def discard() -> None:
    """Forget the token once setup is done, so a copy left in a log or terminal is useless."""
    secrets_store.discard_secret(NAME)


def location() -> Path:
    """The file the token is kept in."""
    return secrets_store.store_location()
