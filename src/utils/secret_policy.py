"""Strength check for the two server secrets, SESSION_SECRET_KEY and ENCRYPTION_KEY.

Values MCP Gate generates itself (``data/secrets.json``) are 43 random URL-safe characters. The risk is a value
set by hand: a placeholder copied from an example, a short word. A guessable SESSION_SECRET_KEY lets anyone forge
a console session; a guessable ENCRYPTION_KEY exposes the signing private keys stored in the database.

* **weak** (warned at every start, and shown as a dashboard banner): shorter than 32 characters, fewer than 10
  distinct characters, or a known placeholder;
* **trivial** (additionally refused, but only on a *new* install): a known placeholder, shorter than 16
  characters, or fewer than 6 distinct characters.

Why not refuse every weak value: on an existing install a refusal locks the owner out until someone edits the
environment, and the obvious "fix" for ENCRYPTION_KEY, changing it, makes every stored private key and secret
unreadable (see SECURITY.md). A new install, detected as "no signing key in the database yet", has nothing
encrypted and no session, so refusing there costs nothing but the edit.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from src.logging import get_logger

logger = get_logger("secret_policy")

MIN_LENGTH = 32
MIN_DISTINCT = 10
TRIVIAL_LENGTH = 16
TRIVIAL_DISTINCT = 6

_PLACEHOLDERS = {
    "changeme", "change_me", "change-me", "changethis", "change_this", "change-this", "secret", "password",
    "passw0rd", "default", "example", "test", "testing", "dev", "development", "admin", "mcp", "mcp-gate",
    "mcp_gate", "mcpgate", "mcp-center", "mcp_center", "your-secret-key", "your_secret_key", "yoursecretkey",
    "your-secret-key-here", "your_secret_key_here", "secret-key", "secret_key", "secretkey", "supersecret",
    "super-secret", "super_secret", "insecure", "replace-me", "replace_me", "replaceme", "xxx", "todo",
}


@dataclass
class Verdict:
    reason: str      # placeholder | too_short | low_variety
    trivial: bool


class WeakSecretError(RuntimeError):
    """A trivial secret on a new install: refuse to start."""


def assess_secret(value: Optional[str]) -> Optional[Verdict]:
    """None when the value is acceptable, otherwise why it is weak (and whether it is trivial)."""
    value = (value or "").strip()
    if value.lower() in _PLACEHOLDERS or "change_me" in value.lower() or "changeme" in value.lower():
        return Verdict("placeholder", True)
    distinct = len(set(value))
    if len(value) < TRIVIAL_LENGTH:
        return Verdict("too_short", True)
    if distinct < TRIVIAL_DISTINCT:
        return Verdict("low_variety", True)
    if len(value) < MIN_LENGTH:
        return Verdict("too_short", False)
    if distinct < MIN_DISTINCT:
        return Verdict("low_variety", False)
    return None


def _effective_secrets() -> Dict[str, str]:
    """The values actually in use (config / environment, else the generated ones from the secrets store)."""
    from src.identity import session_manager
    from src.utils.secrets_store import get_secret

    return {"SESSION_SECRET_KEY": session_manager.secret, "ENCRYPTION_KEY": get_secret("ENCRYPTION_KEY")}


def weak_secrets() -> List[dict]:
    """``[{"name", "reason"}]`` for every weak secret (for the dashboard)."""
    out = []
    for name, value in _effective_secrets().items():
        verdict = assess_secret(value)
        if verdict is not None:
            out.append({"name": name, "reason": verdict.reason})
    return out


def check_startup_secrets(*, fresh_install: bool) -> List[dict]:
    """Log a warning for every weak secret; raise WeakSecretError for a trivial one on a new install."""
    weak = []
    refused = []
    for name, value in _effective_secrets().items():
        verdict = assess_secret(value)
        if verdict is None:
            continue
        weak.append({"name": name, "reason": verdict.reason})
        if fresh_install and verdict.trivial:
            refused.append(f"{name} ({verdict.reason})")
        else:
            logger.warning(
                f"{name} is weak ({verdict.reason}): use at least {MIN_LENGTH} random characters, e.g. "
                "`python -c \"import secrets; print(secrets.token_urlsafe(32))\"`, or unset it to let MCP Gate "
                "generate one. "
                + ("Changing ENCRYPTION_KEY on an existing install makes the stored private keys unreadable: "
                   "see SECURITY.md before you rotate it." if name == "ENCRYPTION_KEY" else
                   "Changing SESSION_SECRET_KEY signs everyone out, nothing else.")
            )
    if refused:
        raise WeakSecretError(
            "Refusing to start a new install with a trivial secret: " + ", ".join(refused) + ". Set at least "
            f"{MIN_LENGTH} random characters, or unset the variable and MCP Gate generates one in data/secrets.json."
        )
    return weak
