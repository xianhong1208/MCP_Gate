"""Startup seed data (idempotent).

1. OAuth scope registry
2. Built-in client `mcp-center-console` (used by the console to sign PATs / by the scanner to self-sign tokens)
3. Owner account (created only when both ADMIN_EMAIL and ADMIN_PASSWORD are set; otherwise left to the /setup page)
"""

from typing import Dict, List, Tuple

from sqlalchemy.orm import Session

from db.models import AdminUser, OAuthClient, OAuthScope, local_now

# (name, description, is_default)
DEFAULT_SCOPES: List[Tuple[str, str, bool]] = [
    ("mcp:tools:read", "List / read tool metadata", True),
    ("mcp:tools:invoke", "Invoke tools", True),
    ("mcp:resources:read", "Read resources", True),
    ("mcp:prompts:read", "Read prompts", True),
    ("offline_access", "Request a refresh token", False),
]

CONSOLE_CLIENT_ID = "mcp-center-console"
SCANNER_CLIENT_ID = "mcp-center-scanner"

SYSTEM_CLIENTS: List[Dict] = [
    {
        "client_id": CONSOLE_CLIENT_ID,
        "client_name": "MCP Center Console",
        "grant_types": '["personal_access_token"]',
    },
    {
        "client_id": SCANNER_CLIENT_ID,
        "client_name": "MCP Center Scanner",
        "grant_types": '["internal"]',
    },
]


def seed_scopes(db: Session) -> int:
    for name, desc, is_default in DEFAULT_SCOPES:
        existing = db.query(OAuthScope).filter(OAuthScope.name == name).first()
        if existing is None:
            db.add(OAuthScope(name=name, description=desc, is_default=is_default))
    db.commit()
    return db.query(OAuthScope).count()


def seed_system_clients(db: Session) -> None:
    for spec in SYSTEM_CLIENTS:
        if db.query(OAuthClient).filter(OAuthClient.client_id == spec["client_id"]).first():
            continue
        db.add(OAuthClient(
            client_id=spec["client_id"],
            client_name=spec["client_name"],
            redirect_uris="[]",
            grant_types=spec["grant_types"],
            response_types="[]",
            token_endpoint_auth_method="none",
            created_via="system",
            is_approved=True,
            is_active=True,
        ))
    db.commit()


def seed_owner(db: Session, email: str, password: str, username: str = "owner") -> AdminUser | None:
    """Create the owner account (no-op if any account already exists)."""
    if not email or not password:
        return None
    if db.query(AdminUser).count() > 0:
        return None
    from src.identity.passwords import hash_password
    user = AdminUser(
        email=email.strip().lower(),
        username=username,
        password_hash=hash_password(password),
        auth_provider="local",
        is_active=True,
        password_changed_at=local_now(),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def seed_database(db: Session, *, bootstrap_email: str = "", bootstrap_password: str = "") -> dict:
    scopes = seed_scopes(db)
    seed_system_clients(db)
    owner = seed_owner(db, bootstrap_email, bootstrap_password)
    return {
        "scopes": scopes,
        "owner_created": owner is not None,
        "users": db.query(AdminUser).count(),
    }
