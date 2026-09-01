"""Database package

Public API:
    Base            ORM declarative base
    get_db          FastAPI dependency (yields a session, closes it automatically)
    make_session    obtain a session manually (caller must close it)
    get_engine      get the SQLAlchemy engine
    seed_database   startup seed data (OAuth scope registry, built-in clients, owner account)
"""
from db.database import Base, get_db, make_session, get_engine, reset_engine
from db.models import AdminUser
from db.seed import seed_database

__all__ = [
    "Base", "get_db", "make_session", "get_engine", "reset_engine",
    "AdminUser", "seed_database",
]
