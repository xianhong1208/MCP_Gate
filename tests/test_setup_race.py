"""H-05: first-time setup creates exactly one owner, however many requests race it.

``setup_owner`` checked ``needs_setup()`` and then created the account ~0.25 s later (bcrypt in between). The
hunt fired 4 concurrent ``POST /api/session/setup`` with different emails: all returned 200 and left 4 admin
accounts, the extra ones invisible in the console. The guarantee now lives in the database (a unique
``owner_slot``), so it holds on SQLite and PostgreSQL alike and for any number of processes.
"""
from tests.conftest import SETUP_TOKEN
import threading

import pytest

from src.identity import service as identity_service
from src.identity.service import IdentityError

RACERS = 4


def test_concurrent_setup_creates_one_owner(seeded, monkeypatch):
    from db.database import make_session
    from db.models import AdminUser

    # Make the race certain: every racer passes the needs_setup() check before any of them writes
    barrier = threading.Barrier(RACERS, timeout=10)
    real_hash = identity_service.hash_password

    def slow_hash(password):
        hashed = real_hash(password)
        barrier.wait()
        return hashed

    monkeypatch.setattr(identity_service, "hash_password", slow_hash)
    results = []

    def racer(i):
        db = make_session()
        try:
            identity_service.setup_owner(db, email=f"user{i}@example.com", password=f"password-{i}-long",
                                          setup_token=SETUP_TOKEN)
            results.append("ok")
        except IdentityError as e:
            results.append((e.code, e.status_code))
        finally:
            db.close()

    threads = [threading.Thread(target=racer, args=(i,)) for i in range(RACERS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert results.count("ok") == 1, results
    assert sorted(r for r in results if r != "ok") == [("auth.setup_already_done", 409)] * (RACERS - 1)
    db = make_session()
    try:
        assert db.query(AdminUser).count() == 1
    finally:
        db.close()


def test_owner_slot_is_unique_at_the_database_level(seeded, db_session):
    from sqlalchemy.exc import IntegrityError

    from db.models import AdminUser

    db_session.add(AdminUser(email="a@example.com", username="a", owner_slot=1))
    db_session.commit()
    db_session.add(AdminUser(email="b@example.com", username="b", owner_slot=1))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()
    # Accounts that are not the owner leave it empty, any number of them
    db_session.add_all([AdminUser(email="c@example.com", username="c"), AdminUser(email="d@example.com", username="d")])
    db_session.commit()


def test_bootstrap_owner_takes_the_slot(engine, db_session):
    from db import seed_database
    from db.models import AdminUser

    seed_database(db_session, bootstrap_email="boot@example.com", bootstrap_password="bootstrap-password-1")
    owner = db_session.query(AdminUser).one()
    assert owner.owner_slot == 1
    with pytest.raises(IdentityError) as e:
        identity_service.setup_owner(db_session, email="late@example.com", password="late-password-1")
    assert e.value.status_code == 409


def test_migration_gives_the_slot_to_the_earliest_existing_account(tmp_path, monkeypatch):
    """Existing installs: the account created first becomes the owner, so setup stays closed."""
    from alembic import command
    from alembic.config import Config as AlembicConfig
    from sqlalchemy import create_engine, text

    from db.database import reset_engine
    from db.migrate import _resolve_alembic_dir
    from src.config import Config

    url = f"sqlite:///{tmp_path / 'm.db'}"
    monkeypatch.setenv("MCP_GATE_CONFIG", str(tmp_path / "missing.yaml"))
    db_cfg = Config.get_database_config()
    saved = db_cfg.url
    db_cfg.url = url
    reset_engine()
    try:
        cfg = AlembicConfig()
        cfg.set_main_option("script_location", str(_resolve_alembic_dir()))
        cfg.set_main_option("sqlalchemy.url", url)
        command.upgrade(cfg, "e5f7a9b1c3d5")
        engine = create_engine(url)
        with engine.begin() as conn:
            for i, created in ((2, "2026-02-01 00:00:00"), (1, "2026-01-01 00:00:00"), (3, "2026-03-01 00:00:00")):
                conn.execute(text(
                    "INSERT INTO admin_users (id, email, username, auth_provider, is_active, created_at) "
                    f"VALUES ('0000000000000000000000000000000{i}', 'u{i}@example.com', 'u{i}', 'local', 1, :c)"
                ), {"c": created})
        command.upgrade(cfg, "head")
        with engine.connect() as conn:
            rows = conn.execute(text("SELECT email, owner_slot FROM admin_users ORDER BY email")).all()
        assert rows == [("u1@example.com", 1), ("u2@example.com", None), ("u3@example.com", None)]
        command.downgrade(cfg, "e5f7a9b1c3d5")
        engine.dispose()
    finally:
        db_cfg.url = saved
        reset_engine()
