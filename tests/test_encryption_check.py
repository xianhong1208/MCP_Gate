"""A lost or replaced secrets file stops startup instead of starting a server whose signing key does not decrypt.

Before: with the secrets volume gone, MCP Gate generated a fresh ENCRYPTION_KEY, started, reported healthy, served
the unchanged JWKS, and answered every token request with 500 ``UnknownEncryptionKeyError``.
"""

import json

import pytest

from src.encryption_check import EncryptionKeyMismatchError, check_encryption_key
from src.utils import crypto as crypto_mod
from src.utils import secrets_store
from src.utils.crypto import PREVIOUS_NAME, TokenCrypto

KEY_A = "key-A-startup-check-0123456789abcdef0123"
KEY_B = "key-B-startup-check-0123456789abcdef0123"


@pytest.fixture
def keys(tmp_path, monkeypatch):
    """A secrets file of its own; ``use(env=..., file=..., previous=...)`` switches the keyring."""
    path = tmp_path / "secrets" / "secrets.json"
    monkeypatch.setenv("MCP_GATE_SECRETS_FILE", str(path))
    monkeypatch.delenv(PREVIOUS_NAME, raising=False)

    def use(env=None, file=None, previous=None):
        if env:
            monkeypatch.setenv("ENCRYPTION_KEY", env)
        else:
            monkeypatch.delenv("ENCRYPTION_KEY", raising=False)
        if previous:
            monkeypatch.setenv(PREVIOUS_NAME, previous)
        else:
            monkeypatch.delenv(PREVIOUS_NAME, raising=False)
        if file is None:
            path.unlink(missing_ok=True)
        else:
            path.parent.mkdir(exist_ok=True)
            path.write_text(json.dumps({"ENCRYPTION_KEY": file}))
        secrets_store.reset_cache()
        crypto_mod.reset_crypto()

    use(env=KEY_A)
    yield type("Keys", (), {"use": staticmethod(use), "path": path})
    secrets_store.reset_cache()
    crypto_mod.reset_crypto()


def _active_key(db):
    from src.oauth.signing_keys import ensure_active_signing_key
    return ensure_active_signing_key(db)


def _new_key_now(db):
    from datetime import timedelta

    from db.models import local_now
    from src.oauth.signing_keys import schedule_rotation
    return schedule_rotation(db, activates_at=local_now() - timedelta(seconds=1))


def _pending_key(db):
    from datetime import timedelta

    from db.models import local_now
    from src.oauth.signing_keys import schedule_rotation
    return schedule_rotation(db, activates_at=local_now() + timedelta(days=1))


def test_new_install_passes_and_generates_the_key(engine, db_session, keys):
    """TC-KCHK-01: an empty database has nothing encrypted: the check passes without writing anything."""
    keys.use()
    assert check_encryption_key(db_session) is None
    assert not keys.path.exists()


def test_init_database_on_a_new_install_still_generates(engine, keys, monkeypatch):
    """TC-KCHK-02: a first start with no key anywhere generates ENCRYPTION_KEY and a signing key that decrypts."""
    import main

    monkeypatch.setattr("src.utils.db_bootstrap.ensure_database_ready", lambda *a, **k: None)
    monkeypatch.setenv("SESSION_SECRET_KEY", "session-secret-for-the-startup-check-0123")
    keys.use()
    summary = main.init_database(run_migrations=False)
    stored = json.loads(keys.path.read_text())
    assert stored.get("ENCRYPTION_KEY")
    from db.database import make_session
    from src.adapters import OAuthKeyAdapter
    db = make_session()
    try:
        key = OAuthKeyAdapter.get_by_kid(db, summary["signing_kid"])
        assert TokenCrypto(stored["ENCRYPTION_KEY"]).decrypt(key.private_pem_enc).startswith("-----BEGIN")
    finally:
        db.close()


def test_lost_secrets_file_refuses_and_generates_nothing(engine, db_session, keys, monkeypatch):
    """TC-KCHK-03: the database holds encrypted keys, but neither the environment nor the secrets file holds a key
    (the secrets volume was lost): refuse, and never write a new key."""
    import main

    keys.use(file=KEY_A)
    _active_key(db_session)
    keys.use()
    with pytest.raises(EncryptionKeyMismatchError) as e:
        check_encryption_key(db_session)
    message = str(e.value)
    assert "does not match the database" in message and "no ENCRYPTION_KEY is set" in message
    assert str(keys.path) in message and "restore" in message and "ENCRYPTION_KEYS_PREVIOUS" in message
    assert TokenCrypto(KEY_A).key_id in message           # which key the database needs
    assert not keys.path.exists()

    monkeypatch.setattr("src.utils.db_bootstrap.ensure_database_ready", lambda *a, **k: None)
    with pytest.raises(EncryptionKeyMismatchError):
        main.init_database(run_migrations=False)
    assert not keys.path.exists()                          # nothing generated: not even the session secret


@pytest.mark.parametrize("where", ["file", "env"])
def test_replaced_key_refuses(engine, db_session, keys, where):
    """TC-KCHK-04: a different key (a secrets file from another install, or a changed ENCRYPTION_KEY) cannot open
    the active signing key: refuse, naming the key id the database needs and the ones configured."""
    keys.use(env=KEY_A)
    key = _active_key(db_session)
    keys.use(**{where: KEY_B})
    with pytest.raises(EncryptionKeyMismatchError) as e:
        check_encryption_key(db_session)
    message = str(e.value)
    assert key.kid[:12] in message and "cannot be decrypted" in message
    assert TokenCrypto(KEY_A).key_id in message and TokenCrypto(KEY_B).key_id in message


@pytest.mark.parametrize("how", ["file", "env", "previous"])
def test_the_documented_fixes_work(engine, db_session, keys, how):
    """TC-KCHK-05: restoring the secrets file, setting ENCRYPTION_KEY, or putting the old key in
    ENCRYPTION_KEYS_PREVIOUS (a new key is then generated for new writes) all pass the check, and the key signs."""
    from src.oauth.signing_keys import load_private_pem

    keys.use(env=KEY_A)
    key = _active_key(db_session)
    keys.use(**{how: KEY_A})
    assert check_encryption_key(db_session) is None
    assert load_private_pem(key).startswith("-----BEGIN")


def test_unreadable_pending_key_refuses(engine, db_session, keys):
    """TC-KCHK-06: the published key that is about to sign is checked too, not only the active one."""
    keys.use(env=KEY_A)
    _active_key(db_session)
    keys.use(env=KEY_B)
    pending = _pending_key(db_session)
    keys.use(env=KEY_A)
    with pytest.raises(EncryptionKeyMismatchError) as e:
        check_encryption_key(db_session)
    assert pending.kid[:12] in str(e.value)


def test_unreadable_values_outside_the_signing_keys_only_warn(engine, db_session, keys):
    """TC-KCHK-07: a retired key or a stored service token that does not open breaks only itself: logged, start
    allowed. A revoked key (private key wiped) is not checked at all."""
    from db.models import Service

    keys.use(env=KEY_A)
    _active_key(db_session)
    keys.use(env=KEY_B)
    _new_key_now(db_session)                               # the KEY_A key is retired now
    assert check_encryption_key(db_session) is not None    # warned, not refused

    db_session.add(Service(name="t", host="127.0.0.1", port=8124, mcp_path="/mcp",
                           auth_token_encrypted=TokenCrypto(KEY_A).encrypt("tok")))
    db_session.commit()
    warning = check_encryption_key(db_session)
    assert "oauth_signing_keys.private_pem_enc: 1" in warning and "services.auth_token_encrypted: 1" in warning


def test_revoked_key_is_not_checked(engine, db_session, keys):
    """TC-KCHK-08: a revoked active key's private key is wiped; the replacement is what must open."""
    from src.oauth.signing_keys import revoke_signing_key

    keys.use(env=KEY_A)
    key = _active_key(db_session)
    revoke_signing_key(db_session, key)
    assert check_encryption_key(db_session) is None


def test_main_exits_with_the_error_logged(monkeypatch):
    """TC-KCHK-09: main() logs the error (so it reaches the log file) and exits 1, like a weak secret."""
    import main

    def refuse(**_):
        raise EncryptionKeyMismatchError("The encryption key does not match the database: test")

    errors = []
    monkeypatch.setattr(main, "init_database", refuse)
    monkeypatch.setattr(main.logger, "error", lambda msg, *a, **k: errors.append(str(msg)))
    monkeypatch.setattr(main, "setup_logging", lambda **_: None)
    monkeypatch.setattr(main.Config, "set_config_dir", lambda *_: None)
    monkeypatch.setattr("sys.argv", ["main.py"])
    with pytest.raises(SystemExit) as e:
        main.main()
    assert e.value.code == 1
    assert errors == ["The encryption key does not match the database: test"]
