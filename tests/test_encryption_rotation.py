"""#30: ENCRYPTION_KEY becomes a keyring and can be rotated with one command, without downtime.

Each ciphertext names its key (``mg1:<key id>:...``); values from before carry no tag and are tried with every
key. ``python -m src.cli encryption-key rotate`` adds a new key, re-encrypts every encrypted column, verifies, and
only then retires the old key; it refuses to start when something does not open, and resumes after an interruption.
"""

import base64
import json
import os

import pytest

from src.utils import crypto as crypto_mod
from src.utils import secrets_store
from src.utils.crypto import PREVIOUS_NAME, TokenCrypto, key_id_of_ciphertext

TEST_KEY = "test-encryption-key-not-for-production"  # tests/conftest.py


def _legacy_encrypt(secret, plaintext):
    """The format before #30: base64(nonce | tag | ciphertext), no key id."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    key = crypto_mod.derive_key(secret)
    nonce = os.urandom(12)
    enc = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    ct = enc.update(plaintext.encode()) + enc.finalize()
    return base64.b64encode(nonce + enc.tag + ct).decode()


# ---------------------------------------------------------------------------
# the keyring
# ---------------------------------------------------------------------------
def test_values_are_tagged_with_their_key():
    """TC-ENC-01: a new value names the key that made it; the key id reveals nothing usable."""
    c = TokenCrypto("key-A-unit-test-0123456789abcdef")
    value = c.encrypt("hello")
    assert value.startswith(f"mg1:{c.key_id}:") and len(c.key_id) == 12
    assert c.key_id not in crypto_mod.derive_key("key-A-unit-test-0123456789abcdef").hex()
    assert c.decrypt(value) == "hello"


def test_untagged_values_still_decrypt():
    """TC-ENC-02: values written before #30 open with the current single key, and with an old key in the ring."""
    legacy = _legacy_encrypt("old-key-0123456789abcdef0123456789", "secret")
    assert TokenCrypto("old-key-0123456789abcdef0123456789").decrypt(legacy) == "secret"
    ring = TokenCrypto("new-key-0123456789abcdef0123456789", ["old-key-0123456789abcdef0123456789"])
    assert ring.decrypt(legacy) == "secret"
    with pytest.raises(Exception):
        TokenCrypto("other-key-0123456789abcdef01234567").decrypt(legacy)


def test_newest_key_writes_and_previous_keys_read():
    """TC-ENC-03: the first key encrypts; values of a previous key still decrypt; a key not in the ring is named."""
    old = TokenCrypto("old-key-0123456789abcdef0123456789")
    ring = TokenCrypto("new-key-0123456789abcdef0123456789", ["old-key-0123456789abcdef0123456789"])
    value = old.encrypt("kept")
    assert ring.decrypt(value) == "kept"
    assert key_id_of_ciphertext(ring.encrypt("x")) == ring.key_id != old.key_id
    assert not ring.decrypts_with_newest(value) and ring.decrypts_with_newest(ring.encrypt("x"))
    with pytest.raises(crypto_mod.UnknownEncryptionKeyError):  # looked up now: another test reloads the module
        TokenCrypto("new-key-0123456789abcdef0123456789").decrypt(value)


def test_tampered_tagged_value_is_rejected():
    """TC-ENC-04: GCM still authenticates the tagged format."""
    c = TokenCrypto("key-A-unit-test-0123456789abcdef")
    value = c.encrypt("hello")
    with pytest.raises(Exception):
        c.decrypt(value[:-2] + ("AA" if value[-2:] != "AA" else "BB"))


@pytest.fixture
def file_keyring(tmp_path, monkeypatch):
    """ENCRYPTION_KEY kept in a secrets file (not the environment), holding the key the test database used."""
    path = tmp_path / "secrets.json"
    path.write_text(json.dumps({"ENCRYPTION_KEY": TEST_KEY}))
    monkeypatch.delenv("ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv(PREVIOUS_NAME, raising=False)
    monkeypatch.setenv("MCP_GATE_SECRETS_FILE", str(path))
    secrets_store.reset_cache()
    crypto_mod.reset_crypto()
    yield path
    secrets_store.reset_cache()
    crypto_mod.reset_crypto()


def test_running_server_picks_up_a_new_keyring(file_keyring):
    """TC-ENC-05: a server's keyring follows the secrets file: the next write uses the new key, a value naming a
    key it has not loaded yet makes it reload -- no restart."""
    server = TokenCrypto()
    before = server.key_id
    other = TokenCrypto("brand-new-key-0123456789abcdef01234")
    value_from_new_key = other.encrypt("from-cli")

    secrets_store.update_file(lambda v: v.update({"ENCRYPTION_KEY": "brand-new-key-0123456789abcdef01234",
                                                  PREVIOUS_NAME: TEST_KEY}))
    assert server.decrypt(value_from_new_key) == "from-cli"
    assert key_id_of_ciphertext(server.encrypt("x")) == other.key_id != before


def test_update_file_never_loses_a_concurrent_change(file_keyring):
    """TC-ENC-06: discarding the setup token re-reads the file under the lock, so a keyring written meanwhile by
    the rotation command (another process) is kept."""
    secrets_store.get_secret("SETUP_TOKEN")
    data = json.loads(file_keyring.read_text())
    data["ENCRYPTION_KEY"] = "written-by-another-process-0123456789"
    file_keyring.write_text(json.dumps(data))
    secrets_store.discard_secret("SETUP_TOKEN")
    assert json.loads(file_keyring.read_text()) == {"ENCRYPTION_KEY": "written-by-another-process-0123456789"}


# ---------------------------------------------------------------------------
# the rotation command
# ---------------------------------------------------------------------------
@pytest.fixture
def encrypted_rows(owner_client, db_session, file_keyring):
    """A signing key (exists), a service static token, managed-server env vars, and one value from before #30."""
    from db.models import ManagedMcpProcess, Service

    r = owner_client.post("/api/services", json={"name": "tok", "host": "127.0.0.1", "port": 8124,
                                                 "mcp_path": "/mcp", "auth_token": "static-token"})
    assert r.status_code == 201, r.text
    db_session.add(ManagedMcpProcess(name="m", catalog_id="c", docker_image="img",
                                     env_vars_encrypted=crypto_mod.encrypt_token(json.dumps({"API_KEY": "v"}))))
    db_session.add(Service(name="legacy", host="127.0.0.1", port=8125, mcp_path="/mcp",
                           auth_token_encrypted=_legacy_encrypt(TEST_KEY, "legacy-token")))
    db_session.commit()
    return {"service": r.json()["id"]}


def _plaintexts(db_session):
    from src.adapters import EncryptedColumnAdapter

    c = TokenCrypto()
    return {name: sorted(c.decrypt(v) for _, v in EncryptedColumnAdapter.values(db_session, name))
            for name in EncryptedColumnAdapter.COLUMNS}


def test_rotate_reencrypts_everything_and_retires_the_old_key(encrypted_rows, db_session, file_keyring):
    """TC-ENC-07: one command: a new key, every value of every encrypted column re-encrypted (the untagged one
    too) and still the same plaintext, then the old key leaves the secrets file."""
    from src import encryption_rotation as rotation

    before = _plaintexts(db_session)
    assert all(before.values())
    old_id = TokenCrypto().key_id
    messages = []
    summary = rotation.rotate(db_session, settle_seconds=0, out=messages.append)

    stored = json.loads(file_keyring.read_text())
    assert stored["ENCRYPTION_KEY"] != TEST_KEY and PREVIOUS_NAME not in stored
    assert summary["new_key"] and summary["retired"] == 1 and summary["key_id"] != old_id
    assert summary["reencrypted"] == sum(len(v) for v in before.values())
    secrets_store.reset_cache()
    crypto_mod.reset_crypto()
    assert _plaintexts(db_session) == before
    report = rotation.status(db_session)
    assert all(set(c) <= {"newest"} for c in report.values())
    assert os.stat(file_keyring).st_mode & 0o777 == 0o600


def test_rotate_refuses_when_something_does_not_open(encrypted_rows, db_session, file_keyring):
    """TC-ENC-08: a value no key in the ring opens: refused before anything changes (file and values intact)."""
    from db.models import Service
    from src import encryption_rotation as rotation

    db_session.add(Service(name="orphan", host="127.0.0.1", port=8126, mcp_path="/mcp",
                           auth_token_encrypted=TokenCrypto("lost-key-0123456789abcdef012345").encrypt("x")))
    db_session.commit()
    file_before = file_keyring.read_text()
    with pytest.raises(rotation.RotationRefused, match="1 encrypted value"):
        rotation.rotate(db_session, settle_seconds=0, out=lambda m: None)
    assert file_keyring.read_text() == file_before


def test_rotate_resumes_after_an_interruption(encrypted_rows, db_session, file_keyring):
    """TC-ENC-09: killed after the new key was written and part of the data re-encrypted: running it again makes
    no other key, finishes, and retires the old one."""
    from src import encryption_rotation as rotation
    from src.adapters import EncryptedColumnAdapter

    before = _plaintexts(db_session)
    secrets_store.update_file(lambda v: v.update({"ENCRYPTION_KEY": "resumed-key-0123456789abcdef0123456",
                                                  PREVIOUS_NAME: TEST_KEY}))
    crypto_mod.reset_crypto()
    ring = TokenCrypto()
    name = "services.auth_token_encrypted"
    key, value = EncryptedColumnAdapter.values(db_session, name)[0]
    EncryptedColumnAdapter.replace(db_session, name, key, value, ring.encrypt(ring.decrypt(value)))

    summary = rotation.rotate(db_session, settle_seconds=0, out=lambda m: None)
    stored = json.loads(file_keyring.read_text())
    assert not summary["new_key"] and stored == {"ENCRYPTION_KEY": "resumed-key-0123456789abcdef0123456"}
    secrets_store.reset_cache()
    crypto_mod.reset_crypto()
    assert _plaintexts(db_session) == before


def test_value_written_by_a_server_still_on_the_old_key_is_caught(encrypted_rows, db_session, file_keyring):
    """TC-ENC-10: a server writes with the old key during the run (before it noticed the new keyring): the next
    pass re-encrypts it, and the old key is retired only once nothing uses it."""
    from db.models import Service
    from src import encryption_rotation as rotation

    old = TokenCrypto(TEST_KEY)
    writes = []

    def late_server_write(_seconds):
        if not writes:
            db_session.add(Service(name="late", host="127.0.0.1", port=8127, mcp_path="/mcp",
                                   auth_token_encrypted=old.encrypt("late-token")))
            db_session.commit()
            writes.append(1)

    rotation.rotate(db_session, settle_seconds=1, out=lambda m: None, sleep=late_server_write)
    secrets_store.reset_cache()
    crypto_mod.reset_crypto()
    assert "late-token" in _plaintexts(db_session)["services.auth_token_encrypted"]
    assert all(set(c) <= {"newest"} for c in rotation.status(db_session).values())


def test_environment_key_is_reencrypted_under_but_never_changed(encrypted_rows, db_session, file_keyring,
                                                                monkeypatch):
    """TC-ENC-11: with ENCRYPTION_KEY in the environment the operator sets the new key there and the old one in
    ENCRYPTION_KEYS_PREVIOUS; the command re-encrypts under it and says the variable can go."""
    from src import encryption_rotation as rotation

    before = _plaintexts(db_session)
    monkeypatch.setenv("ENCRYPTION_KEY", "env-new-key-0123456789abcdef01234567")
    monkeypatch.setenv(PREVIOUS_NAME, TEST_KEY)
    file_keyring.write_text(json.dumps({}))
    crypto_mod.reset_crypto()
    messages = []
    summary = rotation.rotate(db_session, settle_seconds=0, out=messages.append)
    assert not summary["new_key"]
    assert json.loads(file_keyring.read_text()) == {}
    assert any("remove that variable" in m for m in messages)
    monkeypatch.delenv(PREVIOUS_NAME)
    crypto_mod.reset_crypto()
    assert _plaintexts(db_session) == before


def test_every_encrypted_column_is_rotated():
    """TC-ENC-12: a column holding encrypted data (named *_enc / *_encrypted) must be in the rotation's list."""
    from db.database import Base
    from src.adapters import EncryptedColumnAdapter

    found = {f"{t.name}.{c.name}" for t in Base.metadata.tables.values() for c in t.columns
             if c.name.endswith(("_enc", "_encrypted"))}
    assert found == set(EncryptedColumnAdapter.COLUMNS)


def test_cli_arguments():
    """TC-ENC-13: the command line."""
    from src.cli import parse_args

    args = parse_args(["encryption-key", "rotate", "--settle-seconds", "0"])
    assert (args.command, args.action, args.settle_seconds) == ("encryption-key", "rotate", 0.0)
    with pytest.raises(SystemExit):
        parse_args(["encryption-key", "delete"])
