"""#29: the generated secrets live in their own directory, apart from data/.

ENCRYPTION_KEY used to be generated into data/secrets.json, next to the database it protects, so a copy of data/
alone carried both the encrypted signing keys and the key that decrypts them. The store now lives in secrets/
(MCP_GATE_SECRETS_DIR; MCP_GATE_SECRETS_FILE still names an exact file), created 0700 with the file 0600, and an
existing data/secrets.json is moved there once on startup -- never overwriting a file already there.
"""

import errno
import json
import logging
import os
import stat

import pytest

from src.utils import secrets_store


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    """A project root with no secrets anywhere; the default (relative) locations resolve under it."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MCP_GATE_SECRETS_FILE", raising=False)
    monkeypatch.delenv("MCP_GATE_SECRETS_DIR", raising=False)
    monkeypatch.delenv("SECRETS_DIR_TEST_VALUE", raising=False)
    secrets_store.reset_cache()
    yield tmp_path
    secrets_store.reset_cache()


def _mode(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def _legacy(root, data: dict):
    (root / "data").mkdir(exist_ok=True)
    path = root / "data" / "secrets.json"
    path.write_text(json.dumps(data))
    os.chmod(path, 0o600)
    return path


def test_secrets_are_generated_into_their_own_directory(workdir):
    """TC-SECDIR-01: a fresh install writes secrets/secrets.json (dir 0700, file 0600), nothing under data/."""
    value = secrets_store.get_secret("SECRETS_DIR_TEST_VALUE")

    path = workdir / "secrets" / "secrets.json"
    assert json.loads(path.read_text())["SECRETS_DIR_TEST_VALUE"] == value
    assert _mode(workdir / "secrets") == 0o700
    assert _mode(path) == 0o600
    assert not (workdir / "data").exists()
    assert secrets_store.store_location() == secrets_store._DEFAULT_DIR / "secrets.json"


def test_an_existing_secrets_directory_is_tightened(workdir):
    """TC-SECDIR-02: a secrets/ directory created by hand with 0755 becomes 0700 on the first write."""
    (workdir / "secrets").mkdir(mode=0o755)
    os.chmod(workdir / "secrets", 0o755)

    secrets_store.get_secret("SECRETS_DIR_TEST_VALUE")

    assert _mode(workdir / "secrets") == 0o700


def test_secrets_dir_variable_moves_the_store(workdir):
    """TC-SECDIR-03: MCP_GATE_SECRETS_DIR names the directory (e.g. a separate Docker volume)."""
    os.environ["MCP_GATE_SECRETS_DIR"] = str(workdir / "vol" / "keys")
    try:
        secrets_store.get_secret("SECRETS_DIR_TEST_VALUE")
        assert (workdir / "vol" / "keys" / "secrets.json").is_file()
        assert _mode(workdir / "vol" / "keys") == 0o700
        assert not (workdir / "secrets").exists()
    finally:
        del os.environ["MCP_GATE_SECRETS_DIR"]


def test_secrets_file_variable_is_an_exact_file(workdir, monkeypatch):
    """TC-SECDIR-04: MCP_GATE_SECRETS_FILE wins over the directory, and its parent's mode is left alone."""
    (workdir / "shared").mkdir(mode=0o755)
    os.chmod(workdir / "shared", 0o755)
    monkeypatch.setenv("MCP_GATE_SECRETS_DIR", str(workdir / "ignored"))
    monkeypatch.setenv("MCP_GATE_SECRETS_FILE", str(workdir / "shared" / "mine.json"))

    secrets_store.get_secret("SECRETS_DIR_TEST_VALUE")

    assert _mode(workdir / "shared" / "mine.json") == 0o600
    assert _mode(workdir / "shared") == 0o755
    assert not (workdir / "ignored").exists()


def test_legacy_file_is_moved_and_its_keys_kept(workdir, caplog):
    """TC-SECDIR-05: data/secrets.json moves to secrets/ unchanged, so ENCRYPTION_KEY stays the same; logged once."""
    legacy = _legacy(workdir, {"ENCRYPTION_KEY": "kept-encryption-key", "SESSION_SECRET_KEY": "kept-session"})
    caplog.set_level(logging.WARNING, logger="src.utils.secrets_store")

    message = secrets_store.migrate_legacy_store()

    assert not legacy.exists()
    moved = workdir / "secrets" / "secrets.json"
    assert json.loads(moved.read_text()) == {"ENCRYPTION_KEY": "kept-encryption-key",
                                             "SESSION_SECRET_KEY": "kept-session"}
    assert _mode(moved) == 0o600 and _mode(workdir / "secrets") == 0o700
    assert "Moved the generated secrets" in message
    assert [r.message for r in caplog.records].count(message) == 1
    # Once per process: a second call (every read calls it) does nothing and logs nothing
    assert secrets_store.migrate_legacy_store() is None
    assert len(caplog.records) == 1


def test_first_read_moves_the_legacy_file(workdir, monkeypatch):
    """TC-SECDIR-06: without the explicit startup call, the first read moves it before reading."""
    monkeypatch.delenv("ENCRYPTION_KEY", raising=False)
    _legacy(workdir, {"ENCRYPTION_KEY": "kept-encryption-key"})

    assert secrets_store.get_secret("ENCRYPTION_KEY") == "kept-encryption-key"
    assert (workdir / "secrets" / "secrets.json").is_file()
    assert not (workdir / "data" / "secrets.json").exists()


def test_existing_new_file_is_never_overwritten(workdir, caplog):
    """TC-SECDIR-07: when both exist the new one is used, the old one is left in place and a warning says so."""
    legacy = _legacy(workdir, {"ENCRYPTION_KEY": "old"})
    (workdir / "secrets").mkdir()
    (workdir / "secrets" / "secrets.json").write_text(json.dumps({"ENCRYPTION_KEY": "new"}))
    caplog.set_level(logging.WARNING, logger="src.utils.secrets_store")

    message = secrets_store.migrate_legacy_store()

    assert json.loads((workdir / "secrets" / "secrets.json").read_text()) == {"ENCRYPTION_KEY": "new"}
    assert json.loads(legacy.read_text()) == {"ENCRYPTION_KEY": "old"}
    assert "no longer read" in message
    assert any("no longer read" in r.message for r in caplog.records)


def test_explicit_file_disables_the_move(workdir, monkeypatch):
    """TC-SECDIR-08: with MCP_GATE_SECRETS_FILE the operator chose the file; data/secrets.json is not touched."""
    legacy = _legacy(workdir, {"ENCRYPTION_KEY": "old"})
    monkeypatch.setenv("MCP_GATE_SECRETS_FILE", str(workdir / "elsewhere.json"))

    assert secrets_store.migrate_legacy_store() is None
    assert legacy.exists() and not (workdir / "secrets").exists()


def test_environment_still_wins(workdir, monkeypatch):
    """TC-SECDIR-09: an ENCRYPTION_KEY environment variable wins over the moved file."""
    _legacy(workdir, {"ENCRYPTION_KEY": "from-file"})
    monkeypatch.setenv("ENCRYPTION_KEY", "from-env")

    assert secrets_store.get_secret("ENCRYPTION_KEY") == "from-env"


def test_move_across_file_systems(workdir, monkeypatch):
    """TC-SECDIR-10: data/ and secrets/ on different file systems (separate volumes): os.link fails with EXDEV
    for the direct link, the content is copied through a 0600 temporary file and linked into place."""
    _legacy(workdir, {"ENCRYPTION_KEY": "kept"})
    real_link = os.link
    calls = []

    def link(src, dst, *a, **kw):
        calls.append(str(src))
        if str(src).endswith(os.path.join("data", "secrets.json")):
            raise OSError(errno.EXDEV, "Invalid cross-device link")
        return real_link(src, dst, *a, **kw)

    monkeypatch.setattr(os, "link", link)
    secrets_store.migrate_legacy_store()

    moved = workdir / "secrets" / "secrets.json"
    assert json.loads(moved.read_text()) == {"ENCRYPTION_KEY": "kept"}
    assert _mode(moved) == 0o600
    assert not (workdir / "data" / "secrets.json").exists()
    assert len(calls) == 2
    assert [p.name for p in (workdir / "secrets").iterdir()] == ["secrets.json"]  # no temporary file left


def test_failed_move_never_generates_a_new_key(workdir, monkeypatch):
    """TC-SECDIR-11: if the move fails, reading ENCRYPTION_KEY raises -- every time -- instead of generating a
    new key that would make the database unreadable."""
    monkeypatch.delenv("ENCRYPTION_KEY", raising=False)
    legacy = _legacy(workdir, {"ENCRYPTION_KEY": "kept"})

    def broken(src, dst):
        raise PermissionError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(secrets_store, "_link_into_place", broken)
    for _ in range(2):
        with pytest.raises(PermissionError):
            secrets_store.get_secret("ENCRYPTION_KEY")
    assert json.loads(legacy.read_text()) == {"ENCRYPTION_KEY": "kept"}
    assert not (workdir / "secrets" / "secrets.json").exists()


def test_saved_file_is_never_world_readable(workdir, monkeypatch):
    """TC-SECDIR-12: the file is created 0600 (not chmod-ed afterwards), whatever the umask."""
    old = os.umask(0)
    try:
        secrets_store.get_secret("SECRETS_DIR_TEST_VALUE")
    finally:
        os.umask(old)
    assert _mode(workdir / "secrets" / "secrets.json") == 0o600
