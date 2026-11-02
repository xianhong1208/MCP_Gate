"""Known #6: weak SESSION_SECRET_KEY / ENCRYPTION_KEY values were accepted silently.

A guessable SESSION_SECRET_KEY lets anyone forge the HS256 console session (and its binding hash); a guessable
ENCRYPTION_KEY exposes the signing private keys at rest. Generated values are strong; the risk is a value set by
hand (``.env``, compose files, the docs' examples).

Policy: always warn loudly (log + dashboard banner). Refuse to start only when the value is *trivial* and the
install is *new* (no signing key yet, so nothing is encrypted with it and no session exists): refusing an existing
install would lock the owner out, and changing ENCRYPTION_KEY there makes the stored keys unreadable.
"""
import pytest

from src.utils.secret_policy import WeakSecretError, assess_secret, check_startup_secrets


@pytest.mark.parametrize("value, weak, trivial", [
    ("changeme", True, True),
    ("CHANGE_ME", True, True),
    ("secret", True, True),
    ("your-secret-key-here", True, True),
    ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", True, True),   # one character repeated
    ("abc123", True, True),                                    # short
    ("correct-horse-battery", True, False),                    # < 32 characters: weak, not trivial
    ("kQ3v9_TzP1xR8sLm2NwYb7Hc4JdUe6Fa0GoVi5Kt", False, False),
])
def test_assess_secret(value, weak, trivial):
    verdict = assess_secret(value)
    assert (verdict is not None) is weak
    assert (verdict is not None and verdict.trivial) is trivial


def _secrets(monkeypatch, session, encryption):
    import src.utils.secret_policy as policy

    monkeypatch.setattr(policy, "_effective_secrets", lambda: {"SESSION_SECRET_KEY": session,
                                                               "ENCRYPTION_KEY": encryption})


STRONG = "kQ3v9_TzP1xR8sLm2NwYb7Hc4JdUe6Fa0GoVi5Kt"


def test_trivial_secret_refused_on_a_new_install(monkeypatch):
    _secrets(monkeypatch, "changeme", STRONG)
    with pytest.raises(WeakSecretError) as e:
        check_startup_secrets(fresh_install=True)
    assert "SESSION_SECRET_KEY" in str(e.value)


def test_trivial_secret_only_warned_on_an_existing_install(monkeypatch, caplog):
    _secrets(monkeypatch, STRONG, "changeme")
    weak = check_startup_secrets(fresh_install=False)
    assert [w["name"] for w in weak] == ["ENCRYPTION_KEY"]


def test_weak_but_not_trivial_is_only_warned_even_when_new(monkeypatch):
    _secrets(monkeypatch, "correct-horse-battery", STRONG)
    assert [w["name"] for w in check_startup_secrets(fresh_install=True)] == ["SESSION_SECRET_KEY"]


def test_strong_secrets_pass(monkeypatch):
    _secrets(monkeypatch, STRONG, STRONG)
    assert check_startup_secrets(fresh_install=True) == []


def test_dashboard_overview_reports_weak_secrets(owner_client, monkeypatch):
    _secrets(monkeypatch, "correct-horse-battery", STRONG)
    overview = owner_client.get("/api/oauth/overview").json()
    assert overview["weak_secrets"] == [{"name": "SESSION_SECRET_KEY", "reason": "too_short"}]
    _secrets(monkeypatch, STRONG, STRONG)
    assert owner_client.get("/api/oauth/overview").json()["weak_secrets"] == []


def test_init_database_refuses_trivial_secret_only_before_the_first_signing_key(engine, monkeypatch):
    import main

    monkeypatch.setattr("src.utils.db_bootstrap.ensure_database_ready", lambda *a, **k: None)
    _secrets(monkeypatch, "changeme", STRONG)
    with pytest.raises(WeakSecretError):
        main.init_database(run_migrations=False)
    _secrets(monkeypatch, STRONG, STRONG)
    main.init_database(run_migrations=False)       # first start: the signing key now exists
    _secrets(monkeypatch, "changeme", STRONG)
    main.init_database(run_migrations=False)       # existing install: warned, not refused
