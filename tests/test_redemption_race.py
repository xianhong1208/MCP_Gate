"""Single use under concurrency: two simultaneous redemptions of one authorization code (or one refresh token)
must not both get tokens. The claim is a conditional UPDATE; the loser behaves like a replay (invalid_grant, and
every token of the grant -- including the ones the winner just got -- is revoked).

Both requests are forced to read the record before either claims it (a barrier after the read), which is exactly
the window a check-then-set implementation loses. Runs on SQLite and, with TEST_DATABASE_URL, on PostgreSQL.
"""

import threading

from src.adapters import OAuthCodeAdapter, OAuthTokenAdapter
from src.oauth.errors import OAuthError
from tests.test_oauth_flow import REDIRECT_URI, _authorize_and_consent, _exchange, _register

RACERS = "redeem-"


def _race(monkeypatch, adapter, method: str, redeem):
    """Run ``redeem(session)`` in two threads, each with its own session, both pausing after their first
    ``adapter.method`` read until the other has read too. Returns [(result | OAuthError)] for both."""
    from db.database import make_session

    original = getattr(adapter, method)
    barrier = threading.Barrier(2, timeout=10)
    paused = set()

    def read_then_wait(*args, **kwargs):
        out = original(*args, **kwargs)
        name = threading.current_thread().name
        if name.startswith(RACERS) and name not in paused:
            paused.add(name)
            barrier.wait()
        return out

    monkeypatch.setattr(adapter, method, read_then_wait)
    outcomes = [None, None]

    def run(i):
        db = make_session()
        try:
            outcomes[i] = redeem(db)
        except OAuthError as e:
            db.rollback()
            outcomes[i] = e
        except Exception as e:  # pragma: no cover - surfaced by the assertions below
            db.rollback()
            outcomes[i] = e
        finally:
            db.close()

    threads = [threading.Thread(target=run, args=(i,), name=f"{RACERS}{i}") for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert not any(t.is_alive() for t in threads), "a redemption hung"
    return outcomes


def _split(outcomes):
    wins = [o for o in outcomes if isinstance(o, dict)]
    losses = [o for o in outcomes if isinstance(o, OAuthError)]
    assert len(wins) + len(losses) == 2, outcomes
    return wins, losses


def _family(db_session, parent):
    db_session.expire_all()
    from db.models import OAuthToken
    return db_session.query(OAuthToken).filter((OAuthToken.parent_jti == parent) | (OAuthToken.jti == parent)).all()


def test_concurrent_code_redemption_issues_tokens_once(owner_client, service, monkeypatch, db_session):
    from src.adapters import OAuthClientAdapter
    from src.oauth import service as oauth
    from src.utils.crypto import hash_token

    reg = _register(owner_client)
    code, verifier = _authorize_and_consent(owner_client, reg["client_id"])

    def redeem(db):
        client = OAuthClientAdapter.get(db, reg["client_id"])
        return oauth.authorization_code_grant(db, client=client, code=code, redirect_uri=REDIRECT_URI,
                                              code_verifier=verifier, resource=None)

    wins, losses = _split(_race(monkeypatch, OAuthCodeAdapter, "get_by_hash", redeem))
    assert len(wins) == 1 and len(losses) == 1, (wins, losses)
    assert losses[0].error == "invalid_grant"
    # The loser is a replay: whatever the winner got is revoked
    tokens = _family(db_session, hash_token(code))
    assert {t.kind for t in tokens} == {"access", "refresh"}
    assert all(t.revoked_at is not None and t.revoke_reason == "code_replay" for t in tokens)


def test_concurrent_refresh_rotates_once(owner_client, service, monkeypatch, db_session):
    from src.adapters import OAuthClientAdapter
    from src.oauth import service as oauth

    reg = _register(owner_client)
    code, verifier = _authorize_and_consent(owner_client, reg["client_id"])
    first = _exchange(owner_client, reg["client_id"], code, verifier).json()

    def redeem(db):
        client = OAuthClientAdapter.get(db, reg["client_id"])
        return oauth.refresh_token_grant(db, client=client, refresh_token=first["refresh_token"],
                                         requested_scope=None)

    wins, losses = _split(_race(monkeypatch, OAuthTokenAdapter, "get", redeem))
    assert len(wins) == 1 and len(losses) == 1, (wins, losses)
    assert losses[0].error == "invalid_grant"
    import jwt
    family = jwt.decode(first["refresh_token"], options={"verify_signature": False})["jti"]
    rec = OAuthTokenAdapter.get(db_session, family)
    tokens = _family(db_session, rec.parent_jti or rec.jti)
    rotated_away = [t for t in tokens if t.jti == family]
    assert rotated_away and rotated_away[0].revoke_reason == "rotated"
    # Every token the winner got is revoked as a replay
    issued_by_winner = [t for t in tokens if t.issued_at >= rec.issued_at and t.jti != family and t.revoked_at
                        and t.revoke_reason == "refresh_replay"]
    assert len(issued_by_winner) >= 2
    assert all(t.revoked_at is not None for t in tokens)


def test_sequential_replay_still_revokes(owner_client, service):
    """The ordinary (non-concurrent) replay keeps behaving as before."""
    reg = _register(owner_client)
    code, verifier = _authorize_and_consent(owner_client, reg["client_id"])
    assert _exchange(owner_client, reg["client_id"], code, verifier).status_code == 200
    again = _exchange(owner_client, reg["client_id"], code, verifier)
    assert again.status_code == 400 and again.json()["error"] == "invalid_grant"
