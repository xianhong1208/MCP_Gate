"""Family revocation (code replay, refresh reuse) filters oauth_tokens on parent_jti: it is indexed, by the model
and by migration a7c9e1f3b5d7 (tests/test_schema_drift.py checks the two agree)."""

from sqlalchemy import inspect


def test_parent_jti_is_indexed(engine):
    indexes = inspect(engine).get_indexes("oauth_tokens")
    assert any(ix["column_names"] == ["parent_jti"] for ix in indexes), indexes


def test_family_revocation_uses_the_index_on_sqlite(engine):
    from sqlalchemy import text

    from tests.conftest import using_postgres
    if using_postgres():
        return  # the planner may still prefer a scan on a near-empty table; the index's existence is checked above
    with engine.connect() as conn:
        plan = " ".join(str(r[-1]) for r in conn.execute(text(
            "EXPLAIN QUERY PLAN SELECT jti FROM oauth_tokens WHERE (parent_jti = 'x' OR jti = 'x') "
            "AND revoked_at IS NULL")))
    assert "ix_oauth_tokens_parent_jti" in plan, plan
