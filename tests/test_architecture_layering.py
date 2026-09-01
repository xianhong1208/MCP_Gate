"""Architecture fitness function: the three-layer invariants.

routes (src/api, main.py) -> adapters (src/adapters) -> db.crud.
Only the adapter layer may import db.crud. This rule used to live only in the docs of src/adapters/__init__.py and
was checked by manual grep; here it is pinned into CI -- any route that imports crud directly goes red.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CRUD_IMPORT = re.compile(r"^\s*(from\s+db\.crud\b|import\s+db\.crud\b)", re.M)


def _py_files(*dirs: str):
    for d in dirs:
        p = ROOT / d
        if p.is_file():
            yield p
        else:
            yield from p.rglob("*.py")


def test_only_adapters_import_db_crud():
    offenders = []
    for f in _py_files("main.py", "src"):
        rel = f.relative_to(ROOT).as_posix()
        if rel.startswith("src/adapters/"):
            continue
        if CRUD_IMPORT.search(f.read_text(encoding="utf-8")):
            offenders.append(rel)
    assert offenders == [], f"These files bypass the adapter layer and import db.crud directly: {offenders}"


def test_adapters_do_import_crud():
    """Reverse sentinel: if the adapter layer no longer imports crud at all, the rule's premise has changed and
    this test should be rewritten."""
    assert any(
        CRUD_IMPORT.search(f.read_text(encoding="utf-8")) for f in _py_files("src/adapters")
    )


@pytest.mark.parametrize("layer", ["src/api", "src/orchestrator", "src/discovery"])
def test_no_direct_db_session_commit_outside_adapters(layer):
    """Routes / service layers must not db.commit() themselves: the transaction boundary belongs to the adapter.

    The scheduler is exempt -- it calls make_session() itself and owns its own transactions.
    The allowlist below is an inventory of known technical debt, not a permit: the numbers may only go down,
    and each one paid off is removed from the list; new files must never commit directly.
    """
    allowed = {}
    offenders = []
    for f in _py_files(layer):
        rel = f.relative_to(ROOT).as_posix()
        n = len(re.findall(r"\bdb\.commit\(\)", f.read_text(encoding="utf-8")))
        if n > allowed.get(rel, 0):
            offenders.append(f"{rel} ({n} > allowed {allowed.get(rel, 0)})")
    assert offenders == [], f"Direct db.commit() in {layer} exceeds the inventoried technical debt: {offenders}"
