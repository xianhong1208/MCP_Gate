"""Pieces of a server's tool access policy (#37) that do not need the database: how a stored rule looks in the
policy, and which scope a tool's step-up challenge names. ToolAccessAdapter.build_policy assembles the whole policy
(the evaluator's input, see evaluate.py) from the stored rows with these."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, Optional


def epoch_utc(dt: Optional[datetime]) -> Optional[int]:
    """A naive UTC datetime -> unix seconds."""
    return int(dt.replace(tzinfo=timezone.utc).timestamp()) if dt is not None else None


def rule_entry(rule) -> dict:
    """A stored ToolAccessRule as the evaluator (and the policy feed) sees it. A group subject is still a group
    here; evaluate.expand_groups turns it into one entry per member."""
    return {
        "id": str(rule.id),
        "effect": rule.effect,
        "subject": {"kind": rule.subject_kind, "id": rule.subject_id},
        "tools": rule.tool_list(),
        "expires_at": epoch_utc(rule.expires_at),
    }


def is_expired(rule, now_utc: datetime) -> bool:
    return rule.expires_at is not None and rule.expires_at <= now_utc


def challenge_scope(memberships: Iterable, sizes: dict) -> Optional[str]:
    """The scope a step-up challenge names for one tool: the membership marked as the challenge, otherwise the
    narrowest scope (the fewest listed tools, then the name). ``memberships`` are the tool's ToolScope rows;
    ``sizes`` is ToolScopeCRUD.scope_sizes()."""
    rows = list(memberships)
    if not rows:
        return None
    marked = sorted(r.scope_name for r in rows if r.is_challenge)
    if marked:
        return marked[0]

    def key(row):
        sid = str(row.scope_service_id) if row.scope_service_id else None
        return sizes.get((row.scope_name, sid), 0), row.scope_name

    return min(rows, key=key).scope_name
