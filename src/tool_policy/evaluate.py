"""Tool access evaluator (#37): may this token call this tool, and if not, why.

One pure function, stdlib only, so the same logic can be copied into a server-side middleware
(examples/mcp_gate_hooks.py, 1.6 PR 2) and both ends are pinned by the golden vectors in
tests/fixtures/tool_policy_vectors.json (``RULES_VERSION`` names the version those vectors describe).

Input
-----
``policy`` (what MCP Gate builds for one server, src/tool_policy/policy.py, and what the policy feed will carry)::

    {
      "unscoped_tools": "allow" | "require",
      "tool_scopes": {"<tool>": {"any_of": ["<scope>", ...], "challenge": "<scope>"}},
      "rules": [
        {"id": "<rule id>", "effect": "deny" | "only",
         "subject": {"kind": "pat" | "client" | "user", "id": "<jti | client_id | sub>"},
         "tools": ["<tool>", ...] | ["*"],
         "expires_at": <unix seconds> | null}
      ]
    }

Groups never appear here: MCP Gate expands a group rule into one rule per member (subject kind "user", same id)
before building the policy. ``token`` is the verified token's claims (``jti``, ``client_id``, ``sub``, ``scope`` as
a space-separated string); ``approved`` says whether the tool's current definition is approved (1.5 pinning);
``now`` (unix seconds) drops expired rules.

Precedence (first match decides)
--------------------------------
1. not approved                                        -> hidden    (not_approved)
2. a deny rule matches the token and names the tool    -> hidden    (denied_by_rule)
3. "only" rules match and the tool is outside any one  -> hidden    (outside_only_rule)
4. the tool has scopes and the token holds none of them -> needs_scope (missing_scope), with the challenge scope
   the tool has no scope and the server requires one   -> hidden    (unscoped_tool_requires_scope)
5. otherwise                                           -> allowed   (ok)

Fail-closed details: a rule whose effect is not known is applied as a deny of the tools it names (of every tool when
it names none); a rule whose subject kind is not known matches every token. A hidden tool is not listed and its call
is refused as "not available"; a needs_scope tool is listed and its call is refused with an insufficient_scope
challenge (step-up).
"""

from __future__ import annotations

from typing import Iterable, Optional

RULES_VERSION = 1

ALLOWED = "allowed"
HIDDEN = "hidden"
NEEDS_SCOPE = "needs_scope"

REASON_OK = "ok"
REASON_NOT_APPROVED = "not_approved"
REASON_DENIED = "denied_by_rule"
REASON_OUTSIDE_ONLY = "outside_only_rule"
REASON_MISSING_SCOPE = "missing_scope"
REASON_UNSCOPED = "unscoped_tool_requires_scope"

ALL_TOOLS = "*"
_KNOWN_EFFECTS = ("deny", "only")
_CLAIM_OF_KIND = {"pat": "jti", "client": "client_id", "user": "sub"}


def _scopes_of(token: dict) -> set:
    raw = token.get("scope")
    if isinstance(raw, str):
        return set(raw.split())
    if isinstance(raw, (list, tuple)):
        return {s for s in raw if isinstance(s, str)}
    return set()


def subject_matches(subject, token: dict) -> bool:
    """A rule's subject against the token's claims. A personal access token is matched by its jti (old PATs may
    still carry a pre-1.4 client_id, so the client is not checked). An unknown kind matches every token."""
    if not isinstance(subject, dict):
        return True
    claim = _CLAIM_OF_KIND.get(subject.get("kind"))
    if claim is None:
        return True
    value = token.get(claim)
    return isinstance(value, str) and value != "" and value == subject.get("id")


def _names(rule: dict) -> list:
    tools = rule.get("tools")
    return [t for t in tools if isinstance(t, str)] if isinstance(tools, list) else []


def _names_tool(rule: dict, tool: str) -> bool:
    names = _names(rule)
    return ALL_TOOLS in names or tool in names


def _active(rule: dict, now: Optional[float]) -> bool:
    expires = rule.get("expires_at")
    if expires is None or now is None:
        return True
    try:
        return float(expires) > float(now)
    except (TypeError, ValueError):
        return True  # unreadable expiry: keep applying the rule (fail closed)


def _verdict(decision: str, reason: str, *, rule_ids: Iterable = (), scopes: Iterable = (),
             challenge: Optional[str] = None) -> dict:
    return {"decision": decision, "reason": reason, "rule_ids": sorted({str(r) for r in rule_ids}),
            "scopes": sorted(set(scopes)), "challenge": challenge}


def evaluate(policy: dict, token: dict, tool: str, *, approved: bool = True, now: Optional[float] = None) -> dict:
    """The verdict for one tool: ``{"decision", "reason", "rule_ids", "scopes", "challenge"}``.

    ``decision`` is allowed / hidden / needs_scope; ``reason`` one of the REASON_* values; ``rule_ids`` the rules
    that decided it (deny: every matching deny naming the tool; only: every matching "only" rule that leaves it
    out); ``scopes`` the tool's scopes and ``challenge`` the one to ask for (needs_scope only)."""
    if not approved:
        return _verdict(HIDDEN, REASON_NOT_APPROVED)

    rules = [r for r in (policy.get("rules") or []) if isinstance(r, dict) and _active(r, now)
             and subject_matches(r.get("subject"), token)]

    denying = []
    for rule in rules:
        effect = rule.get("effect")
        if effect == "deny" and _names_tool(rule, tool):
            denying.append(rule.get("id"))
        elif effect not in _KNOWN_EFFECTS and (not _names(rule) or _names_tool(rule, tool)):
            denying.append(rule.get("id"))
    if denying:
        return _verdict(HIDDEN, REASON_DENIED, rule_ids=denying)

    outside = [r.get("id") for r in rules if r.get("effect") == "only" and not _names_tool(r, tool)]
    if outside:
        return _verdict(HIDDEN, REASON_OUTSIDE_ONLY, rule_ids=outside)

    entry = (policy.get("tool_scopes") or {}).get(tool) or {}
    any_of = sorted({s for s in (entry.get("any_of") or []) if isinstance(s, str) and s})
    if any_of:
        if _scopes_of(token) & set(any_of):
            return _verdict(ALLOWED, REASON_OK, scopes=any_of)
        challenge = entry.get("challenge")
        if challenge not in any_of:
            challenge = any_of[0]
        return _verdict(NEEDS_SCOPE, REASON_MISSING_SCOPE, scopes=any_of, challenge=challenge)
    if policy.get("unscoped_tools") == "require":
        return _verdict(HIDDEN, REASON_UNSCOPED)
    return _verdict(ALLOWED, REASON_OK)


def expand_groups(rules: list, members: dict) -> list:
    """Replace every group rule by one rule per member (subject kind "user", id = the member's sub), keeping the
    rule's id so a verdict still points at the stored rule. ``members`` maps a group id to its members' subs; a
    group with no members (or unknown) yields no rule. Other rules pass through unchanged. Output order: input
    order, members sorted."""
    out = []
    for rule in rules:
        subject = rule.get("subject") or {}
        if subject.get("kind") != "group":
            out.append(rule)
            continue
        for sub in sorted(set(members.get(subject.get("id"), ()))):
            out.append({**rule, "subject": {"kind": "user", "id": sub}})
    return out
