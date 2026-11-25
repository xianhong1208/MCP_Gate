"""Tool policy feed and tool reports for MCP servers that enforce tool approvals themselves (#33).

Beside the revocation feed, and authenticated the same way (a console-registered confidential client bound to one
server as its resource server), a server's pinning middleware (``MCPGateToolPinning`` in
examples/mcp_gate_hooks.py):

* polls ``POST /oauth/policy`` for the approval state of its own tool definitions, by hash (see
  src/tool_pinning/hashing.py), and lists / runs only the approved ones; a middleware that sends
  ``features=rules1`` also gets the server's tool access policy (#37, format 2: tool scopes and deny / "only"
  rules, see src/tool_policy/evaluate.py) and applies it to each token;
* sends ``POST /oauth/tool-report`` with the definitions it lists that MCP Gate has not seen yet, so they show up
  as pending in the console at once instead of at the next refresh or scan.

Both only ever touch the caller's own server (the service whose audience the client is bound to).
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from typing import Optional

from sqlalchemy.orm import Session

from db.models import TOOL_STATE_APPROVED, TOOL_STATE_PENDING, TOOL_STATE_REJECTED, OAuthClient
from src.adapters import MCPToolAdapter, OAuthClientAdapter, ServiceAdapter, ToolAccessAdapter
from src.adapters.managed_adapter import check_reported_tool
from src.audit import ActorType, AuditAction, AuditService, AuditStatus, ResourceType
from src.logging import get_logger
from src.middleware.rate_limiter import SlidingWindowCounter
from src.oauth.errors import OAuthError
from src.oauth.service import feed_status, local_now, resource_server_audience
from src.tool_pinning.hashing import HASH_VERSION
from src.tool_policy.evaluate import RULES_VERSION
from src.tool_policy.validation import MAX_RULES_BYTES_PER_SERVICE, MAX_RULES_PER_SERVICE, rules_size

logger = get_logger("oauth.policy")

# Version of the feed's response shape (not of the hash: that is hash_version). Format 1 (1.5): approvals only, an
# empty ``rules``. Format 2 (1.6): approvals plus the server's tool access policy, sent only to a middleware that
# advertises FEATURE_RULES, so a 1.5 middleware keeps getting exactly what it got before.
POLICY_FORMAT = 1
POLICY_FORMAT_RULES = 2
# What a middleware puts in ``features`` when it enforces the access rules of RULES_VERSION 1
FEATURE_RULES = "rules1"
KNOWN_FEATURES = (FEATURE_RULES,)
# ``features`` as stored on the client (oauth_clients.policy_features is VARCHAR(64)): known-looking tokens only
_FEATURE_TOKEN = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,31}$")
FEATURES_MAX = 64

# A report carries the definitions the server has not seen approved; a whole tool list fits easily
MAX_REPORTED_TOOLS = 200
# Reports per resource-server client per minute. A middleware sends one when it lists definitions MCP Gate does
# not know yet, and retries a failed one on its next sync; more than this is a loop or abuse
REPORTS_PER_MINUTE = 30

_report_window = SlidingWindowCounter(window_size=60)
_report_lock = threading.Lock()


def _caller_audience(caller: OAuthClient, what: str) -> str:
    audience = resource_server_audience(caller)
    if audience is None:
        raise OAuthError("unauthorized_client",
                         f"only a client registered in the console as a server's resource server may {what}", 403)
    return audience


def _states(db: Session, service) -> dict:
    """The hashes of every recorded definition of the service's tools, by approval state. Versions of tools the
    server stopped listing are included: a server that lists such a definition again gets it with its approval."""
    states = {TOOL_STATE_APPROVED: set(), TOOL_STATE_PENDING: set(), TOOL_STATE_REJECTED: set()}
    if service is not None:
        for tool in MCPToolAdapter.get_by_service(db, str(service.id)):
            for version in tool.versions:
                states.setdefault(version.state, set()).add(version.hash)
    return {state: sorted(hashes) for state, hashes in states.items()}


def normalize_features(raw) -> Optional[str]:
    """The ``features`` a middleware sent (space- or comma-separated) as stored: lowercase tokens that look like
    feature names, no duplicates, the ones MCP Gate knows first (so padding cannot push them out), then the rest
    sorted, at most FEATURES_MAX characters in all. None when nothing is left."""
    if not isinstance(raw, str):
        return None
    tokens = sorted({t for t in re.split(r"[\s,]+", raw.strip().lower()) if _FEATURE_TOKEN.match(t)},
                    key=lambda t: (t not in KNOWN_FEATURES, t))
    kept = []
    for token in tokens:
        if len(" ".join(kept + [token])) > FEATURES_MAX:
            break
        kept.append(token)
    return " ".join(kept) or None


def has_feature(features: Optional[str], feature: str) -> bool:
    return bool(features) and feature in features.split()


def _access_policy(db: Session, service) -> dict:
    """The format-2 part of the feed: ToolAccessAdapter.build_policy for the server (unexpired rules, groups
    expanded to their members), or an empty policy when no active server has the caller's audience (every tool
    is hidden then anyway: no approved hash)."""
    if service is None:
        return {"rules_version": RULES_VERSION, "unscoped_tools": "allow", "tool_scopes": {}, "rules": []}
    policy = ToolAccessAdapter.build_policy(db, service)
    rules = policy["rules"]
    if len(rules) > MAX_RULES_PER_SERVICE or rules_size(rules) > MAX_RULES_BYTES_PER_SERVICE:
        # The saves are capped (PR 1); getting here means the caps were bypassed. Send every rule anyway:
        # dropping some would silently lift a deny.
        logger.warning(f"The access rules of {service.name} exceed the per-server limits "
                       f"({len(rules)} rules, {rules_size(rules)} bytes)")
    return policy


def policy_feed(db: Session, *, caller: OAuthClient, etag: Optional[str] = None,
                features: Optional[str] = None) -> dict:
    """The tool policy of the caller's server.

    ``tools`` lists definition hashes by state: ``approved`` (list and run them), ``pending`` and ``rejected``
    (hide them; already known, so there is no need to report them). Any other hash is unknown: hide it and report
    it. A middleware must ignore fields it does not know.

    ``features`` is what the caller's middleware enforces (stored on the client, shown in the console). With
    ``rules1`` the answer is format 2: ``rules_version``, ``unscoped_tools``, ``tool_scopes`` and ``rules`` carry
    the server's tool access policy (the evaluator's input, src/tool_policy/evaluate.py). Without it the answer is
    format 1, unchanged since 1.5: ``rules`` is an empty list.

    ``etag`` is a digest of everything but ``now``: when the caller sends the one it holds and nothing changed,
    the answer is only ``{"unchanged": true, "etag", "now"}``. When no active server has the caller's audience any
    more (it was deleted or disabled), every list is empty, so the middleware hides every tool.
    """
    audience = _caller_audience(caller, "read the tool policy feed")
    features = normalize_features(features)
    OAuthClientAdapter.mark_policy_polled(db, caller, features)
    service = ServiceAdapter.get_by_audience(db, audience)
    rules_wanted = has_feature(features, FEATURE_RULES)
    body = {
        "format": POLICY_FORMAT_RULES if rules_wanted else POLICY_FORMAT,
        "hash_version": HASH_VERSION,
        "audience": audience,
        "service_id": str(service.id) if service is not None else None,
        "tools": _states(db, service),
        "rules": [],
    }
    if rules_wanted:
        body.update(_access_policy(db, service))
    digest = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    now = int(local_now().timestamp())
    if etag and etag == digest:
        return {"unchanged": True, "etag": digest, "now": now}
    return {**body, "unchanged": False, "etag": digest, "now": now}


def _check_report_rate(caller: OAuthClient) -> None:
    with _report_lock:
        if _report_window.get_count(caller.client_id) >= REPORTS_PER_MINUTE:
            raise OAuthError("slow_down", f"at most {REPORTS_PER_MINUTE} tool reports per minute", 429)
        _report_window.add_request(caller.client_id)


def report_tools(db: Session, *, caller: OAuthClient, tools, ip: Optional[str] = None,
                 request_path: Optional[str] = None) -> dict:
    """Record tool definitions the caller's server lists but has not seen approved, as pending versions with
    source "reported" (the same path as a refresh, MCPToolAdapter.record_reported).

    ``tools`` is a list of tool objects as tools/list returns them (MCP field names). MCP Gate computes every hash
    itself; a ``hash`` field sent along is only compared (``hash_mismatch`` names the tools where the server's own
    hash differs, which means its canonicalisation disagrees with MCP Gate's). Invalid entries are listed under
    ``invalid`` with a reason and not stored; the valid ones are. Each recorded tool comes back with its state.
    """
    audience = _caller_audience(caller, "report tools")
    if not isinstance(tools, list):
        raise OAuthError("invalid_request", "tools must be an array")
    if len(tools) > MAX_REPORTED_TOOLS:
        raise OAuthError("invalid_request", f"at most {MAX_REPORTED_TOOLS} tools per report")
    _check_report_rate(caller)
    service = ServiceAdapter.get_by_audience(db, audience)
    if service is None:
        raise OAuthError("invalid_target", "no active server has this resource server's audience", 404)

    valid, invalid, mismatch, seen = [], [], [], set()
    for index, tool in enumerate(tools):
        digest, reason = check_reported_tool(tool)
        name = tool.get("name") if isinstance(tool, dict) and isinstance(tool.get("name"), str) else None
        if reason is None and name in seen:
            reason = "duplicate_name"
        if reason is not None:
            invalid.append({"index": index, "name": name[:128] if name else None, "reason": reason})
            continue
        seen.add(name)
        claimed = tool.get("hash")
        if claimed is not None and claimed != digest:
            mismatch.append(name)
        valid.append(tool)  # "hash" is not a hashed field: neither the pin nor the stored definition includes it

    recorded = MCPToolAdapter.record_reported(db, str(service.id), valid) if valid else []
    new = [(t, v) for t, v, created in recorded if created]
    if new:
        _audit_report(db, caller, service, new, ip, request_path)
    return {
        "service_id": str(service.id),
        "hash_version": HASH_VERSION,
        "recorded": [{"name": t.name, "hash": v.hash, "state": v.state, "new": created}
                     for t, v, created in recorded],
        "invalid": invalid,
        "hash_mismatch": mismatch,
    }


def _audit_report(db: Session, caller: OAuthClient, service, new, ip, request_path) -> None:
    """One audit entry per report that brought definitions MCP Gate did not know (actor: the resource server).
    Never raises: the versions are already committed."""
    try:
        AuditService.log(
            db=db, action=AuditAction.TOOL_REPORT, resource_type=ResourceType.SERVICE, status=AuditStatus.SUCCESS,
            resource_id=str(service.id), actor_type=ActorType.API, actor_id=caller.client_id,
            actor_name=caller.client_name, ip_address=ip, request_path=request_path,
            request_method="POST" if request_path else None,
            details={"service_name": service.name, "source": "reported",
                     "tools": [{"name": t.name, "hash": v.hash, "state": v.state} for t, v in new]},
        )
    except Exception as e:  # pragma: no cover - defensive
        db.rollback()
        logger.error(f"Failed to audit a tool report for {service.name}: {e}")


def policy_feed_status(db: Session, audience: Optional[str], service=None) -> dict:
    """Does the server with this audience enforce tool approvals? The same states as the revocation feed's
    (active / stale / never_polled / not_wired), from when its resource servers last read the policy feed.

    ``rules_enforced`` (#37) says whether it also enforces tool access rules: true when every resource server that
    has read the feed advertised ``rules1`` on its last poll, false when one did not (a 1.5 middleware lists and
    runs every approved tool whatever the rules say), null when none has read it. ``has_access_policy`` is true
    when the server has something to enforce (a rule, a scoped tool, or "require a scope"), so the console can
    tell a harmless gap from rules that are silently not applied. Each resource server lists its ``features``."""
    status = feed_status(db, audience, "policy_polled_at")
    aud = status["audience"]
    clients = {c.client_id: c for c in (OAuthClientAdapter.list_resource_servers(db, aud) if aud else [])}
    polled = []
    for entry in status["resource_servers"]:
        client = clients.get(entry["client_id"])
        features = client.policy_features if client is not None else None
        entry["features"] = features.split() if features else []
        if client is not None and client.policy_polled_at is not None:
            polled.append(has_feature(features, FEATURE_RULES))
    status["rules_enforced"] = all(polled) if polled else None
    if service is None and aud:
        service = ServiceAdapter.get_by_audience(db, aud)
    if service is None:
        status["has_access_policy"] = False
    else:
        policy = ToolAccessAdapter.build_policy(db, service)
        status["has_access_policy"] = bool(policy["rules"] or policy["tool_scopes"]
                                           or policy["unscoped_tools"] != "allow")
    return status
