"""Tool policy feed and tool reports for MCP servers that enforce tool approvals themselves (#33).

Beside the revocation feed, and authenticated the same way (a console-registered confidential client bound to one
server as its resource server), a server's pinning middleware (``MCPGateToolPinning`` in
examples/mcp_gate_hooks.py):

* polls ``POST /oauth/policy`` for the approval state of its own tool definitions, by hash (see
  src/tool_pinning/hashing.py), and lists / runs only the approved ones;
* sends ``POST /oauth/tool-report`` with the definitions it lists that MCP Gate has not seen yet, so they show up
  as pending in the console at once instead of at the next refresh or scan.

Both only ever touch the caller's own server (the service whose audience the client is bound to).
"""

from __future__ import annotations

import hashlib
import json
import threading
from typing import Optional

from sqlalchemy.orm import Session

from db.models import TOOL_STATE_APPROVED, TOOL_STATE_PENDING, TOOL_STATE_REJECTED, OAuthClient
from src.adapters import MCPToolAdapter, OAuthClientAdapter, ServiceAdapter
from src.adapters.managed_adapter import check_reported_tool
from src.audit import ActorType, AuditAction, AuditService, AuditStatus, ResourceType
from src.logging import get_logger
from src.middleware.rate_limiter import SlidingWindowCounter
from src.oauth.errors import OAuthError
from src.oauth.service import feed_status, local_now, resource_server_audience
from src.tool_pinning.hashing import HASH_VERSION

logger = get_logger("oauth.policy")

# Version of the feed's response shape (not of the hash: that is hash_version)
POLICY_FORMAT = 1

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


def policy_feed(db: Session, *, caller: OAuthClient, etag: Optional[str] = None) -> dict:
    """The tool policy of the caller's server.

    ``tools`` lists definition hashes by state: ``approved`` (list and run them), ``pending`` and ``rejected``
    (hide them; already known, so there is no need to report them). Any other hash is unknown: hide it and report
    it. ``rules`` is reserved for 1.6's tool-level policy (allow / deny per token or client) and is empty in this
    version; a middleware must ignore fields it does not know.

    ``etag`` is a digest of everything but ``now``: when the caller sends the one it holds and nothing changed,
    the answer is only ``{"unchanged": true, "etag", "now"}``. When no active server has the caller's audience any
    more (it was deleted or disabled), every list is empty, so the middleware hides every tool.
    """
    audience = _caller_audience(caller, "read the tool policy feed")
    OAuthClientAdapter.mark_policy_polled(db, caller)
    service = ServiceAdapter.get_by_audience(db, audience)
    body = {
        "format": POLICY_FORMAT,
        "hash_version": HASH_VERSION,
        "audience": audience,
        "service_id": str(service.id) if service is not None else None,
        "tools": _states(db, service),
        "rules": [],
    }
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


def policy_feed_status(db: Session, audience: Optional[str]) -> dict:
    """Does the server with this audience enforce tool approvals? The same states as the revocation feed's
    (active / stale / never_polled / not_wired), from when its resource servers last read the policy feed."""
    return feed_status(db, audience, "policy_polled_at")
