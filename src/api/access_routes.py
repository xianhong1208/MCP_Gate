"""Tool access API (#37): tools in scopes (bundles), per-subject deny / "only" rules, groups of users.

Console session required (any signed-in account: MCP Gate is single tenant, every account is an admin); writes are
audited and go through the same CSRF origin check as the rest of /api. The evaluator these rows feed is
src/tool_policy/evaluate.py; servers receive the result through the policy feed (1.6 PR 2).
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from db import get_db
from db.models import (
    SUBJECT_CLIENT, SUBJECT_GROUP, SUBJECT_PAT, SUBJECT_USER, AdminUser, ToolAccessRule, UserGroup, utc_now,
)
from src.adapters import (
    AdminUserAdapter, MCPToolAdapter, OAuthClientAdapter, OAuthTokenAdapter, ServiceAdapter, ToolAccessAdapter,
    UserGroupAdapter,
)
from src.adapters.exceptions import AdapterError
from src.audit import ActorType, AuditAction, AuditService, AuditStatus, ResourceType
from src.identity import get_current_user
from src.oauth import service as oauth
from src.tool_policy.evaluate import RULES_VERSION
from src.tool_policy.policy import challenge_scope
from src.tool_policy.validation import (
    MAX_RULES_BYTES_PER_SERVICE, MAX_RULES_PER_SERVICE, MAX_SCOPES_PER_TOOL, MAX_TOOLS_PER_RULE, is_scope_token,
)
from src.utils.field_limits import FieldTooLongError, check_max_length, column_limit

router = APIRouter(tags=["Tool access"])


def _adapter_exc(e: AdapterError) -> HTTPException:
    return HTTPException(status_code=e.status_code, detail=e.to_detail())


def _checked_length(field: str, value: Optional[str], limit: int) -> Optional[str]:
    try:
        return check_max_length(field, value, limit)
    except FieldTooLongError as e:
        raise HTTPException(status_code=400, detail=e.to_detail())


def _audit(db, request, user, action, resource_type, resource_id, details=None):
    AuditService.log_from_request(
        db=db, request=request, action=action, resource_type=resource_type, status=AuditStatus.SUCCESS,
        actor_type=ActorType.ADMIN, actor_id=str(user.id), actor_name=user.audit_name,
        resource_id=resource_id, details=details,
    )


def _service(db, service_id):
    try:
        return ServiceAdapter.get_existing(db, service_id)
    except AdapterError as e:
        raise _adapter_exc(e)


def _subject_label(db, kind: str, subject_id: str) -> Optional[str]:
    """How the console names a rule's subject: a PAT's label, a client's name, a user's email, a group's name."""
    if kind == SUBJECT_PAT:
        token = OAuthTokenAdapter.get(db, subject_id)
        return token.label if token else None
    if kind == SUBJECT_CLIENT:
        client = OAuthClientAdapter.get(db, subject_id)
        return client.client_name if client else None
    if kind == SUBJECT_USER:
        user = AdminUserAdapter.get_by_id(db, subject_id)
        return user.email if user else None
    if kind == SUBJECT_GROUP:
        try:
            return UserGroupAdapter.get_existing(db, subject_id).name
        except AdapterError:
            return None
    return None


def _rule_info(db, rule: ToolAccessRule, now=None) -> dict:
    data = rule.to_dict()
    data["subject"]["label"] = _subject_label(db, rule.subject_kind, rule.subject_id)
    data["expired"] = rule.expires_at is not None and rule.expires_at <= (now or utc_now())
    return data


# ==================== A server's access settings ====================

LIMITS = {"scopes_per_tool": MAX_SCOPES_PER_TOOL, "tools_per_rule": MAX_TOOLS_PER_RULE,
          "rules_per_service": MAX_RULES_PER_SERVICE, "rules_bytes_per_service": MAX_RULES_BYTES_PER_SERVICE}


@router.get("/api/services/{service_id}/access")
def get_service_access(service_id: str, db: Session = Depends(get_db), _: AdminUser = Depends(get_current_user)):
    """Everything that decides who may call this server's tools (#37): the default for tools in no scope, each
    tool's scopes and step-up challenge, the server's rules, the scopes a tool may be put in, and `policy`, the
    exact input of the evaluator (src/tool_policy/evaluate.py) as the server will receive it, groups expanded."""
    service = _service(db, service_id)
    by_tool = ToolAccessAdapter.tool_scopes(db, service)
    sizes = ToolAccessAdapter.scope_sizes(db)
    tools = []
    for tool in MCPToolAdapter.get_by_service(db, str(service.id)):
        rows = by_tool.get(tool.id, [])
        tools.append({"id": str(tool.id), "name": tool.name, "state": tool.state,
                      "removed": tool.removed_at is not None,
                      "scopes": [row.to_dict() for row in rows], "challenge": challenge_scope(rows, sizes)})
    scopes = [dict(s, challenge_safe=is_scope_token(s["name"])) for s in oauth.effective_scopes(db, service)]
    now = utc_now()
    return {
        "service_id": str(service.id), "service_name": service.name, "unscoped_tools": service.unscoped_tools,
        "tools": tools, "rules": [_rule_info(db, r, now) for r in ToolAccessAdapter.list_rules(db, service)],
        "scopes": scopes, "policy": ToolAccessAdapter.build_policy(db, service, now),
        "rules_version": RULES_VERSION, "limits": LIMITS,
    }


class AccessSettingsRequest(BaseModel):
    unscoped_tools: str


@router.put("/api/services/{service_id}/access")
def set_service_access(service_id: str, body: AccessSettingsRequest, request: Request, db: Session = Depends(get_db),
                       user: AdminUser = Depends(get_current_user)):
    """Set what a tool in no scope may do: `allow` (any token for this server may call it; the default) or
    `require` (hidden until it is put in a scope)."""
    service = _service(db, service_id)
    try:
        previous = ToolAccessAdapter.set_unscoped_tools(db, service, body.unscoped_tools)
    except AdapterError as e:
        raise _adapter_exc(e)
    _audit(db, request, user, AuditAction.SERVICE_UNSCOPED_TOOLS_SET, ResourceType.SERVICE, str(service.id),
           {"service": service.name, "before": previous, "after": service.unscoped_tools})
    return {"service_id": str(service.id), "unscoped_tools": service.unscoped_tools, "previous": previous}


# ==================== Tool scopes (bundles) ====================

def _tool_scopes_response(db, service, tool, rows) -> dict:
    return {"service_id": str(service.id), "tool_id": str(tool.id), "tool": tool.name,
            "scopes": [row.to_dict() for row in rows],
            "challenge": challenge_scope(rows, ToolAccessAdapter.scope_sizes(db))}


@router.get("/api/services/{service_id}/tools/{tool_id}/scopes")
def get_tool_scopes(service_id: str, tool_id: str, db: Session = Depends(get_db),
                    _: AdminUser = Depends(get_current_user)):
    """The scopes a tool belongs to and the one its step-up challenge names."""
    service = _service(db, service_id)
    try:
        tool = MCPToolAdapter.get_existing(db, service_id, tool_id)
    except AdapterError as e:
        raise _adapter_exc(e)
    return _tool_scopes_response(db, service, tool, ToolAccessAdapter.tool_scopes(db, service).get(tool.id, []))


class ToolScopesRequest(BaseModel):
    scopes: List[str] = Field(default_factory=list, max_length=MAX_SCOPES_PER_TOOL * 4)
    # The scope a step-up challenge names; null = the narrowest of `scopes`
    challenge: Optional[str] = None


@router.put("/api/services/{service_id}/tools/{tool_id}/scopes")
def set_tool_scopes(service_id: str, tool_id: str, body: ToolScopesRequest, request: Request,
                    db: Session = Depends(get_db), user: AdminUser = Depends(get_current_user)):
    """Replace the scopes a tool belongs to (an empty list takes it out of every scope). Each must be the server's
    own scope or a global scope it may grant, with a name a step-up challenge can carry. A token may call the tool
    when it holds any of them."""
    service = _service(db, service_id)
    try:
        tool, before, rows = ToolAccessAdapter.set_tool_scopes(db, service, tool_id, body.scopes, body.challenge,
                                                               user.audit_name)
    except AdapterError as e:
        raise _adapter_exc(e)
    response = _tool_scopes_response(db, service, tool, rows)
    _audit(db, request, user, AuditAction.TOOL_SCOPE_SET, ResourceType.SERVICE, str(service.id),
           {"tool": tool.name, "tool_id": str(tool.id), "before": sorted(b["scope"] for b in before),
            "after": sorted(r.scope_name for r in rows), "challenge": response["challenge"],
            "challenge_explicit": body.challenge is not None})
    return response


# ==================== Rules ====================

class RuleSubject(BaseModel):
    kind: str = Field(..., max_length=16)
    id: str = Field(..., max_length=512)


class RuleRequest(BaseModel):
    effect: str = Field(..., max_length=16)
    subject: RuleSubject
    tools: List[str] = Field(..., max_length=MAX_TOOLS_PER_RULE * 2)
    note: Optional[str] = None
    # When the rule stops applying (ISO 8601; without a zone it is read as UTC). null = never
    expires_at: Optional[datetime] = None


def _rule_body(body: RuleRequest) -> dict:
    _checked_length("note", (body.note or "").strip() or None, column_limit(ToolAccessRule.note))
    return {"effect": body.effect, "subject_kind": body.subject.kind, "subject_id": body.subject.id,
            "tools": body.tools, "note": body.note, "expires_at": body.expires_at}


def _rule_audit(rule: dict) -> dict:
    return {"effect": rule["effect"], "subject": {"kind": rule["subject"]["kind"], "id": rule["subject"]["id"]},
            "tools": rule["tools"], "expires_at": rule["expires_at"], "note": rule["note"]}


@router.get("/api/services/{service_id}/access-rules")
def list_access_rules(service_id: str, db: Session = Depends(get_db), _: AdminUser = Depends(get_current_user)):
    """The server's deny / "only" rules, expired ones included (marked `expired`; they no longer apply)."""
    service = _service(db, service_id)
    rules = [_rule_info(db, r) for r in ToolAccessAdapter.list_rules(db, service)]
    return {"service_id": str(service.id), "rules": rules, "total": len(rules)}


@router.post("/api/services/{service_id}/access-rules", status_code=201)
def create_access_rule(service_id: str, body: RuleRequest, request: Request, db: Session = Depends(get_db),
                       user: AdminUser = Depends(get_current_user)):
    """Add a rule: `deny` (the subject may never call these tools; `["*"]` = every tool) or `only` (the subject may
    call nothing else). The subject is a personal access token of this server (`pat`, its jti), an OAuth client
    (`client`), a user (`user`, the user id = a token's sub) or a group of users (`group`). Deny wins over only,
    which wins over scopes."""
    service = _service(db, service_id)
    fields = _rule_body(body)
    try:
        rule = ToolAccessAdapter.create_rule(db, service, actor=user.audit_name, **fields)
    except AdapterError as e:
        raise _adapter_exc(e)
    info = _rule_info(db, rule)
    _audit(db, request, user, AuditAction.TOOL_RULE_CREATE, ResourceType.SERVICE, str(service.id),
           {"rule_id": info["id"], "service": service.name, **_rule_audit(info)})
    return info


@router.get("/api/services/{service_id}/access-rules/{rule_id}")
def get_access_rule(service_id: str, rule_id: str, db: Session = Depends(get_db),
                    _: AdminUser = Depends(get_current_user)):
    service = _service(db, service_id)
    try:
        return _rule_info(db, ToolAccessAdapter.get_rule(db, service, rule_id))
    except AdapterError as e:
        raise _adapter_exc(e)


@router.put("/api/services/{service_id}/access-rules/{rule_id}")
def update_access_rule(service_id: str, rule_id: str, body: RuleRequest, request: Request,
                       db: Session = Depends(get_db), user: AdminUser = Depends(get_current_user)):
    """Replace a rule's effect, subject, tools, note and expiry."""
    service = _service(db, service_id)
    fields = _rule_body(body)
    try:
        rule, before = ToolAccessAdapter.update_rule(db, service, rule_id, **fields)
    except AdapterError as e:
        raise _adapter_exc(e)
    info = _rule_info(db, rule)
    _audit(db, request, user, AuditAction.TOOL_RULE_UPDATE, ResourceType.SERVICE, str(service.id),
           {"rule_id": info["id"], "service": service.name, "before": _rule_audit(before),
            "after": _rule_audit(info)})
    return info


@router.delete("/api/services/{service_id}/access-rules/{rule_id}")
def delete_access_rule(service_id: str, rule_id: str, request: Request, db: Session = Depends(get_db),
                       user: AdminUser = Depends(get_current_user)):
    service = _service(db, service_id)
    try:
        before = ToolAccessAdapter.delete_rule(db, service, rule_id)
    except AdapterError as e:
        raise _adapter_exc(e)
    _audit(db, request, user, AuditAction.TOOL_RULE_DELETE, ResourceType.SERVICE, str(service.id),
           {"rule_id": before["id"], "service": service.name, **_rule_audit(before)})
    return {"message": "Access rule deleted", "id": before["id"]}


# ==================== Groups ====================

class GroupCreateRequest(BaseModel):
    name: str = Field(..., max_length=256)
    description: Optional[str] = None


class GroupUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, max_length=256)
    description: Optional[str] = None


def _group_rules(db, group) -> list:
    out = []
    for rule in UserGroupAdapter.rules_using(db, group.id):
        service = ServiceAdapter.get_by_id(db, str(rule.service_id))
        out.append({"id": str(rule.id), "service_id": str(rule.service_id),
                    "service_name": service.name if service else None, "effect": rule.effect,
                    "tools": rule.tool_list()})
    return out


def _group_info(db, group: UserGroup, detail: bool = False) -> dict:
    data = group.to_dict()
    rules = _group_rules(db, group)
    data["rules_count"] = len(rules)
    if detail:
        data["members"] = sorted((m.to_dict() for m in group.members), key=lambda m: (m["email"] or ""))
        data["rules"] = rules
    return data


def _check_description(description: Optional[str]) -> None:
    _checked_length("description", (description or "").strip() or None, column_limit(UserGroup.description))


@router.get("/api/users")
def list_users(db: Session = Depends(get_db), _: AdminUser = Depends(get_current_user)):
    """Console accounts (to pick group members and rule subjects). A token's `sub` is the account's `id`."""
    users = AdminUserAdapter.get_all(db, include_inactive=True)
    return {"users": [u.to_dict() for u in users], "total": len(users)}


@router.get("/api/groups")
def list_groups(db: Session = Depends(get_db), _: AdminUser = Depends(get_current_user)):
    """Groups of users, with member and rule counts."""
    groups = [_group_info(db, g) for g in UserGroupAdapter.list_all(db)]
    return {"groups": groups, "total": len(groups)}


@router.post("/api/groups", status_code=201)
def create_group(body: GroupCreateRequest, request: Request, db: Session = Depends(get_db),
                 user: AdminUser = Depends(get_current_user)):
    """Create a group (name unique, case-insensitive)."""
    _check_description(body.description)
    try:
        group = UserGroupAdapter.create(db, name=body.name, description=body.description, actor=user.audit_name)
    except AdapterError as e:
        raise _adapter_exc(e)
    _audit(db, request, user, AuditAction.GROUP_CREATE, ResourceType.GROUP, str(group.id), {"name": group.name})
    return _group_info(db, group, detail=True)


@router.get("/api/groups/{group_id}")
def get_group(group_id: str, db: Session = Depends(get_db), _: AdminUser = Depends(get_current_user)):
    """A group with its members and the rules that name it."""
    try:
        group = UserGroupAdapter.get_existing(db, group_id)
    except AdapterError as e:
        raise _adapter_exc(e)
    return _group_info(db, group, detail=True)


@router.put("/api/groups/{group_id}")
def update_group(group_id: str, body: GroupUpdateRequest, request: Request, db: Session = Depends(get_db),
                 user: AdminUser = Depends(get_current_user)):
    """Rename a group or change its description (fields not sent are kept)."""
    if "description" in body.model_fields_set:
        _check_description(body.description)
    try:
        group, before = UserGroupAdapter.update(db, group_id, name=body.name, description=body.description,
                                                description_set="description" in body.model_fields_set)
    except AdapterError as e:
        raise _adapter_exc(e)
    _audit(db, request, user, AuditAction.GROUP_UPDATE, ResourceType.GROUP, str(group.id),
           {"before": before, "after": {"name": group.name, "description": group.description}})
    return _group_info(db, group, detail=True)


@router.delete("/api/groups/{group_id}")
def delete_group(group_id: str, request: Request, db: Session = Depends(get_db),
                 user: AdminUser = Depends(get_current_user)):
    """Delete a group. Refused with 409 `groups.in_use` while a rule names it: deleting it would lift its denies."""
    try:
        info = UserGroupAdapter.delete(db, group_id)
    except AdapterError as e:
        raise _adapter_exc(e)
    _audit(db, request, user, AuditAction.GROUP_DELETE, ResourceType.GROUP, group_id, info)
    return {"message": "Group deleted"}


@router.put("/api/groups/{group_id}/members/{user_id}")
def add_group_member(group_id: str, user_id: str, request: Request, db: Session = Depends(get_db),
                     user: AdminUser = Depends(get_current_user)):
    """Add a user to a group (`added: false` when already a member). Rules naming the group reach the user's
    tokens with the next policy-feed poll."""
    try:
        group, member, added = UserGroupAdapter.add_member(db, group_id, user_id, user.audit_name)
    except AdapterError as e:
        raise _adapter_exc(e)
    if added:
        _audit(db, request, user, AuditAction.GROUP_MEMBER_ADD, ResourceType.GROUP, str(group.id),
               {"group": group.name, "user_id": str(member.id), "user": member.email})
    return {"added": added, "group": _group_info(db, group, detail=True)}


@router.delete("/api/groups/{group_id}/members/{user_id}")
def remove_group_member(group_id: str, user_id: str, request: Request, db: Session = Depends(get_db),
                        user: AdminUser = Depends(get_current_user)):
    try:
        group = UserGroupAdapter.remove_member(db, group_id, user_id)
    except AdapterError as e:
        raise _adapter_exc(e)
    member = AdminUserAdapter.get_by_id(db, user_id)
    _audit(db, request, user, AuditAction.GROUP_MEMBER_REMOVE, ResourceType.GROUP, str(group.id),
           {"group": group.name, "user_id": user_id, "user": member.email if member else None})
    return {"group": _group_info(db, group, detail=True)}
