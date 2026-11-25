"""Tool access adapter (#37): tools in scopes, deny / "only" rules, groups of users, and the policy built from them.

Business rules (what may be assigned, which subjects exist, the per-server limits) live here; db.crud only stores.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Optional

from db.crud import (
    AdminUserCRUD, MCPToolCRUD, OAuthClientCRUD, OAuthScopeCRUD, OAuthTokenCRUD, ServiceScopeCRUD,
    ToolAccessRuleCRUD, ToolScopeCRUD, UserGroupCRUD, normalize_audience,
)
from db.models import (
    RULE_EFFECTS, RULE_ONLY, SUBJECT_CLIENT, SUBJECT_GROUP, SUBJECT_KINDS, SUBJECT_PAT, SUBJECT_USER,
    UNSCOPED_MODES, utc_now,
)
from src.adapters.exceptions import ConflictError, NotFoundError, ValidationFailedError
from src.tool_policy.evaluate import ALL_TOOLS, RULES_VERSION, expand_groups
from src.tool_policy.policy import challenge_scope, is_expired, rule_entry
from src.tool_policy.validation import (
    GROUP_NAME_MAX, MAX_RULES_BYTES_PER_SERVICE, MAX_RULES_PER_SERVICE, MAX_SCOPES_PER_TOOL, MAX_TOOLS_PER_RULE,
    has_control_chars, is_scope_token, rules_size,
)


def _uuid_str(value) -> Optional[str]:
    try:
        return str(uuid.UUID(str(value)))
    except (TypeError, ValueError):
        return None


def to_utc_naive(value: Optional[datetime]) -> Optional[datetime]:
    """An API datetime -> naive UTC (a naive value is taken as UTC)."""
    if value is None:
        return None
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


class ToolAccessAdapter:
    """Tool scopes, access rules and the policy a server enforces."""

    # ---- tool scopes ------------------------------------------------------------------------------------------
    @staticmethod
    def resolve_scope_for_service(db, service, name: str) -> tuple:
        """(name, scope_service_id or None) of a scope a tool of ``service`` may belong to: the server's own scope,
        or a global scope the server may grant (Service.oauth_scopes restricts global scopes when set)."""
        if not is_scope_token(name):
            raise ValidationFailedError(code="access.scope_name_unsafe", params={"scope": str(name)[:128]},
                                        fallback=f"Scope {name!r} has characters a step-up challenge cannot carry "
                                                 "(allowed: printable ASCII except space, '\"' and '\\')")
        if ServiceScopeCRUD.get(db, service.id, name) is not None:
            return name, str(service.id)
        if OAuthScopeCRUD.get(db, name) is not None:
            if service.oauth_scopes and name not in service.oauth_scopes.split():
                raise ValidationFailedError(code="access.scope_not_permitted", params={"scope": name},
                                            fallback=f"Scope '{name}' is not one this server may grant "
                                                     "(see the server's allowed scopes)")
            return name, None
        raise ValidationFailedError(code="access.unknown_scope", params={"scope": name},
                                    fallback=f"No scope '{name}' exists for this server")

    @classmethod
    def set_tool_scopes(cls, db, service, tool_id, names: list, challenge: Optional[str], actor: str):
        """Replace a tool's scopes. Returns (tool, scopes before, rows after)."""
        tool = MCPToolCRUD.get_in_service(db, str(service.id), tool_id)
        if tool is None:
            raise NotFoundError(code="tools.not_found", fallback="Tool not found on this service")
        wanted = list(dict.fromkeys(n.strip() for n in names if isinstance(n, str) and n.strip()))
        if len(wanted) > MAX_SCOPES_PER_TOOL:
            raise ValidationFailedError(code="access.too_many_scopes", params={"max": MAX_SCOPES_PER_TOOL},
                                        fallback=f"A tool may belong to at most {MAX_SCOPES_PER_TOOL} scopes")
        entries = [cls.resolve_scope_for_service(db, service, name) for name in wanted]
        if challenge is not None and challenge not in wanted:
            raise ValidationFailedError(code="access.challenge_not_in_scopes", params={"scope": challenge[:128]},
                                        fallback="The challenge scope must be one of the tool's scopes")
        before = [row.to_dict() for row in ToolScopeCRUD.list_for_tool(db, tool.id)]
        rows = ToolScopeCRUD.replace_for_tool(db, tool.id, entries, challenge, actor)
        return tool, before, rows

    @staticmethod
    def tool_scopes(db, service) -> dict:
        """{tool id: [ToolScope rows]} for a server."""
        out: dict = {}
        for row in ToolScopeCRUD.list_for_service(db, service.id):
            out.setdefault(row.tool_id, []).append(row)
        return out

    @staticmethod
    def scope_sizes(db) -> dict:
        return ToolScopeCRUD.scope_sizes(db)

    @staticmethod
    def approved_memberships(db, service) -> list:
        """(scope, tool name, tool title, since) for the approved, listed tools of a server that are in a scope."""
        return ToolScopeCRUD.approved_memberships(db, service.id)

    @staticmethod
    def tools_in_scope(db, name, scope_service_id=None):
        return ToolScopeCRUD.tools_in_scope(db, name, scope_service_id)

    @staticmethod
    def set_unscoped_tools(db, service, mode: str) -> str:
        """Set the server's default for tools in no scope. Returns the previous value."""
        if mode not in UNSCOPED_MODES:
            raise ValidationFailedError(code="access.invalid_unscoped_tools", params={"allowed": list(UNSCOPED_MODES)},
                                        fallback="unscoped_tools must be 'allow' or 'require'")
        previous = service.unscoped_tools
        service.unscoped_tools = mode
        db.commit()
        db.refresh(service)
        return previous

    # ---- rules ------------------------------------------------------------------------------------------------
    @staticmethod
    def list_rules(db, service):
        return ToolAccessRuleCRUD.list_for_service(db, service.id)

    @staticmethod
    def get_rule(db, service, rule_id):
        rule = ToolAccessRuleCRUD.get_in_service(db, service.id, rule_id)
        if rule is None:
            raise NotFoundError(code="access.rule_not_found", fallback="Access rule not found on this service")
        return rule

    @staticmethod
    def _subject(db, service, kind: str, subject_id: str) -> str:
        """Check the subject exists (and, for a personal access token, that it was issued for this server); return
        the id as stored (user and group ids in canonical UUID form)."""
        if kind not in SUBJECT_KINDS:
            raise ValidationFailedError(code="access.invalid_subject_kind", params={"allowed": list(SUBJECT_KINDS)},
                                        fallback="subject.kind must be pat, client, user or group")
        subject_id = (subject_id or "").strip()
        missing = ValidationFailedError(code="access.subject_not_found", params={"kind": kind},
                                        fallback=f"No {kind} with this id")
        if not subject_id:
            raise missing
        if kind == SUBJECT_PAT:
            token = OAuthTokenCRUD.get(db, subject_id)
            if token is None or token.kind != "pat":
                raise missing
            if normalize_audience(token.audience or "") != normalize_audience(service.effective_audience or ""):
                raise ValidationFailedError(code="access.pat_other_service",
                                            fallback="This personal access token was issued for another server")
            return subject_id
        if kind == SUBJECT_CLIENT:
            if OAuthClientCRUD.get(db, subject_id) is None:
                raise missing
            return subject_id
        canonical = _uuid_str(subject_id)
        if canonical is None:
            raise missing
        if kind == SUBJECT_USER and AdminUserCRUD.get_by_id(db, canonical) is None:
            raise missing
        if kind == SUBJECT_GROUP and UserGroupCRUD.get(db, canonical) is None:
            raise missing
        return canonical

    @staticmethod
    def _tools(db, service, effect: str, tools) -> list:
        names = list(dict.fromkeys(t.strip() for t in (tools or []) if isinstance(t, str) and t.strip()))
        if not names:
            raise ValidationFailedError(code="access.no_tools", fallback="A rule must name at least one tool, or '*'")
        if len(names) > MAX_TOOLS_PER_RULE:
            raise ValidationFailedError(code="access.too_many_tools", params={"max": MAX_TOOLS_PER_RULE},
                                        fallback=f"A rule may name at most {MAX_TOOLS_PER_RULE} tools")
        if ALL_TOOLS in names:
            if len(names) > 1:
                raise ValidationFailedError(code="access.wildcard_not_alone",
                                            fallback="'*' (every tool) cannot be combined with tool names")
            if effect == RULE_ONLY:
                raise ValidationFailedError(code="access.only_all_tools",
                                            fallback="An 'only' rule for every tool restricts nothing")
            return names
        known = {t.name for t in MCPToolCRUD.get_by_service(db, str(service.id))}
        for name in names:
            if name not in known:
                raise ValidationFailedError(code="access.unknown_tool", params={"tool": name[:128]},
                                            fallback=f"This server has no tool '{name}'")
        return names

    @classmethod
    def _rule_fields(cls, db, service, *, effect, subject_kind, subject_id, tools, note, expires_at) -> dict:
        if effect not in RULE_EFFECTS:
            raise ValidationFailedError(code="access.invalid_effect", params={"allowed": list(RULE_EFFECTS)},
                                        fallback="effect must be 'deny' or 'only'")
        expires = to_utc_naive(expires_at)
        if expires is not None and expires <= utc_now():
            raise ValidationFailedError(code="access.expires_in_past", fallback="expires_at must be in the future")
        return {
            "effect": effect,
            "subject_kind": subject_kind,
            "subject_id": cls._subject(db, service, subject_kind, subject_id),
            "tools": cls._json(cls._tools(db, service, effect, tools)),
            "note": (note or "").strip() or None,
            "expires_at": expires,
        }

    @staticmethod
    def _json(names: list) -> str:
        return json.dumps(names, ensure_ascii=False)

    @classmethod
    def check_limits(cls, db, service, *, replace_rule_id=None, extra_rule: Optional[dict] = None,
                     extra_member: Optional[tuple] = None) -> None:
        """Refuse a change that would make the rules this server receives (after group expansion) exceed the
        per-server limits. ``extra_rule`` is a rule entry being added or replacing ``replace_rule_id``;
        ``extra_member`` = (group id, user id) about to join a group."""
        now = utc_now()
        entries = [rule_entry(r) for r in ToolAccessRuleCRUD.list_for_service(db, service.id)
                   if str(r.id) != str(replace_rule_id) and not is_expired(r, now)]
        if extra_rule is not None:
            entries.append(extra_rule)
        groups = {e["subject"]["id"] for e in entries if e["subject"]["kind"] == SUBJECT_GROUP}
        members = UserGroupCRUD.members_by_group(db, groups) if groups else {}
        if extra_member is not None:
            members.setdefault(extra_member[0], []).append(extra_member[1])
        expanded = expand_groups(entries, members)
        if len(expanded) > MAX_RULES_PER_SERVICE:
            raise ConflictError(code="access.rules_limit", params={"max": MAX_RULES_PER_SERVICE},
                                fallback=f"A server may receive at most {MAX_RULES_PER_SERVICE} rules "
                                         "(group rules count once per member)")
        size = rules_size(expanded)
        if size > MAX_RULES_BYTES_PER_SERVICE:
            raise ConflictError(code="access.rules_too_large", params={"max_bytes": MAX_RULES_BYTES_PER_SERVICE},
                                fallback=f"The rules of a server may take at most {MAX_RULES_BYTES_PER_SERVICE} "
                                         "bytes (group rules count once per member)")

    @classmethod
    def create_rule(cls, db, service, *, actor: str, **body):
        fields = cls._rule_fields(db, service, **body)
        probe = rule_entry(_Probe(id="new", **fields))
        cls.check_limits(db, service, extra_rule=probe)
        return ToolAccessRuleCRUD.create(db, service_id=service.id, created_by=actor, **fields)

    @classmethod
    def update_rule(cls, db, service, rule_id, **body):
        """Replace a rule's content. Returns (rule, before dict)."""
        rule = cls.get_rule(db, service, rule_id)
        before = rule.to_dict()
        fields = cls._rule_fields(db, service, **body)
        cls.check_limits(db, service, replace_rule_id=rule.id, extra_rule=rule_entry(_Probe(id=rule.id, **fields)))
        return ToolAccessRuleCRUD.update(db, rule, **fields), before

    @classmethod
    def delete_rule(cls, db, service, rule_id) -> dict:
        rule = cls.get_rule(db, service, rule_id)
        before = rule.to_dict()
        ToolAccessRuleCRUD.delete(db, rule)
        return before

    # ---- the policy ---------------------------------------------------------------------------------------------
    @staticmethod
    def build_policy(db, service, now: Optional[datetime] = None) -> dict:
        """The evaluator's input for one server (src/tool_policy/evaluate.py): its unscoped-tools default, each
        scoped tool's scopes and challenge, and its unexpired rules with groups expanded to their members' subs."""
        now = now or utc_now()
        names = {t.id: t.name for t in MCPToolCRUD.get_by_service(db, str(service.id))}
        sizes = ToolScopeCRUD.scope_sizes(db)
        by_tool: dict = {}
        for row in ToolScopeCRUD.list_for_service(db, service.id):
            by_tool.setdefault(row.tool_id, []).append(row)
        tool_scopes = {}
        for tool_id, rows in by_tool.items():
            if tool_id in names:
                tool_scopes[names[tool_id]] = {"any_of": sorted(r.scope_name for r in rows),
                                               "challenge": challenge_scope(rows, sizes)}
        entries = [rule_entry(r) for r in ToolAccessRuleCRUD.list_for_service(db, service.id)
                   if not is_expired(r, now)]
        groups = {e["subject"]["id"] for e in entries if e["subject"]["kind"] == SUBJECT_GROUP}
        members = UserGroupCRUD.members_by_group(db, groups) if groups else {}
        return {
            "rules_version": RULES_VERSION,
            "unscoped_tools": service.unscoped_tools,
            "tool_scopes": dict(sorted(tool_scopes.items())),
            "rules": expand_groups(entries, members),
        }


class _Probe:
    """A not-yet-stored rule, shaped like ToolAccessRule for rule_entry()."""

    def __init__(self, id, effect, subject_kind, subject_id, tools, expires_at, **_):
        self.id = id
        self.effect = effect
        self.subject_kind = subject_kind
        self.subject_id = subject_id
        self._tools = json.loads(tools)
        self.expires_at = expires_at

    def tool_list(self):
        return self._tools


class UserGroupAdapter:
    """Groups of console users (#37)."""

    @staticmethod
    def list_all(db):
        return UserGroupCRUD.list_all(db)

    @staticmethod
    def get_existing(db, group_id):
        group = UserGroupCRUD.get(db, group_id)
        if group is None:
            raise NotFoundError(code="groups.not_found", fallback="Group not found")
        return group

    @staticmethod
    def _name(name) -> str:
        name = (name or "").strip()
        if not name or len(name) > GROUP_NAME_MAX or has_control_chars(name):
            raise ValidationFailedError(code="groups.invalid_name", params={"max": GROUP_NAME_MAX},
                                        fallback=f"A group name is 1 to {GROUP_NAME_MAX} printable characters")
        return name

    @classmethod
    def create(cls, db, *, name, description, actor):
        name = cls._name(name)
        if UserGroupCRUD.get_by_name(db, name) is not None:
            raise ConflictError(code="groups.name_taken", fallback="A group with this name exists")
        try:
            return UserGroupCRUD.create(db, name=name, description=(description or "").strip() or None, actor=actor)
        except ValueError:
            raise ConflictError(code="groups.name_taken", fallback="A group with this name exists")

    @classmethod
    def update(cls, db, group_id, *, name=None, description=None, description_set=False):
        """Rename and / or describe a group. Returns (group, before dict)."""
        group = cls.get_existing(db, group_id)
        before = {"name": group.name, "description": group.description}
        fields = {}
        if name is not None:
            name = cls._name(name)
            other = UserGroupCRUD.get_by_name(db, name)
            if other is not None and other.id != group.id:
                raise ConflictError(code="groups.name_taken", fallback="A group with this name exists")
            fields["name"] = name
        if description_set:
            fields["description"] = (description or "").strip() or None
        try:
            return UserGroupCRUD.update(db, group, **fields), before
        except ValueError:
            raise ConflictError(code="groups.name_taken", fallback="A group with this name exists")

    @staticmethod
    def rules_using(db, group_id):
        return ToolAccessRuleCRUD.list_for_subject(db, SUBJECT_GROUP, str(group_id))

    @classmethod
    def delete(cls, db, group_id) -> dict:
        """Delete a group no rule names (deleting one that is would silently lift its denies)."""
        group = cls.get_existing(db, group_id)
        using = cls.rules_using(db, group.id)
        if using:
            raise ConflictError(code="groups.in_use", params={"rules": len(using)},
                                fallback=f"{len(using)} access rule(s) name this group; delete them first")
        info = {"name": group.name, "members": len(group.members)}
        UserGroupCRUD.delete(db, group)
        return info

    @classmethod
    def add_member(cls, db, group_id, user_id, actor) -> tuple:
        """Returns (group, user, added: False when already a member)."""
        group = cls.get_existing(db, group_id)
        canonical = _uuid_str(user_id)
        user = AdminUserCRUD.get_by_id(db, canonical) if canonical else None
        if user is None:
            raise NotFoundError(code="auth.user_not_found", fallback="User not found")
        if any(m.user_id == user.id for m in group.members):
            return group, user, False
        # every server with a rule naming this group receives one more rule per such rule
        from src.adapters.service_adapter import ServiceAdapter
        for service_id in sorted({str(r.service_id) for r in cls.rules_using(db, group.id)}):
            service = ServiceAdapter.get_by_id(db, service_id)
            if service is not None:
                ToolAccessAdapter.check_limits(db, service, extra_member=(str(group.id), str(user.id)))
        added = UserGroupCRUD.add_member(db, group, user.id, actor)
        return cls.get_existing(db, group.id), user, added

    @classmethod
    def remove_member(cls, db, group_id, user_id):
        group = cls.get_existing(db, group_id)
        canonical = _uuid_str(user_id)
        if canonical is None or not UserGroupCRUD.remove_member(db, group, canonical):
            raise NotFoundError(code="groups.member_not_found", fallback="This user is not a member of the group")
        return cls.get_existing(db, group.id)

    @staticmethod
    def members_by_group(db, group_ids=None) -> dict:
        return UserGroupCRUD.members_by_group(db, group_ids)
