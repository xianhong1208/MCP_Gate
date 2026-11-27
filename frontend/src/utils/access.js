/**
 * Tool access (#37) helpers for the console, pure so they can be tested without React.
 *
 * Input shapes are the API's: GET /api/services/{id}/access answers
 *   { unscoped_tools, tools: [{ id, name, state, removed, scopes: [{ scope, source, challenge }], challenge }],
 *     rules: [{ id, effect, subject: { kind, id, label }, tools, note, expires_at, expired }],
 *     scopes: [{ name, title, description, is_default, source, challenge_safe }] }
 * A bundle is a scope: the tools in it are the ones a token holding that scope may call.
 */
import { accessRulesState } from './revocation.js'

export const RULE_EFFECTS = ['deny', 'only']
export const SUBJECT_KINDS = ['pat', 'client', 'user', 'group']
export const ALL_TOOLS = '*'
// Every personal access token is issued through this built-in client: a rule on it would hit all of them
export const CONSOLE_CLIENT_ID = 'mcp-gate-console'

/** RFC 6749 scope-token: printable ASCII without space, '"' or '\\' (it may go into WWW-Authenticate: Bearer scope="…") */
export function isScopeToken(name) {
  return /^[\x21\x23-\x5B\x5D-\x7E]+$/.test(name || '')
}

/** The scope a tool's step-up challenge was explicitly set to, or null (= the narrowest one, chosen by MCP Gate) */
export function explicitChallenge(tool) {
  const row = (tool?.scopes || []).find((s) => s.challenge)
  return row ? row.scope : null
}

/** The names of the scopes (bundles) a tool is in */
export function toolScopeNames(tool) {
  return (tool?.scopes || []).map((s) => s.scope)
}

/**
 * The server's bundles: every scope a token for it may carry, with the tools of this server in it. Scopes that hold
 * tools come first, then the server's own scopes (empty bundles waiting for tools), then the rest; by name within.
 */
export function bundlesFromAccess(access) {
  const tools = (access?.tools || []).filter((tl) => !tl.removed)
  return (access?.scopes || []).map((s) => ({
    ...s,
    tools: tools.filter((tl) => toolScopeNames(tl).includes(s.name)).map((tl) => tl.name).sort(),
  })).sort((a, b) => rank(a) - rank(b) || a.name.localeCompare(b.name))
}

function rank(bundle) {
  if (bundle.tools.length > 0) return 0
  return bundle.source === 'service' ? 1 : 2
}

/** Scopes a tool may be put in: the ones a step-up challenge can carry */
export function assignableScopes(access) {
  return (access?.scopes || []).filter((s) => s.challenge_safe)
}

/**
 * The body of PUT /api/services/{id}/tools/{tool_id}/scopes for a tool whose scopes become `scopes`: the explicit
 * challenge is kept while it is still one of them, otherwise MCP Gate picks the narrowest again (null).
 */
export function toolScopesBody(tool, scopes, challenge = explicitChallenge(tool)) {
  const list = [...new Set(scopes)]
  return { scopes: list, challenge: challenge && list.includes(challenge) ? challenge : null }
}

/**
 * Assigning tools to a bundle from the bundle's side: which tools change and the body each gets. `selected` is the
 * set of tool ids that should be in `scope` afterwards; every other tool of the server leaves it. Tools whose
 * membership does not change are not sent.
 */
export function bundleChanges(access, scope, selected) {
  const want = new Set(selected)
  const changes = []
  for (const tool of access?.tools || []) {
    const names = toolScopeNames(tool)
    const has = names.includes(scope)
    if (has === want.has(tool.id)) continue
    const next = has ? names.filter((n) => n !== scope) : [...names, scope]
    changes.push({ toolId: tool.id, tool: tool.name, body: toolScopesBody(tool, next) })
  }
  return changes
}

/**
 * Bundles to offer in the approval card's "add to bundle" picker: scopes a tool may be put in that are used as
 * bundles here (the server's own, or a global one with a title or with tools of this server), not every scope a
 * token may carry (mcp:tools:invoke and the like would only add noise).
 */
export function bundleChoices(access) {
  return bundlesFromAccess(access).filter((b) => b.challenge_safe && (b.source === 'service' || b.title || b.tools.length > 0))
}

/** The approval-card shortcut: the tool's scopes plus `scope`, or null when it is already in it (or none chosen) */
export function addToBundleBody(tool, scope) {
  if (!scope || toolScopeNames(tool).includes(scope)) return null
  return toolScopesBody(tool, [...toolScopeNames(tool), scope])
}

/** Rules that name a tool (or every tool) */
export function rulesForTool(rules, toolName) {
  return (rules || []).filter((r) => r.tools.includes(toolName) || r.tools.includes(ALL_TOOLS))
}

/** `datetime-local` value (local time, no zone) to an ISO UTC string; '' -> null */
export function localToIso(value) {
  if (!value) return null
  const d = new Date(value)
  return Number.isNaN(d.getTime()) ? null : d.toISOString()
}

/** ISO string to a `datetime-local` value in the viewer's time zone; null -> '' */
export function isoToLocal(iso) {
  if (!iso) return ''
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return ''
  const pad = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
}

/** An empty rule form, or one filled from an existing rule */
export function ruleForm(rule = null) {
  if (!rule) return { effect: 'deny', kind: 'pat', subjectId: '', tools: [], note: '', expires: '' }
  return {
    effect: rule.effect,
    kind: rule.subject.kind,
    subjectId: rule.subject.id,
    tools: [...rule.tools],
    note: rule.note || '',
    expires: isoToLocal(rule.expires_at),
  }
}

/**
 * What is wrong with a rule form before it is sent, as an i18n key under `access.rules.errors`, or null. The API
 * checks the same (and more); this only spares a round trip for the obvious cases.
 */
export function ruleFormError(form, now = Date.now()) {
  if (!RULE_EFFECTS.includes(form.effect)) return 'effect'
  if (!SUBJECT_KINDS.includes(form.kind)) return 'subjectKind'
  if (!form.subjectId) return 'subject'
  if (!form.tools.length) return 'noTools'
  if (form.tools.includes(ALL_TOOLS)) {
    if (form.effect === 'only') return 'onlyAllTools'
    if (form.tools.length > 1) return 'wildcardNotAlone'
  }
  if (form.expires) {
    const iso = localToIso(form.expires)
    if (!iso) return 'expiresInvalid'
    if (new Date(iso).getTime() <= now) return 'expiresInPast'
  }
  return null
}

/** POST/PUT body of /api/services/{id}/access-rules from a form that passed ruleFormError */
export function ruleBody(form) {
  return {
    effect: form.effect,
    subject: { kind: form.kind, id: form.subjectId },
    tools: form.tools.includes(ALL_TOOLS) ? [ALL_TOOLS] : [...form.tools],
    note: form.note.trim() || null,
    expires_at: localToIso(form.expires),
  }
}

/**
 * What the subject picker lists for each kind, as [{ id, label, hint }]. PATs: this server's active personal access
 * tokens (the API refuses another server's); clients: active OAuth clients except MCP Gate's console client; users:
 * console accounts; groups.
 */
export function subjectOptions({ tokens = [], clients = [], users = [], groups = [] } = {}) {
  return {
    pat: tokens.filter((tk) => tk.kind === 'pat' && tk.status === 'active')
      .map((tk) => ({ id: tk.jti, label: tk.label || tk.jti.slice(0, 8), hint: tk.jti.slice(0, 8) })),
    client: clients.filter((c) => c.is_active !== false && c.client_id !== CONSOLE_CLIENT_ID)
      .map((c) => ({ id: c.client_id, label: c.client_name || c.client_id, hint: c.client_id })),
    user: users.map((u) => ({ id: u.id, label: u.email || u.username || u.id, hint: u.username || '' })),
    group: groups.map((g) => ({ id: g.id, label: g.name, hint: '' })),
  }
}

/** How a rule's subject reads in a list: the API's label, else a short form of its id */
export function subjectLabel(subject) {
  if (subject.label) return subject.label
  const id = String(subject.id || '')
  return id.length > 16 ? `${id.slice(0, 12)}…` : id
}

/** Bundles to offer when issuing a token for a server: the ones holding its tools first, then the other scopes */
export function splitBundles(access, available) {
  const byName = new Map(bundlesFromAccess(access).map((b) => [b.name, b]))
  const bundles = []
  const others = []
  for (const s of available || []) {
    const b = byName.get(s.name)
    if (b && b.tools.length > 0) bundles.push({ ...s, title: s.title ?? b.title, tools: b.tools })
    else others.push(s)
  }
  return { bundles, others }
}

/** Members a group can still gain: active accounts not in it yet */
export function addableMembers(users, members) {
  const ids = new Set((members || []).map((m) => m.user_id))
  return (users || []).filter((u) => u.is_active !== false && !ids.has(u.id))
}

/**
 * The Access tab's enforcement banner from the policy-feed status (GET /api/oauth/services/{id}/policy-feed): whether
 * what is set on the tab actually reaches the server. { key (under access.enforcement), tone } or null (unknown).
 * Anything that is not enforced is a warning when the server has something to enforce (a rule, a scoped tool or
 * "require a bundle"), and only a note otherwise.
 */
export function enforcement(status) {
  if (!status) return null
  const gap = status.has_access_policy ? 'warning' : 'neutral'
  if (status.state === 'not_wired') return { key: 'notWired', tone: gap }
  if (status.state === 'never_polled') return { key: 'neverPolled', tone: gap }
  const rules = accessRulesState(status)
  if (rules === 'enforced') return status.state === 'stale' ? { key: 'stale', tone: 'warning' } : { key: 'enforced', tone: 'success' }
  if (rules === null) return { key: 'neverPolled', tone: gap }
  return { key: 'oldMiddleware', tone: gap }
}

function toolsIn(access, scope) {
  return (access?.tools || []).filter((tl) => !tl.removed && toolScopeNames(tl).includes(scope)).map((tl) => tl.name).sort()
}

/**
 * The Bundles page: every global scope used as a bundle (it holds tools somewhere or has a title) with the servers
 * that may grant it, and every server's own scope; `unused` = the names of the other global scopes. Each bundle has
 * `servers` = [{ id, name, tools }] (only servers whose tools can be put in it) and `toolCount`.
 */
export function allBundles({ services = [], accesses = {}, globals = [] }) {
  const bundles = []
  const unused = []
  for (const g of globals) {
    const servers = services
      .filter((s) => (accesses[s.id]?.scopes || []).some((x) => x.name === g.name && x.source === 'global' && x.challenge_safe))
      .map((s) => ({ id: s.id, name: s.name, tools: toolsIn(accesses[s.id], g.name) }))
    const toolCount = servers.reduce((n, s) => n + s.tools.length, 0)
    if (toolCount > 0 || g.title) bundles.push({ ...g, service_id: null, servers, toolCount })
    else unused.push(g.name)
  }
  for (const s of services) {
    const access = accesses[s.id]
    for (const sc of (access?.scopes || []).filter((x) => x.source === 'service')) {
      const tools = toolsIn(access, sc.name)
      bundles.push({ ...sc, service_id: s.id, servers: [{ id: s.id, name: s.name, tools }], toolCount: tools.length })
    }
  }
  bundles.sort((a, b) => (b.toolCount > 0) - (a.toolCount > 0) || (a.title || a.name).localeCompare(b.title || b.name))
  return { bundles, unused }
}
