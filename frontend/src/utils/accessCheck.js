/**
 * Checking tool access (#37, 1.6 PR 5): helpers for "Inspect as", the token page and the what-if form, pure so they
 * can be tested without React.
 *
 * Input shape is the API's: GET /api/services/{id}/access/check answers
 *   { subject: { token, client, user, group }, scopes, base_scopes, added_scopes,
 *     counts: { allowed, needs_scope, hidden },
 *     tools: [{ id, name, state, decision, reason, scopes, challenge, rule_ids, rules: [{ id, effect, subject, note }] }] }
 */

export const DECISIONS = ['allowed', 'needs_scope', 'hidden']
export const WHAT_IF_KINDS = ['pat', 'client', 'user', 'group']

/** An empty what-if form: who (kind + id), optionally through which client (users and group members), extra scopes */
export function whatIfForm(kind = 'pat') {
  return { kind, subjectId: '', clientId: '', scopes: [] }
}

/**
 * The query of GET /api/services/{id}/access/check for a what-if form, or null while no subject is chosen. A personal
 * token is checked as itself (its own scopes, plus the added ones); a client on its own is a client_credentials token;
 * a user or "a member of" a group may go through a client, so that client's rules apply too.
 */
export function whatIfParams(form) {
  if (!form || !WHAT_IF_KINDS.includes(form.kind) || !form.subjectId) return null
  const key = { pat: 'jti', client: 'client_id', user: 'user_id', group: 'group_id' }[form.kind]
  const params = { [key]: form.subjectId }
  if ((form.kind === 'user' || form.kind === 'group') && form.clientId) params.client_id = form.clientId
  const scopes = [...new Set(form.scopes || [])]
  if (scopes.length) params.scope = scopes.join(' ')
  return params
}

/** The tools of a check in reading order: what the token may call, then what more scope would unlock, then the hidden */
export function sortVerdicts(tools) {
  return [...(tools || [])].sort((a, b) => DECISIONS.indexOf(a.decision) - DECISIONS.indexOf(b.decision)
    || a.name.localeCompare(b.name))
}

/** Which of a tool's bundles let the checked token call it (the scopes it holds among the tool's) */
export function grantingScopes(tool, scopes) {
  const held = new Set(scopes || [])
  return (tool.scopes || []).filter((s) => held.has(s))
}

/**
 * How a verdict reads: an i18n key under `access.check.reason` and its values. Allowed through a bundle names the
 * bundle; allowed in no bundle says so; the others name the scope to ask for or the rules that hide the tool.
 */
export function verdictReason(tool, scopes, subjectLabel = (s) => s.label || s.id) {
  if (tool.reason === 'ok') {
    const via = grantingScopes(tool, scopes)
    return via.length ? { key: 'viaBundle', values: { scopes: via.join(', ') } } : { key: 'noBundle', values: {} }
  }
  if (tool.reason === 'missing_scope') return { key: 'missingScope', values: { scope: tool.challenge } }
  if (tool.reason === 'denied_by_rule' || tool.reason === 'outside_only_rule') {
    const who = (tool.rules || []).map((r) => subjectLabel(r.subject)).join(', ')
    return { key: tool.reason === 'denied_by_rule' ? 'denied' : 'outsideOnly', values: { rules: who || (tool.rule_ids || []).join(', ') } }
  }
  if (tool.reason === 'not_approved') return { key: 'notApproved', values: {} }
  if (tool.reason === 'unscoped_tool_requires_scope') return { key: 'unscopedRequired', values: {} }
  return { key: 'unknown', values: { reason: tool.reason } }
}

/**
 * The live tools/list (what the server answered to "Refresh as" this token) against MCP Gate's verdict.
 * `enforcementKey` is enforcement(status).key (utils/access.js) or null when the feed status is unknown.
 *
 * MCP Gate's inspect copy of a token carries `mcp_gate_probe`, and a server running the middleware lists every tool to
 * it, so a hidden tool in the live list is expected there ('probeOnly'): the server hides it from the token itself.
 * A 1.5 middleware hides unapproved tools from tokens but ignores rules and scopes. Without a middleware the live list
 * is exactly what the token sees, so a hidden tool in it is exposed. An allowed or step-up tool missing from the live
 * list is a disagreement too ('notListed').
 *
 * Returns { status: { [tool]: 'listed' | 'notListed' | 'hiddenOk' | 'probeOnly' | 'exposed' | 'unverified' },
 *           exposed: [names], notListed: [names] }
 */
export function compareLive(check, liveNames, enforcementKey) {
  const live = new Set(liveNames || [])
  const status = {}
  const exposed = []
  const notListed = []
  for (const tool of check?.tools || []) {
    const listed = live.has(tool.name)
    let s
    if (tool.decision !== 'hidden') s = listed ? 'listed' : 'notListed'
    else if (!listed) s = 'hiddenOk'
    else if (enforcementKey === 'enforced' || enforcementKey === 'stale') s = 'probeOnly'
    else if (enforcementKey === 'oldMiddleware') s = tool.reason === 'not_approved' ? 'probeOnly' : 'exposed'
    else if (!enforcementKey) s = 'unverified'
    else s = 'exposed'
    status[tool.name] = s
    if (s === 'exposed') exposed.push(tool.name)
    if (s === 'notListed') notListed.push(tool.name)
  }
  return { status, exposed, notListed }
}
