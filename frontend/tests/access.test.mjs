/**
 * Tool access console helpers (#37). Expected values come from the API contract (docs/reference.md "Tool access
 * rules") and the console requirements: bundles are scopes, a tool keeps its other bundles, a rule form is refused
 * before sending for the cases the API refuses.
 * IDs FE-ACC-001 … are unique within the frontend tests.
 */
import assert from 'node:assert/strict'
import {
  addToBundleBody, addableMembers, allBundles, bundleChanges, bundleChoices, bundlesFromAccess, enforcement,
  explicitChallenge, isScopeToken, isoToLocal, localToIso, ruleBody, ruleForm, ruleFormError, rulesForTool,
  splitBundles, subjectLabel, subjectOptions, toolScopesBody,
} from '../src/utils/access.js'

const row = (scope, source = 'service', challenge = false) => ({ scope, source, challenge })
const access = {
  unscoped_tools: 'allow',
  tools: [
    { id: 't1', name: 'read_file', state: 'approved', removed: false, scopes: [row('files:read'), row('workspace:read', 'global')], challenge: 'files:read' },
    { id: 't2', name: 'delete_file', state: 'approved', removed: false, scopes: [row('files:admin', 'service', true)], challenge: 'files:admin' },
    { id: 't3', name: 'search', state: 'approved', removed: false, scopes: [], challenge: null },
    { id: 't4', name: 'old_tool', state: 'approved', removed: true, scopes: [row('files:read')], challenge: 'files:read' },
  ],
  rules: [
    { id: 'r1', effect: 'deny', subject: { kind: 'group', id: 'g1', label: 'Contractors' }, tools: ['delete_file'] },
    { id: 'r2', effect: 'deny', subject: { kind: 'client', id: 'c1', label: null }, tools: ['*'] },
  ],
  scopes: [
    { name: 'mcp:tools:invoke', title: null, source: 'global', is_default: true, challenge_safe: true },
    { name: 'workspace:read', title: 'Read everything', source: 'global', challenge_safe: true },
    { name: 'files:admin', title: 'Admin', source: 'service', challenge_safe: true },
    { name: 'files:read', title: 'Read', source: 'service', challenge_safe: true },
    { name: 'files:empty', title: null, source: 'service', challenge_safe: true },
    { name: 'bad"name', title: null, source: 'global', challenge_safe: false },
  ],
}

// FE-ACC-001 bundles list the server's current tools of each scope (removed tools left out), used bundles first
{
  const b = bundlesFromAccess(access)
  assert.deepEqual(b.map((x) => x.name).slice(0, 3), ['files:admin', 'files:read', 'workspace:read'])
  assert.deepEqual(b.find((x) => x.name === 'files:read').tools, ['read_file'])
  assert.equal(b.find((x) => x.name === 'files:empty').tools.length, 0)
  // an empty server bundle ranks before an unused global scope
  assert.ok(b.findIndex((x) => x.name === 'files:empty') < b.findIndex((x) => x.name === 'mcp:tools:invoke'))
}

// FE-ACC-002 the approval card offers bundles, not every scope a token may carry
assert.deepEqual(bundleChoices(access).map((x) => x.name).sort(), ['files:admin', 'files:empty', 'files:read', 'workspace:read'])

// FE-ACC-003 an explicit step-up scope is kept while the tool stays in it, dropped (null = narrowest) otherwise
assert.equal(explicitChallenge(access.tools[1]), 'files:admin')
assert.equal(explicitChallenge(access.tools[0]), null)
assert.deepEqual(toolScopesBody(access.tools[1], ['files:admin', 'files:read']), { scopes: ['files:admin', 'files:read'], challenge: 'files:admin' })
assert.deepEqual(toolScopesBody(access.tools[1], ['files:read']), { scopes: ['files:read'], challenge: null })
assert.deepEqual(toolScopesBody(access.tools[0], ['a', 'a', 'b'], 'b'), { scopes: ['a', 'b'], challenge: 'b' })

// FE-ACC-004 assigning from the bundle's side: only changed tools are sent, each keeps its other bundles
{
  const changes = bundleChanges(access, 'files:read', ['t3'])   // search joins, read_file and old_tool leave
  const byTool = Object.fromEntries(changes.map((c) => [c.tool, c.body]))
  assert.deepEqual(Object.keys(byTool).sort(), ['old_tool', 'read_file', 'search'])
  assert.deepEqual(byTool.read_file, { scopes: ['workspace:read'], challenge: null })
  assert.deepEqual(byTool.search, { scopes: ['files:read'], challenge: null })
  assert.equal(bundleChanges(access, 'files:read', ['t1', 't4']).length, 0)
  // a tool with an explicit challenge in another bundle keeps it
  assert.deepEqual(bundleChanges(access, 'files:read', ['t1', 't2', 't4'])[0].body, { scopes: ['files:admin', 'files:read'], challenge: 'files:admin' })
}

// FE-ACC-005 approve-and-add: nothing to send without a bundle or when already in it
assert.equal(addToBundleBody(access.tools[0], ''), null)
assert.equal(addToBundleBody(access.tools[0], 'files:read'), null)
assert.equal(addToBundleBody(undefined, 'files:read').scopes[0], 'files:read')
assert.deepEqual(addToBundleBody(access.tools[1], 'files:read'), { scopes: ['files:admin', 'files:read'], challenge: 'files:admin' })

// FE-ACC-006 rules touching a tool include "*" rules
assert.deepEqual(rulesForTool(access.rules, 'delete_file').map((r) => r.id), ['r1', 'r2'])
assert.deepEqual(rulesForTool(access.rules, 'search').map((r) => r.id), ['r2'])

// FE-ACC-007 rule form validation mirrors the API's refusals
{
  const now = Date.parse('2026-11-25T00:00:00Z')
  const ok = { ...ruleForm(), subjectId: 'x', tools: ['search'] }
  assert.equal(ruleFormError(ok, now), null)
  assert.equal(ruleFormError({ ...ok, subjectId: '' }, now), 'subject')
  assert.equal(ruleFormError({ ...ok, tools: [] }, now), 'noTools')
  assert.equal(ruleFormError({ ...ok, effect: 'only', tools: ['*'] }, now), 'onlyAllTools')
  assert.equal(ruleFormError({ ...ok, tools: ['*', 'search'] }, now), 'wildcardNotAlone')
  assert.equal(ruleFormError({ ...ok, tools: ['*'] }, now), null)
  assert.equal(ruleFormError({ ...ok, effect: 'allow' }, now), 'effect')
  assert.equal(ruleFormError({ ...ok, kind: 'token' }, now), 'subjectKind')
  assert.equal(ruleFormError({ ...ok, expires: '2026-11-24T10:00' }, now), 'expiresInPast')
  assert.equal(ruleFormError({ ...ok, expires: 'nonsense' }, now), 'expiresInvalid')
  assert.equal(ruleFormError({ ...ok, expires: '2099-01-01T00:00' }, now), null)
}

// FE-ACC-008 rule body: trimmed note, null expiry, "*" alone; edit form round-trips the expiry
{
  const body = ruleBody({ effect: 'deny', kind: 'user', subjectId: 'u1', tools: ['*'], note: '  ', expires: '' })
  assert.deepEqual(body, { effect: 'deny', subject: { kind: 'user', id: 'u1' }, tools: ['*'], note: null, expires_at: null })
  const iso = '2030-05-06T07:08:00.000Z'
  assert.equal(localToIso(isoToLocal(iso)), iso)
  assert.equal(localToIso(''), null)
  const form = ruleForm({ effect: 'only', subject: { kind: 'pat', id: 'j1' }, tools: ['a'], note: null, expires_at: null })
  assert.deepEqual(form, { effect: 'only', kind: 'pat', subjectId: 'j1', tools: ['a'], note: '', expires: '' })
}

// FE-ACC-009 subject picker: active PATs only, no console client, no disabled clients
{
  const o = subjectOptions({
    tokens: [{ kind: 'pat', status: 'active', jti: 'aaaaaaaaaa', label: 'laptop' }, { kind: 'pat', status: 'revoked', jti: 'b', label: 'old' },
      { kind: 'access', status: 'active', jti: 'c', label: null }],
    clients: [{ client_id: 'mcp-gate-console', client_name: 'Console', is_active: true }, { client_id: 'x', client_name: 'X', is_active: true },
      { client_id: 'y', client_name: 'Y', is_active: false }],
    users: [{ id: 'u1', email: 'a@example.com', username: 'a' }],
    groups: [{ id: 'g1', name: 'Ops' }],
  })
  assert.deepEqual(o.pat.map((x) => x.label), ['laptop'])
  assert.deepEqual(o.client.map((x) => x.id), ['x'])
  assert.equal(o.user[0].label, 'a@example.com')
  assert.equal(o.group[0].label, 'Ops')
}

// FE-ACC-010 subject labels fall back to a short id
assert.equal(subjectLabel({ id: 'x', label: 'Lab' }), 'Lab')
assert.equal(subjectLabel({ id: 'https://client.example/metadata.json', label: null }), 'https://clie…')

// FE-ACC-011 PAT page: bundles that hold this server's tools first, with their tools
{
  const { bundles, others } = splitBundles(access, [{ name: 'files:read' }, { name: 'mcp:tools:invoke' }, { name: 'files:empty' }])
  assert.deepEqual(bundles.map((b) => [b.name, b.title, b.tools]), [['files:read', 'Read', ['read_file']]])
  assert.deepEqual(others.map((s) => s.name), ['mcp:tools:invoke', 'files:empty'])
  assert.deepEqual(splitBundles(null, [{ name: 'a' }]).others.map((s) => s.name), ['a'])
}

// FE-ACC-012 group members that can still be added: active accounts not already in it
assert.deepEqual(addableMembers([{ id: 'a' }, { id: 'b', is_active: false }, { id: 'c' }], [{ user_id: 'c' }]).map((u) => u.id), ['a'])

// FE-ACC-013 scope names a step-up challenge can carry (RFC 6749 scope-token)
assert.equal(isScopeToken('files:read'), true)
for (const bad of ['', 'a b', 'a"b', 'a\\b', 'naïve']) assert.equal(isScopeToken(bad), false, bad)

// FE-ACC-014 enforcement banner: enforced only when the server's middleware advertised rules1 and is polling
{
  const base = { has_access_policy: true }
  assert.equal(enforcement(null), null)
  assert.deepEqual(enforcement({ ...base, state: 'active', rules_enforced: true }), { key: 'enforced', tone: 'success' })
  assert.deepEqual(enforcement({ ...base, state: 'stale', rules_enforced: true }), { key: 'stale', tone: 'warning' })
  assert.deepEqual(enforcement({ ...base, state: 'active', rules_enforced: false }), { key: 'oldMiddleware', tone: 'warning' })
  assert.deepEqual(enforcement({ has_access_policy: false, state: 'active', rules_enforced: false }), { key: 'oldMiddleware', tone: 'neutral' })
  assert.deepEqual(enforcement({ ...base, state: 'not_wired', rules_enforced: null }), { key: 'notWired', tone: 'warning' })
  assert.deepEqual(enforcement({ ...base, state: 'never_polled', rules_enforced: null }), { key: 'neverPolled', tone: 'warning' })
}

// FE-ACC-015 Bundles page: global bundles across the servers that may grant them, each server's own bundles
{
  const services = [{ id: 's1', name: 'files' }, { id: 's2', name: 'wiki' }]
  const s2 = { tools: [{ id: 'w1', name: 'page', removed: false, scopes: [row('workspace:read', 'global')] }],
    scopes: [{ name: 'workspace:read', source: 'global', challenge_safe: true }, { name: 'mcp:tools:invoke', source: 'global', challenge_safe: true }] }
  const { bundles, unused } = allBundles({
    services, accesses: { s1: access, s2 },
    globals: [{ name: 'workspace:read', title: 'Read everything' }, { name: 'mcp:tools:invoke', title: null }, { name: 'titled', title: 'Later' }],
  })
  const ws = bundles.find((b) => b.name === 'workspace:read')
  assert.deepEqual(ws.servers.map((s) => [s.name, s.tools]), [['files', ['read_file']], ['wiki', ['page']]])
  assert.equal(ws.toolCount, 2)
  assert.equal(ws.service_id, null)
  assert.deepEqual(unused, ['mcp:tools:invoke'])
  assert.ok(bundles.some((b) => b.name === 'titled' && b.servers.length === 0))
  assert.equal(bundles.find((b) => b.name === 'files:empty').service_id, 's1')
  // bundles with tools come first
  assert.ok(bundles.findIndex((b) => b.name === 'titled') > bundles.findIndex((b) => b.name === 'files:admin'))
}

console.log('access.test.mjs ALL PASS')
