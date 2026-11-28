/**
 * Checking tool access (#37, 1.6 PR 5): the what-if query, the reading order and wording of verdicts, and the
 * comparison of the server's live tools/list with MCP Gate's verdict. Expected values come from the API contract
 * (GET /api/services/{id}/access/check) and from how a server answers MCP Gate's inspect copy of a token: with the
 * middleware it lists every tool to it; with a 1.5 middleware it ignores rules; without one, the list is what the
 * token sees.
 * IDs FE-CHK-001 … are unique within the frontend tests.
 */
import assert from 'node:assert/strict'
import { compareLive, grantingScopes, sortVerdicts, verdictReason, whatIfForm, whatIfParams } from '../src/utils/accessCheck.js'

const v = (name, decision, reason, extra = {}) => ({ name, decision, reason, scopes: [], challenge: null, rule_ids: [], rules: [], ...extra })
const check = {
  scopes: ['files:read'],
  tools: [
    v('search', 'allowed', 'ok'),
    v('read_file', 'allowed', 'ok', { scopes: ['files:read', 'workspace:read'] }),
    v('delete_file', 'needs_scope', 'missing_scope', { scopes: ['files:admin'], challenge: 'files:admin' }),
    v('move_file', 'hidden', 'denied_by_rule', { rule_ids: ['r1'], rules: [{ id: 'r1', subject: { kind: 'group', id: 'g1', label: 'Contractors' } }] }),
    v('purge', 'hidden', 'not_approved'),
  ],
}

// FE-CHK-001 what-if query per subject kind; nothing to ask without a subject
assert.equal(whatIfParams(whatIfForm()), null)
assert.equal(whatIfParams({ ...whatIfForm('role'), subjectId: 'x' }), null)
assert.deepEqual(whatIfParams({ ...whatIfForm('pat'), subjectId: 'j1', clientId: 'c1' }), { jti: 'j1' })
assert.deepEqual(whatIfParams({ ...whatIfForm('client'), subjectId: 'c1', clientId: 'c2' }), { client_id: 'c1' })
assert.deepEqual(whatIfParams({ ...whatIfForm('user'), subjectId: 'u1' }), { user_id: 'u1' })
assert.deepEqual(whatIfParams({ ...whatIfForm('user'), subjectId: 'u1', clientId: 'c1' }), { user_id: 'u1', client_id: 'c1' })
assert.deepEqual(whatIfParams({ ...whatIfForm('group'), subjectId: 'g1', clientId: 'c1' }), { group_id: 'g1', client_id: 'c1' })

// FE-CHK-002 added scopes travel as one space-separated `scope`, without duplicates
assert.deepEqual(whatIfParams({ ...whatIfForm('client'), subjectId: 'c1', scopes: ['a', 'b', 'a'] }), { client_id: 'c1', scope: 'a b' })
assert.equal('scope' in whatIfParams({ ...whatIfForm('client'), subjectId: 'c1', scopes: [] }), false)

// FE-CHK-003 reading order: allowed, then needs a bundle, then hidden; by name within
assert.deepEqual(sortVerdicts(check.tools).map((t) => t.name), ['read_file', 'search', 'delete_file', 'move_file', 'purge'])
assert.deepEqual(sortVerdicts(undefined), [])

// FE-CHK-004 an allowed tool names the bundle that lets the token call it; a tool in no bundle says so
assert.deepEqual(grantingScopes(check.tools[1], check.scopes), ['files:read'])
assert.deepEqual(verdictReason(check.tools[1], check.scopes), { key: 'viaBundle', values: { scopes: 'files:read' } })
assert.deepEqual(verdictReason(check.tools[0], check.scopes), { key: 'noBundle', values: {} })

// FE-CHK-005 the other reasons: the scope to ask for, the rules' subjects, not approved, unscoped
assert.deepEqual(verdictReason(check.tools[2], check.scopes), { key: 'missingScope', values: { scope: 'files:admin' } })
assert.deepEqual(verdictReason(check.tools[3], check.scopes), { key: 'denied', values: { rules: 'Contractors' } })
assert.deepEqual(verdictReason(v('x', 'hidden', 'outside_only_rule', { rule_ids: ['r9'] }), []), { key: 'outsideOnly', values: { rules: 'r9' } })
assert.equal(verdictReason(check.tools[4], []).key, 'notApproved')
assert.equal(verdictReason(v('x', 'hidden', 'unscoped_tool_requires_scope'), []).key, 'unscopedRequired')
assert.deepEqual(verdictReason(v('x', 'hidden', 'later_reason'), []), { key: 'unknown', values: { reason: 'later_reason' } })

// FE-CHK-006 a server running the 1.6 middleware lists every tool to the inspect copy: hidden tools are expected there
const all = check.tools.map((t) => t.name)
let c = compareLive(check, all, 'enforced')
assert.deepEqual(c.exposed, [])
assert.deepEqual(c.notListed, [])
assert.equal(c.status.move_file, 'probeOnly')
assert.equal(c.status.search, 'listed')
assert.equal(compareLive(check, all, 'stale').status.move_file, 'probeOnly')

// FE-CHK-007 a 1.5 middleware hides unapproved tools but ignores rules: a rule-hidden tool it lists is exposed
c = compareLive(check, all, 'oldMiddleware')
assert.deepEqual(c.exposed, ['move_file'])
assert.equal(c.status.purge, 'probeOnly')

// FE-CHK-008 without a middleware (or one that never polled) every hidden tool the server lists is exposed
for (const key of ['notWired', 'neverPolled']) {
  assert.deepEqual(compareLive(check, all, key).exposed, ['move_file', 'purge'], key)
}

// FE-CHK-009 a hidden tool the server did not list agrees; an allowed one it did not list disagrees
c = compareLive(check, ['search', 'delete_file'], 'notWired')
assert.equal(c.status.move_file, 'hiddenOk')
assert.deepEqual(c.exposed, [])
assert.deepEqual(c.notListed, ['read_file'])

// FE-CHK-010 no feed status: a listed hidden tool is not judged
c = compareLive(check, all, null)
assert.equal(c.status.move_file, 'unverified')
assert.deepEqual(c.exposed, [])

console.log('accessCheck tests passed')
