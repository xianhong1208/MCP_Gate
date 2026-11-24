import assert from 'node:assert/strict'
import { accessRulesState, feedTone, revocationNote, revocationReachesServer } from '../src/utils/revocation.js'

// A stand-in for i18next's t: key plus the interpolation values, so the assertions see what was chosen
const t = (key, vars = {}) => `${key} ${JSON.stringify(vars)}`
const pat = { kind: 'pat', audience: 'http://h:1/mcp', service_name: 'kb', expires_at: '2027-01-01 00:00:00' }

assert.equal(feedTone('active'), 'success')
assert.equal(feedTone('stale'), 'warning')
assert.equal(feedTone('never_polled'), 'danger')
assert.equal(feedTone('not_wired'), 'danger')
assert.equal(revocationReachesServer('active'), true)
assert.equal(revocationReachesServer('never_polled'), false)

assert.match(revocationNote(t, { state: 'active', last_poll: 'p' }, pat), /^confirm\.revokeFeedActive .*"server":"kb".*"when":"p"/)
assert.match(revocationNote(t, { state: 'stale', last_poll: 'p' }, pat), /^confirm\.revokeFeedStale /)
for (const state of ['never_polled', 'not_wired']) {
  assert.match(revocationNote(t, { state, last_poll: null }, pat), /^confirm\.revokeFeedNotWired .*"expires":"2027-01-01 00:00:00"/)
}
// the server falls back to the audience; formatTime is applied
assert.match(revocationNote(t, { state: 'not_wired', audience: 'http://h:1/mcp' }, { ...pat, service_name: null }, () => 'F'),
  /"server":"http:\/\/h:1\/mcp".*"expires":"F"/)
// nothing to say for refresh tokens, unknown status, or tokens without an audience
assert.equal(revocationNote(t, { state: 'not_wired' }, { ...pat, kind: 'refresh' }), null)
assert.equal(revocationNote(t, null, pat), null)
assert.equal(revocationNote(t, { state: 'not_wired' }, { ...pat, audience: null }), null)

// access rules (#37): shown only once a resource server read the policy feed; a warning only when rules exist
assert.equal(accessRulesState(null), null)
assert.equal(accessRulesState({ state: 'never_polled', rules_enforced: null, has_access_policy: true }), null)
assert.equal(accessRulesState({ state: 'active', rules_enforced: true, has_access_policy: true }), 'enforced')
assert.equal(accessRulesState({ state: 'active', rules_enforced: true, has_access_policy: false }), 'enforced')
assert.equal(accessRulesState({ state: 'active', rules_enforced: false, has_access_policy: false }), 'not_enforced')
assert.equal(accessRulesState({ state: 'stale', rules_enforced: false, has_access_policy: true }), 'not_enforced_warn')
// an older MCP Gate answer without the field says nothing
assert.equal(accessRulesState({ state: 'active' }), null)

console.log('revocation.test.mjs ALL PASS')
