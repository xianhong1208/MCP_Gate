/**
 * Client configuration export (#36): the step keys the panel builds dynamically (t(`clientConfig.steps.${k}`))
 * exist in both locales, every client has steps for both variants, and the PAT names come from the API answer.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { CLIENTS, VARIANTS, allStepKeys, fileBlob, patNames, stepKeys } from '../src/utils/clientConfig.js'

const load = (loc) => JSON.parse(readFileSync(new URL(`../src/i18n/locales/${loc}.json`, import.meta.url), 'utf8'))
const lookup = (dict, key) => key.split('.').reduce((n, p) => (n && typeof n === 'object' ? n[p] : undefined), dict)

for (const loc of ['en', 'zh-TW']) {
  const dict = load(loc)
  for (const k of allStepKeys()) {
    assert.equal(typeof lookup(dict, `clientConfig.steps.${k}`), 'string', `${loc}: clientConfig.steps.${k}`)
  }
  for (const v of VARIANTS) assert.equal(typeof lookup(dict, `clientConfig.variant.${v}`), 'string', `${loc}: variant ${v}`)
}
console.log('ok   step keys exist in en and zh-TW')

assert.deepEqual(CLIENTS.map((c) => c.key), ['claude-code', 'cursor', 'vscode', 'codex'])
for (const c of CLIENTS) {
  for (const v of VARIANTS) assert.ok(stepKeys(c.key, v).length >= 2, `${c.key}/${v} has steps`)
  assert.equal(stepKeys(c.key, 'pat')[0], 'createPat', `${c.key}: a PAT starts with creating one`)
  assert.ok(!stepKeys(c.key, 'oauth').includes('createPat'), `${c.key}: sign-in needs no token`)
}
assert.deepEqual(stepKeys('nope', 'oauth'), [])
console.log('ok   every client has steps for both variants')

assert.deepEqual(patNames({ servers: [{ pat_env: 'MCP_GATE_PAT_A' }, { pat_input: 'mcp-gate-pat-b' }, {}] }),
  ['MCP_GATE_PAT_A', 'mcp-gate-pat-b'])
assert.deepEqual(patNames(null), [])
console.log('ok   PAT names')

const blob = fileBlob({ format: 'toml', filename: 'config.toml', content: '[mcp_servers.x]\nurl = "u"\n' })
assert.equal(blob.type, 'application/toml;charset=utf-8')
assert.equal(await blob.text(), '[mcp_servers.x]\nurl = "u"\n')
console.log('ok   file blob')
