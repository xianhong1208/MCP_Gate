/**
 * Snippet quoting (H-08): a hostile service name must not turn the copy-paste command into shell code.
 * Each generated command is run through a real `sh` with `printf` in place of `claude`.
 */
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { shellCommand, shellQuote, snippetServerName, tokenSnippets } from '../src/utils/snippets.js'

const nasty = ['pwn;touch${IFS}X;#', `a'b"c`, 'line1\nline2', '$(touch X)', '`touch X`', 'x && rm -rf ~', '名稱 sp', '']

for (const v of nasty) {
  const out = execFileSync('sh', ['-c', `printf %s ${shellQuote(v)}`], { encoding: 'utf8' })
  assert.equal(out, v, `round trip of ${JSON.stringify(v)}`)
  const slug = snippetServerName(v)
  assert.match(slug, /^[A-Za-z0-9_-]{1,64}$/, `slug of ${JSON.stringify(v)} is ${slug}`)
}

assert.equal(shellQuote('http://127.0.0.1:8123/mcp'), 'http://127.0.0.1:8123/mcp')
assert.equal(snippetServerName('My Server/v2'), 'My-Server-v2')
assert.equal(snippetServerName('pwn;touch${IFS}X;#'), 'pwn-touch-IFS-X')

const cmd = shellCommand('mcp', 'add', snippetServerName('pwn;touch${IFS}X;#'), 'http://h:1/mcp?a=1&b=$(id)')
const argv = execFileSync('sh', ['-c', `printf '%s\\n' ${cmd}`], { encoding: 'utf8' }).trimEnd().split('\n')
assert.deepEqual(argv, ['mcp', 'add', 'pwn-touch-IFS-X', 'http://h:1/mcp?a=1&b=$(id)'])

const { claudeCmd, mcpJson } = tokenSnippets({ name: 'pwn;touch${IFS}X;#', mcpUrl: 'http://127.0.0.1:1/mcp', token: 'eyJ.a.b' })
const parsed = execFileSync('sh', ['-c', claudeCmd.replace(/^claude /, "printf '%s\\n' ")], { encoding: 'utf8' }).trimEnd().split('\n')
assert.deepEqual(parsed, ['mcp', 'add', '--transport', 'http', 'pwn-touch-IFS-X', 'http://127.0.0.1:1/mcp',
  '--header', 'Authorization: Bearer eyJ.a.b'])
assert.deepEqual(Object.keys(mcpJson.mcpServers), ['pwn-touch-IFS-X'])

console.log('ok   snippets: shell quoting and server-name slugs')
