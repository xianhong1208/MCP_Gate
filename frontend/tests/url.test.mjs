/**
 * safeHttpUrl (H-16): client-supplied URIs (DCR client_uri) become links only when they are http(s).
 */
import assert from 'node:assert/strict'
import { safeHttpUrl } from '../src/utils/url.js'

assert.equal(safeHttpUrl('https://client.example/about'), 'https://client.example/about')
assert.equal(safeHttpUrl('http://127.0.0.1:8080/'), 'http://127.0.0.1:8080/')
for (const bad of ['javascript:alert(1)', 'JavaScript:alert(1)', ' javascript:alert(1)', 'java\nscript:alert(1)',
  'data:text/html,<script>alert(1)</script>', 'vbscript:x', 'file:///etc/passwd', '//evil.example', '/relative',
  'not a url', '', null, undefined, 42, 'https://' + 'a'.repeat(3000)]) {
  assert.equal(safeHttpUrl(bad), null, `rejects ${JSON.stringify(bad)}`)
}
console.log('ok   url: safeHttpUrl')
