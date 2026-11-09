import assert from 'node:assert/strict'
import {
  safeRedirectPath, rememberRedirect, consumeRedirect, peekRedirect, forgetRedirectIfAt, navigateAfterLoginOnce,
} from '../src/utils/redirect.js'

// node has no sessionStorage
const store = new Map()
globalThis.sessionStorage = {
  getItem: (k) => (store.has(k) ? store.get(k) : null),
  setItem: (k, v) => store.set(k, String(v)),
  removeItem: (k) => store.delete(k),
}

// Valid same-site paths are returned unchanged
assert.equal(safeRedirectPath('/services/abc?tab=tools'), '/services/abc?tab=tools')
assert.equal(safeRedirectPath('/'), '/')
// Open redirects always return the fallback
assert.equal(safeRedirectPath('//evil.example.com'), '/')
assert.equal(safeRedirectPath('/\\evil.example.com'), '/')
assert.equal(safeRedirectPath('https://evil.example.com'), '/')
assert.equal(safeRedirectPath('javascript:alert(1)'), '/')
assert.equal(safeRedirectPath('/ok bad'), '/')
assert.equal(safeRedirectPath('/ok\tbad'), '/')
// Avoid bouncing back to the login page after login
assert.equal(safeRedirectPath('/login'), '/')
assert.equal(safeRedirectPath('/login?next=x'), '/')
// /setup is also part of the login flow
assert.equal(safeRedirectPath('/setup'), '/')
// The OAuth consent page must be remembered so login can resume the authorization flow
assert.equal(safeRedirectPath('/consent?rid=abc'), '/consent?rid=abc')
// Non-string / empty / custom fallback / too long
assert.equal(safeRedirectPath(null), '/')
assert.equal(safeRedirectPath('', '/dashboard'), '/dashboard')
assert.equal(safeRedirectPath('/' + 'x'.repeat(3000)), '/')

// Signing in returns to the consent page once, however many places report the sign-in (#20): the login page's
// effect and its submit handler both did, the second found the remembered path gone and went to '/'
{
  const calls = []
  rememberRedirect('/consent?rid=abc')
  const goOn = navigateAfterLoginOnce((to, opts) => calls.push([to, opts]))
  goOn()
  goOn()
  assert.deepEqual(calls, [['/consent?rid=abc', { replace: true }]])
  assert.equal(peekRedirect(), '/')   // taken
}
// Nothing remembered -> the fallback, still only once
{
  const calls = []
  const goOn = navigateAfterLoginOnce((to) => calls.push(to), '/services')
  goOn(); goOn()
  assert.deepEqual(calls, ['/services'])
}
// Each sign-in gets its own once: a new function navigates again
{
  const calls = []
  rememberRedirect('/tokens')
  navigateAfterLoginOnce((to) => calls.push(to))()
  rememberRedirect('/consent?rid=def')
  navigateAfterLoginOnce((to) => calls.push(to))()
  assert.deepEqual(calls, ['/tokens', '/consent?rid=def'])
}
// Third-party login lands on the page from the server: the remembered value is forgotten there, not elsewhere
{
  rememberRedirect('/consent?rid=abc')
  forgetRedirectIfAt('/services')
  assert.equal(peekRedirect(), '/consent?rid=abc')
  forgetRedirectIfAt('/consent?rid=abc')
  assert.equal(consumeRedirect(), '/')
}

console.log('redirect.test.mjs ALL PASS')
