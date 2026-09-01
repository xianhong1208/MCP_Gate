import assert from 'node:assert/strict'
import { safeRedirectPath } from '../src/utils/redirect.js'

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

console.log('redirect.test.mjs ALL PASS')
