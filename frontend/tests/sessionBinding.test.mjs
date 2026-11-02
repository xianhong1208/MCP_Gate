import assert from 'node:assert/strict'
import {
  BINDING_STORAGE_KEY, adoptBindingFromLocation, clearBinding, getBinding, setBinding, splitBindingFragment,
  wsProtocols,
} from '../src/utils/sessionBinding.js'

function memoryStorage() {
  const data = new Map()
  return {
    getItem: (k) => (data.has(k) ? data.get(k) : null),
    setItem: (k, v) => data.set(k, String(v)),
    removeItem: (k) => data.delete(k),
  }
}

const B = 'a'.repeat(43)

// Storage round trip; malformed values are never stored or returned
{
  const s = memoryStorage()
  assert.equal(getBinding(s), null)
  setBinding(B, s)
  assert.equal(getBinding(s), B)
  setBinding('bad value\r\nX-Injected: 1', s)
  assert.equal(getBinding(s), B)
  s.setItem(BINDING_STORAGE_KEY, 'short')
  assert.equal(getBinding(s), null)
  clearBinding(s)
  assert.equal(getBinding(s), null)
  // Storage that throws (private mode, blocked site data) behaves as empty
  const broken = { getItem() { throw new Error('x') }, setItem() { throw new Error('x') }, removeItem() { throw new Error('x') } }
  assert.equal(getBinding(broken), null)
  setBinding(B, broken)
  clearBinding(broken)
}

// Fragment parsing
assert.deepEqual(splitBindingFragment(''), { binding: null, rest: '' })
assert.deepEqual(splitBindingFragment('#section'), { binding: null, rest: 'section' })
assert.deepEqual(splitBindingFragment(`#mcp_sb=${B}`), { binding: B, rest: '' })
assert.deepEqual(splitBindingFragment(`#mcp_sb=${B}&tab=x`), { binding: B, rest: 'tab=x' })
assert.deepEqual(splitBindingFragment('#mcp_sb=bad%20value'), { binding: null, rest: '' })

// Adopting from the URL stores it and strips it from the address bar, keeping path and query
{
  const s = memoryStorage()
  const calls = []
  const history = { state: { k: 1 }, replaceState: (...args) => calls.push(args) }
  const loc = { pathname: '/services', search: '?a=1', hash: `#mcp_sb=${B}` }
  assert.equal(adoptBindingFromLocation(loc, history, s), true)
  assert.equal(getBinding(s), B)
  assert.deepEqual(calls, [[{ k: 1 }, '', '/services?a=1']])
  // A URL without the parameter is left alone
  const untouched = []
  assert.equal(adoptBindingFromLocation({ pathname: '/', search: '', hash: '#x' }, { replaceState: (...a) => untouched.push(a) }, s), false)
  assert.equal(adoptBindingFromLocation({ pathname: '/', search: '', hash: '' }, { replaceState: (...a) => untouched.push(a) }, s), false)
  assert.equal(untouched.length, 0)
}

// WebSocket subprotocols
assert.deepEqual(wsProtocols(B), ['mcp-gate.v1', `mcp-gate.v1.binding.${B}`])
assert.deepEqual(wsProtocols(null), ['mcp-gate.v1'])

console.log('sessionBinding.test.mjs ALL PASS')
