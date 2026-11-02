/**
 * Session binding: the second half of a console session (see src/identity/session.py, "Session binding").
 *
 * The session cookie is sent by the browser to every port of the host, so on localhost any local listener
 * (an MCP client's OAuth callback, a dev server) receives it. The backend therefore also requires a random
 * per-session secret in the X-Session-Binding header. It comes back in the body of the login / setup /
 * password-change response, or in the URL fragment (#mcp_sb=...) after a GitHub / Google login, and is kept
 * in localStorage, which, unlike cookies, is scoped to this exact origin (scheme, host AND port). It survives
 * reloads and is shared by tabs of the console, and is removed on logout.
 */
export const BINDING_HEADER = 'X-Session-Binding'
export const WS_PROTOCOL = 'mcp-gate.v1'
export const BINDING_STORAGE_KEY = 'mcp_gate.session_binding'
const FRAGMENT_PARAM = 'mcp_sb'
const VALID = /^[A-Za-z0-9_-]{20,128}$/

function defaultStorage() {
  try { return window.localStorage } catch { return null }
}

export function isValidBinding(value) {
  return typeof value === 'string' && VALID.test(value)
}

export function getBinding(storage = defaultStorage()) {
  try {
    const value = storage?.getItem(BINDING_STORAGE_KEY)
    return isValidBinding(value) ? value : null
  } catch {
    return null
  }
}

export function setBinding(value, storage = defaultStorage()) {
  if (!isValidBinding(value)) return
  try { storage?.setItem(BINDING_STORAGE_KEY, value) } catch { /* storage unavailable: the session ends at reload */ }
}

export function clearBinding(storage = defaultStorage()) {
  try { storage?.removeItem(BINDING_STORAGE_KEY) } catch { /* ignore */ }
}

/** Split '#mcp_sb=...&other' into the binding and the rest of the fragment ('' when nothing is left). */
export function splitBindingFragment(hash) {
  const raw = (hash || '').replace(/^#/, '')
  if (!raw) return { binding: null, rest: '' }
  const params = new URLSearchParams(raw)
  const binding = params.get(FRAGMENT_PARAM)
  if (binding === null) return { binding: null, rest: raw }
  params.delete(FRAGMENT_PARAM)
  return { binding: isValidBinding(binding) ? binding : null, rest: params.toString() }
}

/** After a third-party login: move the binding from the URL fragment into storage and drop it from the URL. */
export function adoptBindingFromLocation(loc = window.location, history = window.history, storage = defaultStorage()) {
  const { binding, rest } = splitBindingFragment(loc.hash)
  if (!loc.hash || rest === (loc.hash || '').replace(/^#/, '')) return false
  if (binding) setBinding(binding, storage)
  history.replaceState(history.state, '', `${loc.pathname}${loc.search}${rest ? `#${rest}` : ''}`)
  return Boolean(binding)
}

/** Subprotocols for the /ws/services handshake (a browser WebSocket cannot send custom headers). */
export function wsProtocols(binding) {
  return isValidBinding(binding) ? [WS_PROTOCOL, `${WS_PROTOCOL}.binding.${binding}`] : [WS_PROTOCOL]
}
