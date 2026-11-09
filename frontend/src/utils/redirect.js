/**
 * Remember where the user was when the session expired / they were not logged in, and return there after login.
 * The OAuth flow relies on this too: the backend sends an unauthenticated browser to /consent?rid=...,
 * ProtectedRoute remembers it, and after login (including third-party login) we return to the consent page.
 *
 * Only same-site relative paths are accepted: a single leading '/', not '//' (protocol-relative URLs leave the site),
 * no control characters or whitespace, and not /login or /setup itself (to avoid bouncing back to the login page).
 */
const STORAGE_KEY = 'mcp_redirect_after_login'

export function safeRedirectPath(raw, fallback = '/') {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > 2048) return fallback
  if (!raw.startsWith('/') || raw.startsWith('//') || raw.startsWith('/\\')) return fallback
  // eslint-disable-next-line no-control-regex -- rejecting control characters and spaces is the point
  if (/[\x00-\x20]/.test(raw)) return fallback
  for (const own of ['/login', '/setup']) {
    if (raw === own || raw.startsWith(`${own}?`) || raw.startsWith(`${own}/`)) return fallback
  }
  return raw
}

export function rememberRedirect(path) {
  try { sessionStorage.setItem(STORAGE_KEY, path) } catch { /* ignore when storage is unavailable */ }
}

/** Peek without clearing (for the third-party login ?next=; the callback redirects directly after login). */
export function peekRedirect(fallback = '/') {
  try {
    return safeRedirectPath(sessionStorage.getItem(STORAGE_KEY), fallback)
  } catch {
    return fallback
  }
}

/** Forget the remembered page once the user is on it. Third-party login lands there straight from the server
 * callback, without going through consumeRedirect, and a leftover value would send a later sign-in back to a consent
 * request that has expired. */
export function forgetRedirectIfAt(path) {
  try {
    if (sessionStorage.getItem(STORAGE_KEY) === path) sessionStorage.removeItem(STORAGE_KEY)
  } catch { /* ignore when storage is unavailable */ }
}

/**
 * A function that sends the browser to the remembered page (or `fallback`) the first time it is called and does
 * nothing afterwards. Signing in finishes in more than one place that can fire (the login page's effect when the
 * session appears, its submit handler, StrictMode running effects twice): the first call takes the remembered
 * /consent?rid=..., and a second one used to find nothing left and go to '/', which won and ended the MCP client's
 * authorization flow (#20).
 */
export function navigateAfterLoginOnce(navigate, fallback = '/') {
  let done = false
  return () => {
    if (done) return
    done = true
    navigate(consumeRedirect(fallback), { replace: true })
  }
}

/** Take and clear; always returns a safe path. */
export function consumeRedirect(fallback = '/') {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY)
    sessionStorage.removeItem(STORAGE_KEY)
    return safeRedirectPath(raw, fallback)
  } catch {
    return fallback
  }
}
