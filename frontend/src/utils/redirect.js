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
