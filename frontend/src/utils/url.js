/**
 * URLs supplied by third parties (e.g. a dynamically registered client's client_uri) are rendered as links
 * only when they are absolute http(s) URLs; anything else (javascript:, data:, relative, garbage) is shown as
 * plain text by the caller. Returns the normalised URL or null.
 */
const MAX_LEN = 2048

export function safeHttpUrl(raw) {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > MAX_LEN) return null
  // eslint-disable-next-line no-control-regex -- control characters and whitespace are never part of a link here
  if (/[\x00-\x20\x7f]/.test(raw)) return null
  let url
  try {
    url = new URL(raw)
  } catch {
    return null
  }
  return url.protocol === 'http:' || url.protocol === 'https:' ? url.href : null
}
