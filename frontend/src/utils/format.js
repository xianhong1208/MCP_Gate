/**
 * Display formatting helpers (pure functions, no React dependency)
 */

/**
 * Milliseconds -> human-readable string.
 *   842      → "842 ms"
 *   1480     → "1.5 s"
 *   60226    → "60.2 s"
 *   125000   → "2.1 min"
 * A raw "60226ms" means nothing to users; such numbers must be scaled to a human range first.
 */
export function formatMs(ms) {
  if (ms == null || Number.isNaN(Number(ms))) return ''
  const n = Number(ms)
  if (n < 1000) return `${Math.round(n)} ms`
  if (n < 60_000) return `${(n / 1000).toFixed(1)} s`
  if (n < 3_600_000) return `${(n / 60_000).toFixed(1)} min`
  return `${(n / 3_600_000).toFixed(1)} h`
}

/**
 * Backend time string -> Date.
 * The backend returns 'YYYY-MM-DD HH:MM:SS' (server local time, no zone marker); replacing the space with T
 * makes every browser parse it. Correct when browser and server share a time zone (the norm for intranet deployments).
 */
export function parseServerDate(value) {
  if (!value) return null
  const d = new Date(typeof value === 'string' ? value.replace(' ', 'T') : value)
  return Number.isNaN(d.getTime()) ? null : d
}

/**
 * Relative time broken into { key, n }; the caller translates via i18n (common.relative.<key>).
 * Returning data instead of a string keeps this pure and testable under node without pulling i18n into utils.
 */
export function relativeTimeParts(value, now = Date.now()) {
  const d = parseServerDate(value)
  if (!d) return null
  const seconds = Math.max(0, Math.round((now - d.getTime()) / 1000))
  if (seconds < 45) return { key: 'justNow', n: seconds }
  const minutes = Math.round(seconds / 60)
  if (minutes < 60) return { key: 'minutesAgo', n: minutes }
  const hours = Math.round(minutes / 60)
  if (hours < 24) return { key: 'hoursAgo', n: hours }
  return { key: 'daysAgo', n: Math.round(hours / 24) }
}

/**
 * Backend time string -> fixed "YYYY/MM/DD HH:mm" format (local zone, locale-independent, year/month/day order).
 * withSeconds=true appends :ss. Returns the original string when it cannot be parsed.
 */
export function formatDateTime(value, { withSeconds = false } = {}) {
  const d = parseServerDate(value)
  if (!d) return value || ''
  const pad = (n) => String(n).padStart(2, '0')
  const base = `${d.getFullYear()}/${pad(d.getMonth() + 1)}/${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
  return withSeconds ? `${base}:${pad(d.getSeconds())}` : base
}

/** Time of day only: HH:mm:ss (local time zone). */
export function formatTime(value) {
  const d = parseServerDate(value)
  if (!d) return value || ''
  const pad = (n) => String(n).padStart(2, '0')
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

/** Date only: YYYY/MM/DD */
export function formatDate(value) {
  const d = parseServerDate(value)
  if (!d) return value || ''
  const pad = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}/${pad(d.getMonth() + 1)}/${pad(d.getDate())}`
}
