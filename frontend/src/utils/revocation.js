/**
 * Revocation-feed status (GET /api/oauth/services/{id}/revocation-feed, /api/oauth/revocation-feed?audience=):
 * does revoking a token reach its server before the token expires? Pure helpers, testable without React.
 *
 * state: active | stale | never_polled | not_wired
 */

/** StatusDot / Badge tone for a feed state */
export function feedTone(state) {
  if (state === 'active') return 'success'
  if (state === 'stale') return 'warning'
  return 'danger'
}

/** Whether a revoked token stays usable at that server until it expires */
export function revocationReachesServer(state) {
  return state === 'active'
}

/**
 * The sentence the revoke dialog adds about the token's server, or null when there is nothing to say: refresh
 * tokens are only ever presented to MCP Gate itself (revoking one takes effect at once), and an unknown status
 * says nothing either.
 */
export function revocationNote(t, status, token, formatTime = (v) => v) {
  if (!status || !token || token.kind === 'refresh' || !token.audience) return null
  const server = token.service_name || status.audience || token.audience
  if (status.state === 'active') {
    return t('confirm.revokeFeedActive', { server, when: formatTime(status.last_poll) })
  }
  if (status.state === 'stale') {
    return t('confirm.revokeFeedStale', { server, when: formatTime(status.last_poll) })
  }
  return t('confirm.revokeFeedNotWired', { server, expires: formatTime(token.expires_at) })
}
