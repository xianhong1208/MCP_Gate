/**
 * CSV Export Utilities
 */

/**
 * Convert array of objects to CSV string
 */
export function toCSV(data, columns) {
  if (!data || data.length === 0) return ''

  const headers = columns.map(col => `"${col.label}"`)
  const rows = [headers.join(',')]

  data.forEach(item => {
    const row = columns.map(col => {
      let value = col.accessor(item)
      if (value === null || value === undefined) value = ''
      value = String(value).replace(/"/g, '""')
      return `"${value}"`
    })
    rows.push(row.join(','))
  })

  return rows.join('\n')
}

/**
 * Download CSV file
 */
export function downloadCSV(csvContent, filename) {
  const BOM = '\uFEFF' // UTF-8 BOM for Excel compatibility
  const blob = new Blob([BOM + csvContent], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)

  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.style.display = 'none'

  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)

  URL.revokeObjectURL(url)
}

/**
 * Export OAuth tokens (the token dict array from /api/oauth/tokens) to CSV
 */
export function exportTokensToCSV(tokens) {
  const columns = [
    { label: 'JTI', accessor: (t) => t.jti },
    { label: 'Kind', accessor: (t) => t.kind },
    { label: 'Label', accessor: (t) => t.label || '' },
    { label: 'Client', accessor: (t) => t.client_name || t.client_id || '' },
    { label: 'Service', accessor: (t) => t.service_name || '' },
    { label: 'Audience', accessor: (t) => t.audience || '' },
    { label: 'Scopes', accessor: (t) => (t.scopes || []).join(' ') },
    { label: 'Issued At', accessor: (t) => t.issued_at || '' },
    { label: 'Expires At', accessor: (t) => t.expires_at || '' },
    { label: 'Last Used At', accessor: (t) => t.last_used_at || '' },
    { label: 'Use Count', accessor: (t) => t.use_count ?? 0 },
    { label: 'Status', accessor: (t) => t.status || '' },
  ]

  const csvContent = toCSV(tokens, columns)
  const timestamp = new Date().toISOString().split('T')[0]
  downloadCSV(csvContent, `tokens_export_${timestamp}.csv`)
}

/**
 * Export services to CSV
 */
export function exportServicesToCSV(services) {
  const columns = [
    { label: 'Name', accessor: (s) => s.name },
    { label: 'Description', accessor: (s) => s.description || '' },
    { label: 'MCP URL', accessor: (s) => s.mcp_url || '' },
    { label: 'Audience', accessor: (s) => s.effective_audience || '' },
    { label: 'Scopes', accessor: (s) => (s.oauth_scopes || []).join(' ') },
    { label: 'Requires Auth', accessor: (s) => s.requires_auth ? 'Yes' : 'No' },
    { label: 'Health', accessor: (s) => s.health?.status || 'unknown' },
    { label: 'Tools', accessor: (s) => s.tools_count ?? 0 },
    { label: 'Active', accessor: (s) => s.is_active ? 'Yes' : 'No' },
    { label: 'Created At', accessor: (s) => s.created_at || '' },
  ]

  const csvContent = toCSV(services, columns)
  const timestamp = new Date().toISOString().split('T')[0]
  downloadCSV(csvContent, `services_export_${timestamp}.csv`)
}

/**
 * Export audit logs to CSV
 */
export function exportAuditLogsToCSV(logs) {
  const columns = [
    { label: 'Time', accessor: (l) => l.created_at || '' },
    { label: 'Action', accessor: (l) => l.action },
    { label: 'Resource Type', accessor: (l) => l.resource_type },
    { label: 'Resource ID', accessor: (l) => l.resource_id || '' },
    { label: 'Actor', accessor: (l) => l.actor_name || '' },
    { label: 'Actor Type', accessor: (l) => l.actor_type || '' },
    { label: 'Status', accessor: (l) => l.status },
    { label: 'IP Address', accessor: (l) => l.ip_address || '' },
    { label: 'Request Method', accessor: (l) => l.request_method || '' },
    { label: 'Request Path', accessor: (l) => l.request_path || '' },
    { label: 'Error Message', accessor: (l) => l.error_message || '' },
    { label: 'User Agent', accessor: (l) => l.user_agent || '' },
  ]

  const csvContent = toCSV(logs, columns)
  const timestamp = new Date().toISOString().split('T')[0]
  downloadCSV(csvContent, `audit_logs_export_${timestamp}.csv`)
}
