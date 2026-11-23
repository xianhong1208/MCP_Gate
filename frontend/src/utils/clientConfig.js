/**
 * Client configuration export (#36): what the "Connect a client" panel shows for each MCP client.
 *
 * The snippets themselves come from the backend (GET /api/services/{id}/client-config, GET /api/client-config);
 * this file only holds the client list, the localized steps per client and auth variant, and the file download.
 */

export const CLIENTS = [
  { key: 'claude-code', label: 'Claude Code' },
  { key: 'cursor', label: 'Cursor' },
  { key: 'vscode', label: 'VS Code' },
  { key: 'codex', label: 'Codex' },
]

export const VARIANTS = ['oauth', 'pat']

/**
 * The i18n keys of the steps for one client and variant, in order (under clientConfig.steps).
 * `pat` variants start with creating a token and setting it where the client reads it.
 */
const STEPS = {
  'claude-code': {
    oauth: ['claudeCode.runCommands', 'claudeCode.login', 'claudeCode.orFile'],
    pat: ['createPat', 'setEnv', 'claudeCode.runPatCommands', 'claudeCode.orFile'],
  },
  cursor: {
    oauth: ['cursor.installLink', 'cursor.orFile', 'cursor.login'],
    pat: ['createPat', 'setEnv', 'cursor.installLink', 'cursor.orFile'],
  },
  vscode: {
    oauth: ['vscode.runCommands', 'vscode.orFile', 'vscode.login'],
    pat: ['createPat', 'vscode.patFile', 'vscode.patPrompt'],
  },
  codex: {
    oauth: ['codex.runCommands', 'codex.orFile'],
    pat: ['createPat', 'setEnv', 'codex.patFile'],
  },
}

export function stepKeys(client, variant) {
  return (STEPS[client] && STEPS[client][variant]) || []
}

export function allStepKeys() {
  const out = new Set()
  for (const c of Object.values(STEPS)) for (const list of Object.values(c)) list.forEach((k) => out.add(k))
  return [...out]
}

const MIME = { json: 'application/json', toml: 'application/toml' }

/** A Blob for the generated file; `download` turns it into a browser download. */
export function fileBlob(file) {
  return new Blob([file.content], { type: `${MIME[file.format] || 'text/plain'};charset=utf-8` })
}

export function downloadFile(file) {
  const url = URL.createObjectURL(fileBlob(file))
  const a = document.createElement('a')
  a.href = url
  a.download = file.filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  setTimeout(() => URL.revokeObjectURL(url), 0)
}

/** The env var / prompt names a PAT snippet uses, for the "set it" step. */
export function patNames(config) {
  return (config?.servers || []).map((s) => s.pat_env || s.pat_input).filter(Boolean)
}
