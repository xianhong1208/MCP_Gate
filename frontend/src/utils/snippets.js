/**
 * Quoting for copy-paste snippets (mirrors src/utils/snippets.py on the backend).
 *
 * A service name can be a scanned server's self-chosen serverInfo.name, and the admin pastes these
 * snippets into a shell, so every interpolated value is quoted and the CLI name is reduced to a slug.
 */

const SAFE_WORD = /^[A-Za-z0-9@%+=:,./_-]+$/
const SLUG_UNSAFE = /[^A-Za-z0-9_-]+/g
const SLUG_MAX_LEN = 64

/** One POSIX shell word (bash / zsh / sh), whatever `value` contains; same rule as Python's shlex.quote. */
export function shellQuote(value) {
  const s = String(value ?? '')
  if (s === '') return "''"
  if (SAFE_WORD.test(s)) return s
  return `'${s.replace(/'/g, `'"'"'`)}'`
}

export function shellCommand(...argv) {
  return argv.map(shellQuote).join(' ')
}

/** The name `claude mcp add` / an mcpServers key gets: ASCII letters, digits, '-' and '_' only. */
export function snippetServerName(name) {
  const trim = (s) => s.replace(/^[-_]+|[-_]+$/g, '')
  const slug = trim(trim(String(name ?? '').replace(SLUG_UNSAFE, '-')).slice(0, SLUG_MAX_LEN))
  return slug || 'mcp-server'
}

/** The Claude Code command and mcpServers JSON shown after a personal access token is created. */
export function tokenSnippets({ name, mcpUrl, token }) {
  const key = snippetServerName(name)
  const header = `Authorization: Bearer ${token}`
  return {
    claudeCmd: `${shellCommand('claude', 'mcp', 'add', '--transport', 'http', key, mcpUrl)} --header ${shellQuote(header)}`,
    mcpJson: { mcpServers: { [key]: { type: 'http', url: mcpUrl, headers: { Authorization: `Bearer ${token}` } } } },
  }
}
