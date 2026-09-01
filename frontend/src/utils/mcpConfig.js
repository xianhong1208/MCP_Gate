/**
 * MCP config JSON parsing (pure functions, no React dependency -- testable in isolation)
 *
 * Supports the two common shapes users copy from MCP marketplaces / official docs:
 *   1. Claude Desktop / mcpmarket format:
 *      { "mcpServers": { "<name>": { command, args, env } } }
 *   2. a single server object: { command, args, env }
 */

/** Frontend mirror of the backend argv_policy._ALLOWED_BYO_COMMANDS (must stay in sync) */
export const BYO_COMMANDS = ['npx', 'node', 'uvx', 'python', 'python3']

/**
 * @param {string} text pasted JSON text
 * @returns {{name: string, command: string, args: string[], env: object, extraCount: number}|null}
 *          null when parsing fails
 */
export function parseMcpConfigJson(text) {
  let obj
  try {
    obj = JSON.parse(text)
  } catch {
    return null
  }
  if (!obj || typeof obj !== 'object') return null

  let name = ''
  let server = null
  let extraCount = 0

  if (obj.mcpServers && typeof obj.mcpServers === 'object') {
    const keys = Object.keys(obj.mcpServers)
    if (keys.length === 0) return null
    name = keys[0] // take the first when there are several; the UI notes the rest were skipped
    server = obj.mcpServers[name]
    extraCount = keys.length - 1
  } else if (obj.command) {
    server = obj
  } else {
    return null
  }

  if (!server || typeof server !== 'object' || !server.command) return null

  return {
    name,
    command: String(server.command),
    args: Array.isArray(server.args) ? server.args.map(String) : [],
    env: server.env && typeof server.env === 'object' ? server.env : {},
    extraCount,
  }
}

/**
 * Build an mcpServers config that agents (Claude Desktop / Cursor / Cline, ...) can paste directly.
 * Services that require auth get an explicit placeholder reminding the user to create a token on the Tokens page,
 * rather than copying a config that looks complete but cannot connect.
 */
export const TOKEN_PLACEHOLDER = '<YOUR_MCP_CENTER_TOKEN>'

export function buildAgentConfig({ name, url, requiresAuth = false }) {
  const server = { type: 'http', url }
  if (requiresAuth) server.headers = { Authorization: `Bearer ${TOKEN_PLACEHOLDER}` }
  return { mcpServers: { [name]: server } }
}
