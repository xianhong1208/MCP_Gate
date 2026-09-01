/**
 * MCP config JSON parser tests (zero dependencies, run via `npm test`)
 *
 * Covers the shapes users actually copy from MCP marketplaces: the Claude Desktop mcpServers wrapper,
 * multi-path args, multiple servers, a single server object, invalid input, and unsupported commands.
 */
import { parseMcpConfigJson, BYO_COMMANDS } from '../src/utils/mcpConfig.js'
let fail = 0
const eq = (label, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want)
  if (!ok) { fail++; console.log(`FAIL ${label}\n  got : ${JSON.stringify(got)}\n  want: ${JSON.stringify(want)}`) }
  else console.log(`ok   ${label}`)
}

// 1. mcpmarket / Claude Desktop format (firecrawl example)
const firecrawl = `{
  "mcpServers": {
    "firecrawl-mcp": {
      "command": "npx",
      "args": ["-y", "firecrawl-mcp"],
      "env": { "FIRECRAWL_API_KEY": "fc-YOUR-KEY" }
    }
  }
}`
const a = parseMcpConfigJson(firecrawl)
eq('firecrawl name', a.name, 'firecrawl-mcp')
eq('firecrawl command', a.command, 'npx')
eq('firecrawl args', a.args, ['-y', 'firecrawl-mcp'])
eq('firecrawl env', a.env, { FIRECRAWL_API_KEY: 'fc-YOUR-KEY' })
eq('firecrawl extra', a.extraCount, 0)

// 2. filesystem (multi-path args, no env)
const fs = `{"mcpServers":{"filesystem":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/Users/u/Desktop","/other"]}}}`
const b = parseMcpConfigJson(fs)
eq('fs args', b.args, ['-y', '@modelcontextprotocol/server-filesystem', '/Users/u/Desktop', '/other'])
eq('fs env empty', b.env, {})

// 3. multiple servers -> take the first and report the rest
const multi = `{"mcpServers":{"one":{"command":"npx","args":[]},"two":{"command":"uvx","args":[]}}}`
const c = parseMcpConfigJson(multi)
eq('multi name', c.name, 'one')
eq('multi extraCount', c.extraCount, 1)

// 4. single server object (no mcpServers wrapper)
const bare = `{"command":"uvx","args":["some-mcp"],"env":{"K":"V"}}`
const d = parseMcpConfigJson(bare)
eq('bare command', d.command, 'uvx')
eq('bare name empty', d.name, '')

// 5. invalid input
eq('invalid json', parseMcpConfigJson('not json'), null)
eq('empty mcpServers', parseMcpConfigJson('{"mcpServers":{}}'), null)
eq('no command', parseMcpConfigJson('{"foo":1}'), null)
eq('null', parseMcpConfigJson('null'), null)

// 6. docker-based (unsupported, but still parsed so the UI can give a clear message)
const dk = parseMcpConfigJson('{"mcpServers":{"x":{"command":"docker","args":["run","-i","img"]}}}')
eq('docker parsed', dk.command, 'docker')
eq('docker not allowed', BYO_COMMANDS.includes(dk.command), false)

console.log(fail === 0 ? '\nALL PASS' : `\n${fail} FAILED`)
process.exit(fail ? 1 : 0)

// ---- buildAgentConfig ----
{
  const { buildAgentConfig, TOKEN_PLACEHOLDER } = await import('../src/utils/mcpConfig.js')
  const open = buildAgentConfig({ name: 'kb', url: 'http://10.0.0.5:5010/mcp' })
  if (JSON.stringify(open) !== JSON.stringify({ mcpServers: { kb: { type: 'http', url: 'http://10.0.0.5:5010/mcp' } } }))
    throw new Error('open config mismatch: ' + JSON.stringify(open))
  const secured = buildAgentConfig({ name: 'kb', url: 'http://h:1/mcp', requiresAuth: true })
  if (secured.mcpServers.kb.headers.Authorization !== `Bearer ${TOKEN_PLACEHOLDER}`)
    throw new Error('secured config must carry a Bearer placeholder')
  console.log('ok   buildAgentConfig')
}
