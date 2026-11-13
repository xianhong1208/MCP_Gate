# Roadmap

[繁體中文](ROADMAP.zh-TW.md)

Where MCP Gate is going after 1.3. The plan was agreed on 2026-11-13; each line names what users get, not
how it is built. MCP Gate stays focused on **managing MCP servers**: it is not meant to become a general
identity provider. Each version has a [milestone](https://github.com/xianhong1208/MCP_Gate/milestones) with
one issue per item.

## Shipped

**1.0.0 (2026-09-01), first public release.** A complete OAuth 2.1 authorization server for MCP: discovery,
dynamic client registration, PKCE, refresh rotation, revocation, introspection, resource indicators and a
consent screen. RS256 tokens that servers verify offline against the JWKS. Personal access tokens. A console
with a server registry, health checks, tool sync, a Marketplace and an audit log. SQLite by default,
PostgreSQL optional.

**1.0.1 (2026-09-15).** Token scopes show at every screen width on a server's page.

**1.1.0 (2026-09-18).** `private_key_jwt` client authentication; the first revocation feed and usage reports
for servers that verify offline (`MCPGateVerifier`); scopes declared per server; a page of remembered
consents; a warning when requests arrive through a host other than the issuer; "Inspect as", which shows a
server's tools as one of its tokens sees them; a Docker-free process runtime for the orchestrator.

**1.2.0 (2026-11-04).** Client ID Metadata Documents (an https URL as `client_id`, the registration method
of MCP 2026-07-28). The revocation feed is limited to each server's own tokens, and the console shows
whether a server is polling it. Access tokens last 15 minutes. Continuous integration on SQLite and
PostgreSQL, and a security hardening pass over the OAuth endpoints, the console session, outbound fetches
and the orchestrator.

**1.3.0 (2026-11-09).** First-run setup needs a one-time setup token, so nobody else on the network can
claim the owner account first. A dependency audit in CI.

**1.3.1 (2026-11-09).** Signing in from the consent screen returns to the authorization request; two
services can no longer share one audience.

See [CHANGELOG.md](CHANGELOG.md) for the details.

## How the next versions fit together

MCP Gate will govern two kinds of server from one console:

- **Servers you control** stay off the request path. MCP Gate sends their rules through a **policy feed**,
  next to today's revocation feed, and the server enforces them in `MCPGateVerifier` and a FastMCP
  middleware, the same pieces as the [README example](README.md#quick-start). The server reports its tool
  calls back.
- **Third-party servers** you cannot change go through an opt-in proxy (1.9).

## Next

| Version | What you get |
|---|---|
| **1.4: security and operations** | `ENCRYPTION_KEY` no longer sits next to the database in `data/`. Rotation for both signing keys and the encryption key: today signing keys are rotated by hand, and changing the encryption key makes the secrets it protects unreadable. An official Docker image and a compose file. |
| **1.5: know your tools** | Each tool's description and input schema is pinned by a hash, and **a new or changed tool is hidden until an admin approves it**. Tool descriptions are scanned for prompt injection ("tool poisoning"). Support for MCP 2026-07-28: `server/discover`, stateless servers, a deprecation notice for dynamic client registration, `application_type`. Ready-made client configuration for Claude Code, Cursor, VS Code and Codex. |
| **1.6: who may call what** | **Tool-level policy:** map tools to scopes and allow or deny tools per token or client. The rules reach your servers through the policy feed and are enforced by the same `MCPGateVerifier` / FastMCP middleware as in the README example, extended, so no request goes through MCP Gate. **Step-up:** a call that needs more answers with `WWW-Authenticate: … scope=`, and the client asks for it. **Tool bundles** to grant a set of tools at once. **"Inspect as"** shows which tools a token may and may not call. |
| **1.7: see every call** | An audit of tool calls (tool, caller, result and time; arguments are not recorded by default). Latency and errors per tool. Quotas. OpenTelemetry export. Alerts. |
| **1.8: catalog and supply chain** | The Marketplace syncs with the official MCP Registry. Server versions are pinned, and an upgrade is reviewed before it runs. Image signatures are checked. Sandbox limits for the servers MCP Gate runs. |
| **1.9: a proxy for third-party servers** | An opt-in proxy at `/mcp/<bundle>`, **off by default**, for servers you cannot change. It reaches the upstream server with token exchange or stored upstream credentials, never by passing the client's token through. |

## Later

- **Several hosts** for the orchestrator: a host registry and a remote agent (#2).
- **GitHub and Google sign-in verified against live OAuth apps** (#1).
- **REST → MCP:** wrap an existing REST API as an MCP server (#51).

## Verification still to do

- GitHub and Google sign-in are implemented and unit-tested, but have never run against real OAuth apps (#1).
- The Docker runtime of the orchestrator is covered by a fake runtime in tests and a build and smoke test of
  the `mcp-runtime` image in CI; it has not run against a real Docker daemon in the test suite.
