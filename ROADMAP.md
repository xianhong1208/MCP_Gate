# Roadmap

## Done (1.0.0)
- Complete OAuth 2.1 flow: discovery, dynamic client registration, PKCE, refresh rotation, revocation, introspection, consent.
- Personal access tokens, FastMCP integration snippets and an end-to-end interop test suite.
- Email/password sign-in with GitHub / Google provider hooks.
- SQLite by default, single initial migration, secrets generated on first start.

## Planned
- **Verify GitHub / Google sign-in against live accounts.** The providers are implemented and unit-tested but have not been exercised with real OAuth apps.
- **Multi-issuer / reverse-proxy detection.** Warn when the request host differs from `OAUTH_ISSUER`.
- **Usage visibility for offline-verified servers.** Only servers that call `/oauth/introspect` report usage; a lightweight usage hook for FastMCP would close the gap.
- **`private_key_jwt` client authentication (RFC 7523)** for machine-to-machine clients.
- **Per-server scopes.** The scope registry is global today; servers should be able to declare their own.
- **Orchestrator:** multiple hosts and non-Docker runtimes.
- **Console:** manage remembered consents from the UI (the API exists).
