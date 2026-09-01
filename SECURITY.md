# Security policy

## Report a vulnerability

Open a [GitHub security advisory](https://github.com/xianhong1208/MCP_Center/security/advisories/new) or email the maintainer listed in `pyproject.toml`. Do not open a public issue for security problems. You will get an acknowledgement within a few days.

## Supported versions

Only the latest release on the `main` branch receives fixes.

## What MCP Center protects and how

| Asset | Protection |
|---|---|
| RS256 signing private keys | Encrypted at rest with AES-256-GCM using `ENCRYPTION_KEY`; only public keys are ever served (`/.well-known/jwks.json`). |
| Stored secrets (service bearer tokens, container environment variables) | Same AES-256-GCM encryption. The console never returns them; environment values are write-only. |
| `ENCRYPTION_KEY`, `SESSION_SECRET_KEY` | Read from the environment, or generated on first start and written to `data/secrets.json` with mode `0600`. Rotating `ENCRYPTION_KEY` makes existing private keys and secrets unreadable. |
| Owner password | bcrypt (12 rounds). Changing it invalidates every existing console session. |
| Console session | HttpOnly cookie, `SameSite=Lax` by default, `Secure` when `SECURE_COOKIE=true`; 12-hour lifetime, 30-minute idle timeout in the UI. |
| Authorization codes | Stored as SHA-256 hashes, single use, 120-second lifetime, bound to client, redirect URI, PKCE challenge and resource. Reuse revokes every token derived from the code. |
| Refresh tokens | Rotated on every use; presenting a rotated token revokes the whole family. |
| Client secrets | Stored as SHA-256 hashes, compared in constant time, returned once at registration. |
| Redirect URIs | Exact-match against the registered list; `http` is allowed only for loopback hosts. |

## Known limitations

- **Access tokens verified offline cannot be revoked instantly.** A server that uses `JWTVerifier` keeps accepting a revoked access token until it expires (60 minutes by default). Use shorter lifetimes or FastMCP's `IntrospectionTokenVerifier` where instant revocation matters.
- **Single tenant.** Anyone who can sign in to the console is an administrator. Protect the console URL accordingly.
- **Dynamic client registration is open by default** (`OAUTH_DCR_AUTO_APPROVE=true`). Registering a client grants nothing by itself — the owner must approve every authorization on the consent screen — but set it to `false` if you want to review clients before they can even ask.
- **Plain HTTP is for local use only.** Deploy behind HTTPS (see [docs/deploy.md](docs/deploy.md)); the OAuth 2.1 specification requires it.
