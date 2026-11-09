# Contributing

Thanks for helping improve MCP Gate. This page covers the development setup, the rules the test suite enforces, and what a pull request should contain.

## Set up a development environment

```bash
git clone https://github.com/xianhong1208/MCP_Gate.git
cd MCP_Gate
uv sync --all-groups          # runtime + dev dependencies (pytest, ruff, fastmcp)
cp .env.example .env
uv run python main.py         # API + built console on http://localhost:4568
```

For console work run Vite alongside the API:

```bash
cd frontend
npm install
npm run dev                   # http://localhost:5173, proxies /api, /oauth, /.well-known, /ws to :4568
                              # (same-origin through the proxy: no CORS entry needed for :5173)
npm run build                 # writes static/web, which the API serves in production
```

## Run the checks

```bash
uv run pytest                 # backend suite; uses temporary SQLite files, no services required
TEST_DATABASE_URL=postgresql://user:pass@localhost:5432/mcp_gate_test uv run pytest
                              # same suite on PostgreSQL; that database is WIPED, use a throwaway one
uv run ruff check src db main.py tests
cd frontend && npm run lint   # ESLint: recommended rules + React hooks, must report 0 errors
cd frontend && npm test       # node-based unit tests, including i18n key parity
cd frontend && npm run build  # must succeed with 0 errors
```

SQLite ignores the length of `VARCHAR(n)` columns and PostgreSQL enforces it, so run the PostgreSQL variant when you add a field that stores user input or remote text. CI (`.github/workflows/ci.yml`) runs both, plus ruff, the frontend checks, a check that the committed `static/web` matches a fresh build, a build and smoke test of the `mcp-runtime` image, and a dependency audit (`pip-audit` on the locked runtime dependencies, `npm audit` on the console's production dependencies). All five jobs are required checks on `dev` and `main`.

`tests/test_fastmcp_interop.py` starts a real MCP Gate and a real FastMCP server on free ports and drives FastMCP's own OAuth client through registration, consent and token exchange. It is the acceptance test for anything that touches `src/oauth/`.

## Project layout

```
main.py              application entry point and app assembly
config/              config.yaml with environment expansion
db/                  models · crud (data layer) · seed · migrate
alembic/             migration scripts (single init revision plus yours)
src/oauth/           authorization server: signing keys, grants, consent policy
src/identity/        console sign-in: passwords, sessions, GitHub / Google providers
src/api/             routers: oauth, session, services, discovery, marketplace, stats, audit
src/adapters/        the only layer allowed to import db.crud
src/discovery/       scanner, health monitor, WebSocket fan-out
src/orchestrator/    Docker-backed managed and bring-your-own MCP servers
frontend/            React console (Vite + Tailwind)
examples/            FastMCP server example
tests/               pytest suite
```

## Rules enforced by the suite

- **Layering:** `routes → adapters → db.crud`. Only `src/adapters/*` may import `db.crud`, and code under `src/api`, `src/orchestrator` and `src/discovery` never calls `db.commit()` directly (`tests/test_architecture_layering.py`).
- **i18n parity:** `frontend/src/i18n/locales/en.json` and `zh-TW.json` must contain the same keys (`frontend/tests/i18nKeys.test.mjs`). Add strings to both.
- **Argument policy:** container commands and flags pass through `src/marketplace/argv_policy.py`; tests in `tests/test_marketplace_schema.py` and `tests/test_orchestrator_flags.py` guard it.

## Change the database schema

1. Edit `db/models.py`.
2. Generate a migration: `uv run python main.py --migrate-only generate -m "describe the change"`.
3. Review the file under `alembic/versions/` (SQLite needs batch mode, which is enabled).
4. Start the app or run `uv run python main.py --migrate-only auto`; migrations apply automatically at startup.
5. `tests/test_schema_drift.py` migrates an empty database to head and fails if the result differs from `db/models.py`, so a model change without a migration (or the reverse) is caught by `uv run pytest`.

## Change the UI

The console follows the design system in `design-system/*/MASTER.md` (tokens in `frontend/tailwind.config.js` and `frontend/src/index.css`, primitives in `frontend/src/components/ui/`). Use the primitives rather than ad-hoc classes, keep one primary action per screen, and check both themes and both languages.

## Pull request checklist

- [ ] Tests added or updated for the behaviour you changed; `uv run pytest` passes.
- [ ] `uv run ruff check src db main.py tests` passes.
- [ ] `npm run lint`, `npm test` and `npm run build` pass if you touched `frontend/`.
- [ ] Documentation updated (`README.md` **and** `README.zh-TW.md`, `docs/`, `.env.example`) if behaviour or configuration changed.
- [ ] No secrets, `.env`, `data/` or screenshots committed.
- [ ] One focused change per pull request.

## Releasing

Releases are cut from `main`; feature work lands on `dev` first.

1. On `dev`, bump `[project].version` in `pyproject.toml`. It is the single source of truth: `npm run sync-version` (also run by `prebuild`) copies it into `frontend/package.json`, `npm install --package-lock-only` refreshes the lock file, and `uv lock` refreshes `uv.lock`.
2. Add the `## [x.y.z] — YYYY-MM-DD` section to `CHANGELOG.md` and rebuild `static/web` so the bundle carries the new version.
3. Open a pull request from `dev` to `main` and merge it.
4. On the merge commit: `git tag -a vx.y.z -m "MCP Gate x.y.z"` and `git push origin vx.y.z`.
5. Publish a GitHub Release for the tag; its notes mirror the CHANGELOG section.
