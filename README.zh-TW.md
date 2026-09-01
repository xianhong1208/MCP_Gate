# MCP Center

**開源的 OAuth 2.1 授權伺服器與 Model Context Protocol server 管理台。**

MCP Center 把標準化的身分驗證放在你每一台 MCP server 前面。[FastMCP](https://github.com/PrefectHQ/fastmcp) server 只要一個 `RemoteAuthProvider` 就受到保護;Claude Code、Claude Desktop、Cursor 這類 MCP client 則直接用它們內建的 OAuth 流程連上——不用自訂 token、不用驗證回呼、不用在每台 server 各寫一套驗證。

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-green.svg)](pyproject.toml)
[![OAuth 2.1](https://img.shields.io/badge/OAuth-2.1-6366f1.svg)](#運作原理)
[![Works with FastMCP](https://img.shields.io/badge/FastMCP-3.x-22c55e.svg)](https://gofastmcp.com)
[![Tests](https://img.shields.io/badge/tests-pytest-informational.svg)](CONTRIBUTING.md)

[English](README.md) · [快速開始](#快速開始) · [運作原理](#運作原理) · [設定](#設定) · [部署](docs/deploy.md) · [疑難排解](docs/troubleshooting.md) · [架構](docs/architecture.md)

```
┌──────────────────────┐   ① 401 + protected-resource metadata   ┌──────────────────────┐
│      MCP client      │ ───────────────────────────────────────▶ │  你的 FastMCP server  │
│ Claude Code / Cursor │ ◀─────────────────────────────────────── │   (resource server)   │
│  Claude Desktop / …  │   ⑤ Authorization: Bearer <JWT>          │                      │
└──────────┬───────────┘                                          └──────────┬───────────┘
           │ ② discovery + 動態註冊(DCR)                                       │ ④ 抓一次 JWKS,
           │ ③ authorize(PKCE)→ 同意頁 → code → token                         │    之後離線驗簽
           ▼                                                                 ▼
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│  MCP Center — OAuth 2.1 授權伺服器 + 管理台                                                │
│  /.well-known/oauth-authorization-server   /.well-known/jwks.json                        │
│  /oauth/register  /oauth/authorize  /oauth/token  /oauth/revoke  /oauth/introspect       │
└──────────────────────────────────────────────────────────────────────────────────────────┘
```

## 主要特色

- **標準化的授權伺服器。** 涵蓋 [MCP 規範(2025-06-18)](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)的授權要求:RFC 8414 metadata、RFC 7591 動態註冊、authorization code + PKCE(S256)、refresh token 輪替與重放偵測、RFC 7009 撤銷、RFC 7662 內省、RFC 8707 resource indicator、RFC 9207 `iss` 回應。
- **非對稱簽章、離線驗證。** RS256 金鑰,公開 JWKS、可輪替。MCP server 用公鑰在本地驗 token;MCP Center 不在請求路徑上。
- **一段設定接上 FastMCP。** `RemoteAuthProvider` + `JWTVerifier(jwks_uri, issuer, audience)` 就完成保護。token 綁定每台 server 的 audience,給 A 的 token 永遠不能打 B。
- **同意頁。** 動態註冊的 client 第一次連線要請擁有者按「允許」;可依 client + server 記住。你自己登記的 client 免同意。
- **Personal access token(PAT)。** 從管理台簽長效 bearer token 給腳本、CI 與不會走 OAuth 的 client,附上可直接貼的 `claude mcp add` 與 `mcpServers` 片段。
- **服務登錄與健康監控。** 手動登記或自動掃描 MCP server、同步 tools 列表、每 30 秒健康檢查、狀態變更經 WebSocket 即時推播。
- **Marketplace 與 orchestrator。** 從 catalog 一鍵部署 MCP server;或貼一段標準的 `{command, args, env}`,由 MCP Center 容器化並掛上 HTTP bridge(需要 Docker)。
- **零設定啟動。** 預設 SQLite、首次啟動自動產生密鑰、瀏覽器內的擁有者帳號設定精靈。PostgreSQL 與 GitHub / Google 登入只差幾個環境變數。

## 安裝 MCP Center

前置需求:

- Python 3.11 以上與 [uv](https://docs.astral.sh/uv/)。
- Docker——只有使用 Marketplace 或自帶 MCP server 時才需要。
- Node.js 18 以上——只有要改管理台前端時才需要。

```bash
git clone https://github.com/xianhong1208/MCP_Center.git
cd MCP_Center
uv sync
cp .env.example .env      # 可省略:所有設定都有可用的預設值
uv run python main.py
```

啟動畫面會告訴你每樣東西在哪裡:

```
╔══════════════════════════════════════════════════════╗
║   MCP Center — OAuth 2.1 AS for your MCP servers     ║
╚══════════════════════════════════════════════════════╝
  Version:    1.0.0
  Address:    http://0.0.0.0:4568
  Issuer:     http://localhost:4568
  Database:   sqlite:///data/mcp_center.db
  Metadata:   http://localhost:4568/.well-known/oauth-authorization-server
  JWKS:       http://localhost:4568/.well-known/jwks.json
  No admin account yet → open http://localhost:4568/setup to create the owner
```

打開 <http://localhost:4568/setup> 建立擁有者帳號,就進入管理台了。

> **不是部署在 `localhost`?** 在簽發任何 token 之前,先把 `OAUTH_ISSUER` 設成公開網址(例如 `https://mcp.example.com`)。它會寫進每個 token 的 `iss` 與 discovery 文件,MCP server 和 client 都必須連得到它;之後更改會讓所有 token 失效。見[部署](docs/deploy.md)。

## 快速開始

順序很重要:**先登記 server**。MCP Center 只替它認得的 audience 簽 token;client 要求一台未登記的 server 會得到 `invalid_target`。

### 1. 在管理台登記 server

打開 **Services → Register Service**,輸入 server 的 host、port 與 path(path 是 MCP 端點,預設 `/mcp`)。server 的 *audience*——token 對誰有效——預設就是它的 MCP URL,例如 `http://127.0.0.1:8000/mcp`。

### 2. 保護 FastMCP server

服務頁的 **Integration** 面板會替你產生這段:

```python
from fastmcp import FastMCP
from fastmcp.server.auth import RemoteAuthProvider
from fastmcp.server.auth.providers.jwt import JWTVerifier
from pydantic import AnyHttpUrl

auth = RemoteAuthProvider(
    token_verifier=JWTVerifier(
        jwks_uri="http://localhost:4568/.well-known/jwks.json",
        issuer="http://localhost:4568",
        audience="http://127.0.0.1:8000/mcp",   # 必須和管理台上的 audience 一致
    ),
    authorization_servers=[AnyHttpUrl("http://localhost:4568")],
    base_url="http://127.0.0.1:8000",
)

mcp = FastMCP(name="demo", auth=auth)

@mcp.tool
def hello(name: str) -> str:
    return f"Hello, {name}!"

mcp.run(transport="http", host="127.0.0.1", port=8000)
```

FastMCP 會自動提供 `/.well-known/oauth-protected-resource`,把 client 指向 MCP Center。完整可執行的版本——含回傳 token 內容的 `whoami` 工具——在 [`examples/fastmcp_server.py`](examples/fastmcp_server.py)。

### 3. 連上 client

**支援 OAuth 的 client**(Claude Code、Claude Desktop、Cursor、FastMCP `Client`)什麼都不用先做:

```bash
claude mcp add --transport http demo http://127.0.0.1:8000/mcp
```

第一次使用時 client 會自己向 MCP Center 註冊,並在瀏覽器開啟同意頁。頁面顯示 client 名稱、目標 server、要求的 scope(預設 `mcp:tools:read`、`mcp:tools:invoke`、`mcp:resources:read`、`mcp:prompts:read`)與「記住這個決定」核取方塊。按 **Allow**,client 就拿到 token,之後自己 refresh。

```python
from fastmcp import Client

async with Client("http://127.0.0.1:8000/mcp", auth="oauth") as client:
    print(await client.list_tools())
```

**其他情況**——腳本、CI、不支援 OAuth 的 client——在管理台的 **Issue Token** 簽一個 personal access token:

```bash
claude mcp add --transport http demo http://127.0.0.1:8000/mcp \
  --header "Authorization: Bearer <PERSONAL_ACCESS_TOKEN>"
```

```python
from fastmcp import Client
from fastmcp.client.auth import BearerAuth

async with Client("http://127.0.0.1:8000/mcp", auth=BearerAuth("<PERSONAL_ACCESS_TOKEN>")) as client:
    print(await client.list_tools())
```

### 4. 驗證

```bash
curl -s http://localhost:4568/.well-known/oauth-authorization-server | python -m json.tool | head
claude mcp list          # 預期:  demo: http://127.0.0.1:8000/mcp (HTTP) - ✓ Connected
```

在 Claude Code 裡呼叫範例 server 的 `whoami` 工具,它會回傳到達 server 的那張 token 的 subject、client 與 scope:

```json
{"subject": "9b76a95d-…", "client_id": "mcpc_6c68…", "scopes": ["mcp:prompts:read", "mcp:resources:read", "mcp:tools:invoke", "mcp:tools:read"], "email": "you@example.com"}
```

## 運作原理

MCP Center 扮演 MCP 規範中的 **authorization server**;你的 MCP server 是 **resource server**,從不簽發、也不儲存 token。

| 步驟 | 誰 | 發生什麼事 |
|---|---|---|
| Discovery | client → server → MCP Center | server 回 `401` 並在 `WWW-Authenticate` 指向它的 protected-resource metadata,裡面寫著 MCP Center 是授權伺服器;client 再抓 `/.well-known/oauth-authorization-server`。 |
| 註冊 | client → MCP Center | client 動態註冊(`POST /oauth/register`)拿到 `client_id`。public client 用 PKCE;confidential client 拿到 secret。 |
| 授權 | 瀏覽器 → MCP Center | `/oauth/authorize` 驗證請求、用 `resource` 參數綁定目標 server,顯示同意頁(記住過或受信任的 client 直接略過)。 |
| Token | client → MCP Center | `/oauth/token` 用授權碼——檢查 PKCE、redirect URI、resource——換出 RS256 access token 與 refresh token。 |
| 驗證 | server | server 抓一次 JWKS,之後在本地驗簽章、issuer、audience、有效期與 scope。 |
| 撤銷 | 管理台或 client | 撤銷 refresh token 會讓整條鏈失效,`POST /oauth/introspect` 立刻回 `active: false`。離線驗簽的 access token 會撐到過期,所以請保持短效(預設 60 分鐘),需要即時撤銷的 server 改用 FastMCP 的 `IntrospectionTokenVerifier`。 |

Access token 的 claim:`iss`、`sub`、`aud`、`scope`、`client_id`、`jti`、`iat`、`exp`、`token_use`,以及——簽給已登入擁有者的 token——`email` 與 `name`。

想改「同意頁什麼時候出現」,修改 [`src/oauth/consent_policy.py`](src/oauth/consent_policy.py);整個政策只是一個小函式。

### 名詞

| 名詞 | 意思 |
|---|---|
| Issuer | MCP Center 的公開網址(`OAUTH_ISSUER`)。寫進每個 token 的 `iss`;client 與 server 用它做 discovery。 |
| Classic client | 在管理台手動登記、允許不用 PKCE 並套用預設 resource 的機密 client;給 OAuth 模組只認 client_id / client_secret 的平台用。 |
| Audience | token 對哪個 MCP URL 有效(`aud` claim)。在管理台逐台設定;server 的 `JWTVerifier(audience=…)` 必須一致。 |
| Resource server | 你的 MCP server。只驗 token、從不簽發。管理台稱之為 *service*。 |
| Scope | token 在 server 上可以做什麼,例如 `mcp:tools:invoke`。管理台的 scope 註冊表定義整個集合。 |
| DCR | 動態註冊(RFC 7591):client 第一次連線時自己建立 `client_id`。 |
| PAT | Personal access token:從管理台簽的長效 access token,當一般 bearer token 使用。 |

## 設定

所有設定在 [`config/config.yaml`](config/config.yaml),敏感值從環境變數(`.env`)讀取。你可能會碰到的:

| 變數 | 預設 | 用途 |
|---|---|---|
| `OAUTH_ISSUER` | `http://localhost:4568` | MCP Center 的公開網址,同時決定 MCP Center bind 的 port。**非本機部署一定要改。** |
| `DATABASE_URL` | `sqlite:///data/mcp_center.db` | 指向 `postgresql://…` 即改用 PostgreSQL(`uv sync --extra postgres`)。 |
| `SESSION_SECRET_KEY`、`ENCRYPTION_KEY` | 自動產生 | 未設定時存在 `data/secrets.json`。`ENCRYPTION_KEY` 保護私鑰與儲存的 secret;更換會讓它們無法解密。 |
| `ADMIN_EMAIL`、`ADMIN_PASSWORD` | — | 首次啟動直接建立擁有者帳號,不用走 `/setup`。 |
| `OAUTH_ACCESS_EXPIRE_MINUTES`、`OAUTH_REFRESH_EXPIRE_DAYS` | `60`、`30` | token 有效期。 |
| `OAUTH_DCR_AUTO_APPROVE` | `true` | 動態註冊的 client 是否立即可用(同意頁仍是閘門),或必須在管理台核准。 |
| `GITHUB_CLIENT_ID/_SECRET`、`GOOGLE_CLIENT_ID/_SECRET` | — | 啟用管理台的 GitHub / Google 登入(實驗性——已實作但尚未用真實帳號驗證)。Callback:`<issuer>/api/session/oauth/<provider>/callback`。 |
| `SECURE_COOKIE` | `false` | 走 HTTPS 時設 `true`。 |
| `ENABLE_API_DOCS` | — | `true` 會在 `/docs` 開放 OpenAPI。只讀環境變數,不在 `config.yaml` 內。 |

進階:`SERVER_HOST` / `SERVER_PORT` 可覆寫 bind 位址,只在它必須和 issuer 不同時使用(例如反向代理後面只聽 `127.0.0.1`)。完整的反向代理與 HTTPS 步驟見[部署](docs/deploy.md)。

## 使用管理台

| 頁面 | 在這裡做什麼 |
|---|---|
| **Dashboard** | 服務健康、token 活動、最近事件、系統狀態。 |
| **Services** | 登記或掃描 MCP server、設定 audience 與允許的 scope、更新 tools、執行健康檢查、複製接入片段。 |
| **Tokens · Issue Token** | MCP Center 簽發過的所有 token——OAuth 授權與 PAT——含撤銷、到期與最後使用資訊。 |
| **OAuth Clients** | 動態註冊與受信任的 client:核准、撤銷、刪除;scope 註冊表;簽章金鑰輪替。 |
| **Marketplace** | 從 catalog 部署 MCP server,或自帶 `{command, args, env}`。 |
| **Audit Logs** | 誰、何時、從哪裡、做了什麼。 |

用 email + 密碼登入,設定好之後也可用 GitHub / Google。管理台刻意設計為單租戶:登入的人就是管理員。

管理台預設為英文;頂列的語言切換可改為繁體中文,選擇會記在該瀏覽器。

## API 參考

| 類別 | 端點 |
|---|---|
| OAuth(公開) | `GET /.well-known/oauth-authorization-server` · `GET /.well-known/openid-configuration` · `GET /.well-known/jwks.json` · `POST /oauth/register` · `GET /oauth/authorize` · `GET/POST /oauth/authorize/requests/{id}[/decision]`(同意頁)· `POST /oauth/token` · `POST /oauth/revoke` · `POST /oauth/introspect` |
| 管理台 session | `GET /api/session/status` · `POST /api/session/setup` · `POST /api/session/login` · `POST /api/session/logout` · `GET /api/session/me` · `PUT /api/session/me/{profile,password}` · `GET /api/session/oauth/{github,google}/{start,callback}` |
| 管理 API(需登入) | `/api/services*` · `/api/oauth/{clients,scopes,tokens,consents,keys,activity,overview,snippets}` · `/api/discovery/*` · `/api/marketplace*` · `/api/managed*` · `/api/byo-mcp*` · `/api/stats/*` · `/api/audit/*` · `/api/system/*` |
| 維運 | `GET /health` · `WS /ws/services`(服務狀態即時推播) |

設 `ENABLE_API_DOCS=true` 後 `/docs` 有完整 OpenAPI 參考。

## 文件

- [反向代理與 HTTPS 部署](docs/deploy.md)
- [疑難排解](docs/troubleshooting.md)
- [架構](docs/architecture.md)
- [安全政策](SECURITY.md)
- [貢獻與開發環境](CONTRIBUTING.md)
- [變更紀錄](CHANGELOG.md) · [藍圖](ROADMAP.md)

(以上文件為英文。)

## 貢獻

歡迎 issue 與 pull request。開發環境、CI 守住的分層規則與 PR 檢查清單見 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 授權

[MIT](LICENSE)
