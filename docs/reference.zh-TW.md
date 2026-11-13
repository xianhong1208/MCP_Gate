# 參考資料

[English](reference.md)

MCP Gate 的運作方式、常用設定、撤銷清單、管理台各頁與 HTTP API。要開始使用,請看 [README](../README.zh-TW.md)。

## 運作原理

MCP Gate 扮演 MCP 規範中的 **authorization server**;你的 MCP server 是 **resource server**,從不簽發、也不儲存 token。

| 步驟 | 誰 | 發生什麼事 |
|---|---|---|
| Discovery | client → server → MCP Gate | server 回 `401` 並在 `WWW-Authenticate` 指向它的 protected-resource metadata,裡面寫著 MCP Gate 是授權伺服器;client 再抓 `/.well-known/oauth-authorization-server`。 |
| 註冊 | client → MCP Gate | client 以自己中繼資料文件的 https 網址當 `client_id`(不需註冊,MCP Gate 會去抓那份文件),或動態註冊(`POST /oauth/register`)拿到 `client_id`。public client 用 PKCE;confidential client 拿到 secret,或登記公鑰後以簽章 JWT 認證(`private_key_jwt`,RFC 7523)。 |
| 授權 | 瀏覽器 → MCP Gate | `/oauth/authorize` 驗證請求、用 `resource` 參數綁定目標 server,顯示同意頁(記住過或受信任的 client 直接略過)。 |
| Token | client → MCP Gate | `/oauth/token` 用授權碼——檢查 PKCE、redirect URI、resource——換出 RS256 access token 與 refresh token。 |
| 驗證 | server | server 抓一次 JWKS,之後在本地驗簽章、issuer、audience、有效期與 scope。 |
| 撤銷 | 管理台或 client | 撤銷 refresh token 會讓整條鏈失效,`POST /oauth/introspect` 立刻回 `active: false`。離線驗簽的 token 會撐到過期——access token 撐滿其有效期(預設 15 分鐘),personal access token 最長可達 `pat_max_days`——除非 server 輪詢[撤銷清單](#撤銷清單)(`POST /oauth/revoked`)或改用 FastMCP 的 `IntrospectionTokenVerifier`。 |

Access token 的 claim:`iss`、`sub`、`aud`、`scope`、`client_id`、`jti`、`iat`、`exp`、`token_use`,以及——簽給已登入擁有者的 token——`email` 與 `name`。

想改「同意頁什麼時候出現」,修改 [`src/oauth/consent_policy.py`](../src/oauth/consent_policy.py);整個政策只是一個小函式。

### 名詞

| 名詞 | 意思 |
|---|---|
| Issuer | MCP Gate 的公開網址(`OAUTH_ISSUER`)。寫進每個 token 的 `iss`;client 與 server 用它做 discovery。 |
| Classic client | 在管理台手動登記、允許不用 PKCE 並套用預設 resource 的機密 client;給 OAuth 模組只認 client_id / client_secret 的平台用。 |
| private_key_jwt | 不用共享 secret 的 client 認證:client 登記 JWKS(直接貼上或提供 `jwks_uri`),每次向 token 端點請求時簽一個短效 JWT。適合 CI 工作、後端服務等機器對機器的 client。 |
| Audience | token 對哪個 MCP URL 有效(`aud` claim)。在管理台逐台設定;server 的 `JWTVerifier(audience=…)` 必須一致。 |
| Resource server | 你的 MCP server。只驗 token、從不簽發。管理台稱之為 *service*。 |
| Scope | token 在 server 上可以做什麼,例如 `mcp:tools:invoke`。管理台的全域 scope 註冊表定義共用集合;每台 server 還可以宣告只有簽給它的 token 才能帶的專屬 scope。 |
| DCR | 動態註冊(RFC 7591):client 第一次連線時自己建立 `client_id`。MCP 2026-07-28 已改建議 CIMD,但仍支援。 |
| CIMD | Client ID Metadata Document:client 的 `client_id` 是一個 https 網址,該網址以 JSON 提供它的中繼資料。不需事先註冊。 |
| PAT | Personal access token:從管理台簽的長效 access token,當一般 bearer token 使用。 |

## 設定

所有設定在 [`config/`](../config/) 底下的五個檔案,啟動時合併:

| 檔案 | 內容 |
|---|---|
| [`database.yaml`](../config/database.yaml) | `database`:連線與連線池 |
| [`oauth.yaml`](../config/oauth.yaml) | `oauth`:issuer、token 有效期、動態 client 註冊、Client ID Metadata Documents(`oauth.cimd`) |
| [`identity.yaml`](../config/identity.yaml) | `identity`:登入方式(本機、GitHub、Google)、預設管理員;`session`:管理台 session |
| [`security.yaml`](../config/security.yaml) | `rate_limit`、`security`(受信任的 proxy、cookie、允許的主機)、`cors` |
| [`system.yaml`](../config/system.yaml) | `server`、`logging`、`scheduler`(清理、保留期、健康檢查) |

同一個 key 只能寫在一個檔案:同一個 key 出現在兩個檔案,或缺少任何一個檔案,啟動時都會報錯並指出是哪些檔案。`MCP_GATE_CONFIG_DIR`(或 `main.py --config-dir`)可指向另一個放這五個檔案的目錄。所有敏感值或每台機器不同的值都是 `${VAR:-default}`,從環境變數(`.env`)讀取,所以這些檔案不含 secret,會 commit 進 repo。你可能會碰到的變數:

| 變數 | 預設 | 用途 |
|---|---|---|
| `OAUTH_ISSUER` | `http://localhost:4568` | MCP Gate 的公開網址,同時決定 MCP Gate bind 的 port。**非本機部署一定要改。** |
| `DATABASE_URL` | `sqlite:///data/mcp_gate.db` | 指向 `postgresql://…` 即改用 PostgreSQL(`uv sync --extra postgres`)。 |
| `SESSION_SECRET_KEY`、`ENCRYPTION_KEY` | 自動產生 | 未設定時存在 `secrets/secrets.json`(見 `MCP_GATE_SECRETS_DIR`)。`ENCRYPTION_KEY` 保護私鑰與儲存的 secret;請用 `python -m src.cli encryption-key rotate` 輪替,不要直接改(會讓它們無法解密)。 |
| `ENCRYPTION_KEYS_PREVIOUS` | — | 舊的加密金鑰,以逗號分隔,仍可解密它們加密過的資料。只有輪替放在環境變數裡的金鑰時才需要;輪替指令會把自己的舊金鑰記在 secrets 檔裡。 |
| `MCP_GATE_SECRETS_DIR` | `secrets` | 自動產生的 secret 所在目錄,與 `data/` 分開(目錄 `0700`、檔案 `0600`)。舊的 `data/secrets.json` 會在第一次啟動時搬過來。請和 `data/` 分開備份;Docker 請給它獨立的 volume。 |
| `MCP_GATE_SECRETS_FILE` | — | 改用指定的檔案(不會搬任何東西進去)。 |
| `ADMIN_EMAIL`、`ADMIN_PASSWORD` | — | 首次啟動直接建立擁有者帳號,不用走 `/setup`。 |
| `MCP_GATE_SETUP_TOKEN` | 自動產生 | `/setup` 要求的一次性設定碼。尚無擁有者時自動產生到 `secrets/secrets.json` 並印在 log;log 不方便看時(例如容器)可自行設定。 |
| `OAUTH_ACCESS_EXPIRE_MINUTES`、`OAUTH_REFRESH_EXPIRE_DAYS` | `15`、`30` | OAuth token 有效期(personal access token 各自設定)。 |
| `OAUTH_SIGNING_KEY_ROTATION_DAYS`、`OAUTH_SIGNING_KEY_PREPUBLISH_MINUTES` | `90`、`1440` | 簽章金鑰每 N 天自動輪替(`0` = 只在按「立即輪替」時輪替);新金鑰在開始簽發前這麼多分鐘就放進 JWKS,讓 resource server 先快取。 |
| `OAUTH_DCR_AUTO_APPROVE` | `true` | 動態註冊的 client 是否立即可用(同意頁仍是閘門),或必須在管理台核准。 |
| `OAUTH_CIMD_ENABLED`、`OAUTH_CIMD_AUTO_APPROVE` | `true`、`true` | 接受 https 網址當 `client_id`([Client ID Metadata Documents](#client-id-metadata-documents));這類 client 是否立即可用,或要在管理台核准。 |
| `OAUTH_CIMD_ALLOWED_HOSTS` | — | 以逗號分隔、允許其 `client_id` 網址的主機(`*.example.com` 代表子網域)。空白表示任何公開主機。 |
| `GITHUB_CLIENT_ID/_SECRET`、`GOOGLE_CLIENT_ID/_SECRET` | — | 啟用管理台的 GitHub / Google 登入(實驗性——已實作但尚未用真實帳號驗證)。Callback:`<issuer>/api/session/oauth/<provider>/callback`。 |
| `SECURE_COOKIE` | `false` | 走 HTTPS 時設 `true`。 |
| `CORS_ALLOWED_ORIGINS` | — | 以逗號分隔、可帶 cookie 存取管理台 API 的額外 origin。除非有其他網站必須呼叫它，否則請留空；Vite 開發伺服器不需要設定。 |
| `ALLOWED_HOSTS` | — | 以逗號分隔、除 `OAUTH_ISSUER` 的 host、`localhost` 與 IP 位址外也要回應的主機名稱（例如容器的 service 名稱）；可用 `*.suffix` 萬用字元，`*` 會關閉此檢查。其他名稱一律回 421。 |
| `ENABLE_API_DOCS` | — | `true` 會在 `/docs` 開放 OpenAPI。只讀環境變數,不在設定檔內。 |
| `MCP_GATE_CONFIG_DIR` | `config` | 放五個設定檔的目錄。 |

### 升級到 1.4

1.4 不再讀 `config/config.yaml`。如果它還在,MCP Gate 啟動時會記一筆錯誤(log 檔裡也有),並照五個檔案運作;舊檔的值會被忽略。`MCP_GATE_CONFIG` 也不再讀取,請改用指向目錄的 `MCP_GATE_CONFIG_DIR`。

| 舊 `config.yaml` 的區段 | 現在在 |
|---|---|
| `database` | `config/database.yaml` |
| `oauth`(含 `oauth.cimd`) | `config/oauth.yaml` |
| `identity`、`session` | `config/identity.yaml` |
| `rate_limit`、`security`、`cors` | `config/security.yaml` |
| `server`、`logging`、`scheduler` | `config/system.yaml` |

- **沒改過 `config.yaml`**(全部用 `.env` 設定):不用做任何事。pull 之後就有五個檔案、`config.yaml` 也會被移除;`.env` 照常可用。
- **改過 `config.yaml`**:把修改搬到對應的檔案。`uv run python scripts/split_config.py --old <你的舊 config.yaml> --force` 會幫你做:把每個區段連同註解複製到對應檔案,再載入新舊兩份設定逐欄比對是否相同。之後刪掉舊檔。
- **有設 `MCP_GATE_CONFIG`**:改成 `MCP_GATE_CONFIG_DIR=<目錄>`。`python -m db.migrate --config` 改為 `--config-dir`,`main.py --config` 也一樣。

### Client ID Metadata Documents

MCP 授權規範(2026-07-28)把動態註冊列為過時,改建議 [Client ID Metadata Documents](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/)(CIMD)。client 在某個 https 網址發布一份 JSON 文件,並以該網址當 `client_id`;MCP Gate 在 metadata 中宣告 `client_id_metadata_document_supported: true`,並在 client 第一次來到 `/oauth/authorize` 時去抓這份文件:

```json
{
  "client_id": "https://app.example.com/oauth/client-metadata.json",
  "client_name": "Example MCP Client",
  "redirect_uris": ["http://127.0.0.1/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "token_endpoint_auth_method": "none"
}
```

- 文件中的 `client_id` 必須與網址完全相同;`client_name` 與 `redirect_uris` 為必填。redirect URI 完全比對,但 loopback 的可以是任何連接埠(和已註冊的 client 相同)。
- public client(`none`)使用 PKCE。文件若宣告 `private_key_jwt`(在 `token_endpoint_auth_methods_supported` 或 `token_endpoint_auth_method` 中),就必須附上 `jwks` 或 `jwks_uri`,之後也必須以簽章 JWT 認證。共用密鑰的認證方式與 `client_secret` 一律拒絕。這類 client 不能用 `client_credentials`。
- 這類 client 會出現在 **OAuth Clients**,以網址為 id(*中繼資料文件*)。撤銷它會封鎖該網址,直到你刪除它;刪除後該網址可再被抓取。token、同意紀錄與稽核紀錄都和其他 client 一樣運作。從未取得 token 的會在 `dcr_unused_client_days` 後清除,和動態註冊的 client 相同。
- 同意頁會說明這個 client 只以網址的主機識別:名稱與連結都未經驗證。
- MCP Gate 只抓公開位址(不抓 loopback、私有網段、link-local 或雲端 metadata 服務位址),不跟隨重新導向,5 秒內最多讀 5 KB,且要求 `application/json`。文件依 `Cache-Control: max-age` 快取,介於 1 分鐘到 1 天;抓取失敗後 30 秒內不再重試。所有限制都在 `config/oauth.yaml` 的 `oauth.cimd` 底下;`OAUTH_CIMD_PRIVATE_NETWORK_HOSTS` 可放行私有網路上指定的主機(僅限開發或內網)。

動態註冊(`/oauth/register`)仍可並用;設定 `OAUTH_CIMD_ENABLED=false` 則只接受已註冊的 client。

進階:`SERVER_HOST` / `SERVER_PORT` 可覆寫 bind 位址,只在它必須和 issuer 不同時使用(例如反向代理後面只聽 `127.0.0.1`)。完整的反向代理與 HTTPS 步驟見[部署](deploy.md)。

### 撤銷清單

MCP server 是離線驗證 token,單靠自己的話,被撤銷的 token 會一直有效到過期為止:access token 是 15 分鐘,PAT 則是它的整個效期。改為定期拉撤銷清單的 server,會在一個拉取間隔內拒絕它:

1. **替 server 註冊一個 client。** 在 **OAuth Clients** → *Register*:grant type 只選 `client_credentials`、不填 redirect URI、token endpoint 驗證選 *Client secret*(POST body 或 HTTP Basic)或 `private_key_jwt`,*Resource server for* 選這個 server。既有的 client 用它的 *Resource server…* 動作,或呼叫 `PUT /api/oauth/clients/{client_id}/resource-server`,body 為 `{"service_id": "<server id>"}`。
2. **定期呼叫 `POST /oauth/revoked`**,帶上這個 client 的憑證;可加 `since=<unix 時間>` 只取較新的撤銷。回應是 `{"revoked": [{"jti", "revoked_at", "exp"}, …], "now": …}`:**只限該 server** 已撤銷、尚未過期的 access token、PAT 與 refresh token。沒綁定的 client 會拿到 `403`。同一個綁定也讓 server 能呼叫 `/oauth/introspect` 和回報 token 用量,同樣只限它自己的 token。
3. **在管理台確認。** server 頁面有一列 *Revocation feed*:已接上(附最後一次拉取時間)、已停止拉取、從未拉取,或未接上。

自己的 FastMCP server 可以用 [`examples/mcp_gate_hooks.py`](../examples/mcp_gate_hooks.py) 裡的 `MCPGateVerifier` 來拉。[Folio](https://github.com/xianhong1208/folio-rag) 與 [Morphyard](https://github.com/xianhong1208/morphyard) 已內建,設定方式見各自的 README。

## 使用管理台

| 頁面 | 在這裡做什麼 |
|---|---|
| **Dashboard** | 服務健康、token 活動、最近事件、系統狀態。 |
| **Services** | 登記或掃描 MCP server、設定 audience 與允許的 scope、宣告 server 專屬 scope、更新 tools、執行健康檢查、複製接入片段。 |
| **Tokens · Issue Token** | MCP Gate 簽發過的所有 token——OAuth 授權與 PAT——含撤銷、到期與最後使用資訊。 |
| **OAuth Clients** | 動態註冊、中繼資料文件與受信任的 client:核准、撤銷、刪除;scope 註冊表;簽章金鑰輪替。 |
| **Marketplace** | 從 catalog 部署 MCP server,或自帶 `{command, args, env}`。 |
| **Audit Logs** | 誰、何時、從哪裡、做了什麼。 |

用 email + 密碼登入,設定好之後也可用 GitHub / Google。管理台刻意設計為單租戶:登入的人就是管理員。

管理台預設為英文;頂列的語言切換可改為繁體中文,選擇會記在該瀏覽器。

## API 參考

| 類別 | 端點 |
|---|---|
| OAuth(公開) | `GET /.well-known/oauth-authorization-server` · `GET /.well-known/openid-configuration` · `GET /.well-known/jwks.json` · `POST /oauth/register` · `GET /oauth/authorize` · `GET/POST /oauth/authorize/requests/{id}[/decision]`(同意頁)· `POST /oauth/token` · `POST /oauth/revoke` · `POST /oauth/introspect` |
| Resource server | `POST /oauth/revoked`(撤銷清單)· `POST /oauth/usage`(使用回報);需綁定到該 server 的 confidential client,見[撤銷清單](#撤銷清單) |
| 管理台 session | `GET /api/session/status` · `POST /api/session/setup` · `POST /api/session/login` · `POST /api/session/logout` · `GET /api/session/me` · `PUT /api/session/me/{profile,password}` · `GET /api/session/oauth/{github,google}/{start,callback}` |
| 管理 API(需登入) | `/api/services*` · `/api/oauth/{clients,scopes,tokens,consents,keys,activity,overview,snippets}` · `/api/discovery/*` · `/api/marketplace*` · `/api/managed*` · `/api/byo-mcp*` · `/api/stats/*` · `/api/audit/*` · `/api/system/*` |
| 維運 | `GET /health` · `WS /ws/services`(服務狀態即時推播) |

用腳本呼叫管理 API 時,先 `POST /api/session/login`,之後每個請求都要帶 `mcp_session` cookie、以 `X-Session-Binding` 標頭帶上登入回應裡的 `session_binding` 值,寫入請求還要帶同源的 `Origin` 標頭。

設 `ENABLE_API_DOCS=true` 後 `/docs` 有完整 OpenAPI 參考。
