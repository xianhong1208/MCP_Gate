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
| `SESSION_SECRET_KEY`、`ENCRYPTION_KEY` | 自動產生 | 未設定時存在 `secrets/secrets.json`(見 `MCP_GATE_SECRETS_DIR`)。`ENCRYPTION_KEY` 保護私鑰與儲存的 secret;請用 `python -m src.cli encryption-key rotate` 輪替,不要直接改(會讓它們無法解密)。金鑰打不開資料庫裡的簽章金鑰,或既有資料庫找不到金鑰時,會拒絕啟動([疑難排解](troubleshooting.md#server))。 |
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

### 動態用戶端註冊(DCR)

MCP 2026-07-28 把動態用戶端註冊(RFC 7591)列為棄用,改用 [Client ID Metadata Documents](#client-id-metadata-documents)。MCP Gate 的 `/oauth/register` 照常可用,也仍列在 metadata(`registration_endpoint`)裡,給還沒改用 metadata document 的 client;新版 client 看到 server 宣告 `client_id_metadata_document_supported`(MCP Gate 有宣告)就會優先用 metadata document。啟動後第一個經由 DCR 註冊的 client 會留下一行警告說明此事,**OAuth Clients** 頁也會顯示有多少個啟用中的 client 是這樣註冊的。

- **`application_type`。** 規範要求 client 註冊時送出 `application_type`(桌面 app、CLI 和 loopback redirect 用 `native`;遠端瀏覽器 app 用 `web`),因為 OpenID provider 會依它限制 redirect URI。MCP Gate 不是 OpenID provider:註冊與 metadata document 中的 `native`、`web` 都接受,其他值以 `invalid_client_metadata`(metadata document 則是 `invalid_client`)拒絕,不對 redirect URI 加任何額外規則。這個值不會被儲存。

### MCP 協定版本

MCP Gate 的掃描、健康檢查、*Refresh from server* 與 *Inspect as* 兩個世代的協定都會講:

- **2026-07-28(無狀態)。** MCP Gate 先送 `server/discover`,協定版本、client 資訊與 capabilities 放在 `_meta`,並帶 `MCP-Protocol-Version` / `Mcp-Method` header。會回答它的 server 就不需要握手也沒有 session:每次重新整理只送一個 `tools/list`。
- **2024-11-05 到 2025-11-25(`initialize` 握手)。** 其他任何回應 —— 像「missing session id」的 `400`、`404`、`405`、JSON-RPC「method not found」—— 依規範的向下相容規則都代表舊版 server:MCP Gate 改用 `initialize`(提出 2025-11-25,由 server 選版本),之後的請求帶 session id 與協商出的 `MCP-Protocol-Version`。
- 新世代的錯誤(`-32022` 不支援的版本、`-32020` header 不一致、`-32021` 缺少 capability)絕不會讓它退回舊流程:不支援的版本會改用 server 列出的版本重試,否則回報「沒有共同的協定版本」。
- MCP Gate 執行期間會依 server URL 記住它屬於哪個世代,失效時再重新探測,所以升級到 2026-07-28(或退回舊版)的 server 會在下一次檢查時被發現。
- Server 頁面會顯示它最近一次回應所用的協定(例如 *MCP 版本 2026-07-28 · 無狀態*),MCP Gate 啟動後第一次健康檢查、掃描或重新整理之後才會出現;只保存在記憶體。`POST /api/services/{id}/health-check`、`GET /api/services/{id}`(`health.protocol_version`、`health.protocol_era`、`health.protocol_seen_at`)與 `POST /api/discovery/verify` 也會回報。

你自己的 FastMCP server 不需要改:FastMCP 4 在同一個 endpoint 同時提供兩個世代,`MCPGateVerifier` 與 `MCPGateToolPinning` 在兩者下都能運作,`stateless_http=True` 也一樣。

### 撤銷清單

MCP server 是離線驗證 token,單靠自己的話,被撤銷的 token 會一直有效到過期為止:access token 是 15 分鐘,PAT 則是它的整個效期。改為定期拉撤銷清單的 server,會在一個拉取間隔內拒絕它:

1. **替 server 註冊一個 client。** 在 **OAuth Clients** → *Register*:grant type 只選 `client_credentials`、不填 redirect URI、token endpoint 驗證選 *Client secret*(POST body 或 HTTP Basic)或 `private_key_jwt`,*Resource server for* 選這個 server。既有的 client 用它的 *Resource server…* 動作,或呼叫 `PUT /api/oauth/clients/{client_id}/resource-server`,body 為 `{"service_id": "<server id>"}`。
2. **定期呼叫 `POST /oauth/revoked`**,帶上這個 client 的憑證;可加 `since=<unix 時間>` 只取較新的撤銷。回應是 `{"revoked": [{"jti", "revoked_at", "exp"}, …], "now": …}`:**只限該 server** 已撤銷、尚未過期的 access token、PAT 與 refresh token。沒綁定的 client 會拿到 `403`。同一個綁定也讓 server 能呼叫 `/oauth/introspect` 和回報 token 用量,同樣只限它自己的 token。
3. **在管理台確認。** server 頁面有一列 *Revocation feed*:已接上(附最後一次拉取時間)、已停止拉取、從未拉取,或未接上。

自己的 FastMCP server 可以用 [`examples/mcp_gate_hooks.py`](../examples/mcp_gate_hooks.py) 裡的 `MCPGateVerifier` 來拉。[Folio](https://github.com/xianhong1208/folio-rag) 與 [Morphyard](https://github.com/xianhong1208/morphyard) 已內建,設定方式見各自的 README。

### Tool 釘選與核准

server 列出的每個 tool 都以其定義的 SHA-256 釘選;新的或變更過的定義要等管理員核准,才算已核准。

- **雜湊的範圍。** 取 `tools/list` 回傳的 tool 物件,只留 `name`、`title`、`description`、`inputSchema`、`outputSchema` 與 `annotations`(`_meta`、`icons` 等其他欄位不算)。缺少或為 `null` 的欄位直接略過,所以兩者雜湊相同;空字串或空物件則算是值。其餘部分序列化為 JSON:每一層的 key 排序、不含空白、非 ASCII 字元以 UTF-8 原樣寫出(不轉成 `\uXXXX`),再以 UTF-8 編碼取雜湊。定義在 `src/tool_pinning/hashing.py`;`tests/fixtures/tool_hash_vectors.json` 有一組標準向量,其他實作都必須算出相同結果。
- **狀態。** tool 的每一份定義都保留為一個版本,帶有雜湊與狀態:*已核准*、*待核准* 或 *已拒絕*。重新整理(*從 Server 重新整理*、掃描)時,新 tool 或定義變更會新增一個待核准版本,舊版本全部保留,管理台因此能拿變更與已核准的版本比對。server 不再列出的 tool 會標為 *已不再列出*,不會刪除;之後再出現時歷史仍在。用 *Inspect as* 以其他身分重新整理也一樣:該身分看不到的 tool 只會被標記,不會失去核准。
- **第一次核准。** 升級到 1.5 時,所有已存的 tool 都會被核准為基準(`decided_by: upgrade`)。這些資料當初沒有存 `title`、`outputSchema` 與 `annotations`,所以升級後第一次重新整理列出該 tool 時,只要 `name`、`description` 與 `inputSchema` 沒變,就以完整定義補齊基準;這三者有變則和其他變更一樣待核准。之後才登記的 server,所有 tool 一開始都是待核准,管理台只在這第一份清單上提供 **全部核准**。之後每個新的或變更的 tool 都在自己的卡片上核准或拒絕,卡片會列出每個變更欄位的逐行差異(新 tool 則列出完整定義)。
- **決定。** 核准與拒絕都以雜湊指定版本,管理員決定的就是畫面上那一份定義。已拒絕的版本之後仍可核准,已核准的也可以用拒絕撤回。每次核准、拒絕與 *全部核准* 都記在稽核日誌(`tool_approve`、`tool_reject`、`tool_approve_all`)。儀表板與服務列表會顯示有幾個 tool 在等。
- **API。** `GET /api/services/{id}/tools` 列出 tool,含 `state`、`hash`、`removed_at`、`versions` 與 `approved_version`(待核准變更要比對的版本),另有 `pending_count` 與 `first_review`。`POST /api/services/{id}/tools/{tool_id}/approve` 與 `…/reject` 接受 `{"hash": "<64 位十六進位>"}`;`POST /api/services/{id}/tools/approve-all` 接受 `{"hashes": [...]}`,一旦該服務有任何東西被核准過,就回 `409 tools.approve_all_not_first`。

MCP Gate 只記錄這些決定;它不在 client 與 server 之間,所以單靠它無法隱藏未核准的 tool。執行釘選 middleware 的 server 會隱藏(見下一節);其他 server 只會在管理台顯示狀態,client 仍看得到所有 tool。

### Poisoning 掃描

呼叫 tool 的模型會讀它的說明與 schema,所以 server 可以把指令藏在裡面。每一份釘選的定義也會經過內建規則檢查(不用模型、不連網;`src/tool_pinning/scan.py`),結果顯示在核准卡片上,以及已核准 tool 的旁邊。**發現永遠不會擋下任何東西**:未核准的 tool 本來就會被隱藏(在執行 middleware 的 server 上),決定仍由管理員做。

- **掃描範圍。** 雜湊欄位(`name`、`title`、`description`、`inputSchema`、`outputSchema`、`annotations`)裡的每個字串與物件 key,遞迴進去,所以藏在參數說明或 `default` 裡的指令也找得到。工作量有上限:每份定義 2,000 個字串、200,000 字元、32 層、200 項發現;超過時會有一項 `scan-truncated`。比對前先做 NFKC 正規化(全形字母變成 ASCII)、把常見的西里爾與希臘相似字母換成拉丁字母、大小寫折疊,並去掉不可見字元,所以 `ig<U+200B>nore` 仍會讀成 `ignore`。位移量指向原始文字。
- **規則**(嚴重度 `high`、`warning` 或 `info`):

  | 規則 | 標示什麼 | 嚴重度 |
  |---|---|---|
  | `invisible-characters` | 零寬字元、雙向控制字元(U+202A–U+202E、U+2066–U+2069)、Unicode tag 字元(U+E0000–U+E007F,會解碼並顯示為 *hidden text*)、補充變體選擇符、韓文填充字元。兩個非 ASCII 字元之間的單一 joiner(emoji 序列、印度與阿拉伯文字)不算。 | 雙向控制、tag、變體選擇符、連續 3 個以上,或夾在大部分字母之間(合併為一項)為 high;其餘 warning |
  | `instruction-phrase` | 「ignore / disregard previous instructions」、「do not tell the user」、「without telling the user」、`<IMPORTANT>`、`<system>`、`[INST]`、chat template 標記,以及中文變體(忽略之前的指示、不要告訴使用者、对用户保密 …) | high |
  | | 「before using this tool」、HTML 註解、「do not mention that」、「new instructions:」、「system prompt:」、「you are now a …」、使用這個工具之前 | warning |
  | | 「you must」、「very important」、你必須 | info |
  | `tool-mention` | 提到 MCP Gate 裡登記的 tool 名稱(任何 server),但不是自己。只找含 `_`、`-`、`.` 或 camelCase 且至少 4 字元的名稱,所以單獨的「search」或「fetch」不會命中。 | 另一台 server 有這個 tool 時 warning(shadowing);只有自己這台有時 info |
  | `sensitive-data` | `~/.ssh`、`id_rsa` 等金鑰檔、`.aws/credentials`、`/etc/passwd`、`.netrc`、`.npmrc`、`.git-credentials`、`.kube/config`、`.env`、`mcp.json`、`claude_desktop_config.json`、`.cursor/` | 附近有「read / send / include / pass …」時 high;否則 warning |
  | | 「API key」、「private key」、「credentials」、「password」、私鑰、密碼 … 出現在「read / send / include / pass …」附近 | warning |
  | `url` | 任何網址 | info;IP 位址、非 loopback 的 `http` / `ftp` / `ws`、短網址為 warning,參數名稱像目的地(webhook、callback、report、upload、backup …)的 `default` / `const` / `enum` / `examples` 裡的網址也是 warning;上述網址出現在這些值裡,或在「send / upload / post … to」之後為 high |
  | `encoded-blob` | 60 字元以上的 base64(大小寫加數字混合)或 64 字元以上的 hex | 能解碼成可讀文字時 high(會顯示);否則 warning(base64)或 info(hex,例如 SHA-256) |
  | `long-text` | 說明超過 4,000 字元(info),或 schema 字串超過 1,000 字元(warning) | info / warning |
  | `scan-truncated` | 達到工作量上限 | info |

- **被標示** 指至少有一項 `warning` 或 `high`;只有 `info` 算是提示。儀表板與服務列表會計算被標示的待核准 tool(「2 個待核准,1 個被標示」)。
- **卡片上。** 發現依規則分組,附簡短說明與命中的文字(不可見字元以方框 `U+XXXX` 顯示),命中的文字在差異裡也會標亮。核准帶有 `high` 發現的定義時會跳出一次確認,列出發現;其他情況一鍵即可,拒絕也是。每次核准或拒絕的稽核紀錄都記下當時顯示的發現(`details.findings`:各嚴重度的數量與規則 id,另有 `scan_rules_version`);*全部核准* 則逐個 tool 記錄。
- **不儲存。** 發現在讀取 tool 清單時才計算(每份定義在記憶體快取:第一次約 1 ms,之後幾微秒),所以規則改進後,舊版本也會重新檢查;API 的 `scan_rules_version` 標明是哪一版規則算的。
- **API。** `GET /api/services/{id}/tools` 的每個版本都有 `findings`:`[{rule, severity, path, start, end, match, excerpt, detail}]`(`path` 指向正規化後的定義,例如 `inputSchema.properties.url.default`;`start` / `end` 是該字串中的 code point 位移;`excerpt` 把不可見字元寫成 `<U+XXXX>`)。每個 tool 另有目前定義的 `findings` 與 `flagged`;回應另加 `flagged_count` 與 `scan_rules_version`,服務的回應另加 `tools_flagged`。
- **抓不到的。** 規則比對的是用字與字元,不是意圖:換句話說的指令、其他語言、拆在不同欄位的指令,或行為與說明不符的 tool 都會通過。見 [SECURITY.md](../SECURITY.md#known-limitations)。請閱讀定義;掃描只是指出該先看哪裡。

### Server 上的 tool 核准

[`examples/mcp_gate_hooks.py`](../examples/mcp_gate_hooks.py) 裡的 `MCPGateToolPinning` 是一個 FastMCP middleware,在 server 本身執行核准。它需要和撤銷清單相同的 resource server client(見上文),與 `MCPGateVerifier` 並用:`FastMCP(..., middleware=[MCPGateToolPinning(verifier)])`。完整的 server 見 [`examples/fastmcp_server_hooks.py`](../examples/fastmcp_server_hooks.py)。

- **`tools/list`** 會為 server 的每個 tool 計算雜湊(定義同上;範例檔自帶一份實作,並能算出標準向量),只列出已核准的。**`tools/call`** 會為被呼叫的 tool 計算雜湊,未核准就拒絕,回覆 `Tool '<name>' is not available on this server.`,和不存在的 tool 一樣;原因只寫進 server 的 log。
- **回報。** MCP Gate 還不認得的定義會立刻送到 `POST /oauth/tool-report`,不必等重新整理就會在管理台顯示為待核准(標示 *由 server 回報*)。所以說明一改,server 下一次 `tools/list` 就會隱藏它,幾秒後管理台就看得到待核准。
- **Policy。** 每 `poll_interval` 秒(預設 15)讀一次 `POST /oauth/policy`。MCP Gate 自己的請求(重新整理、掃描、健康檢查、*Inspect as*)所用的短效 token 帶有 `mcp_gate_probe` claim;middleware 對它們列出所有 tool,不論是否核准,因此重新整理記錄的是真正的清單,不會把被隱藏的 tool 標成已不再列出。帶這種 token 的呼叫仍會被拒絕。
- **連不到 MCP Gate 時**,繼續使用最後一次收到的清單。它也會寫進 `cache_file`(預設為工作目錄下的 `mcp_gate_policy.json`;以原子方式寫入、權限 600;設 `None` 則只放記憶體),所以 MCP Gate 停機時重啟 server 也還在。為其他 issuer、audience 或雜湊版本寫的快取會被忽略;有設 `max_cache_age` 時,超過該秒數的也一樣。MCP Gate 恢復回應後,它的清單會取代快取。
- **從未收到清單**(第一次啟動時 MCP Gate 沒開、也沒有可用的快取):所有 tool 都隱藏且不能呼叫,並有一行 log 說明原因。設 `fail_open=True` 則在收到第一份清單前列出並執行所有 tool。
- **存取規則(1.6)。** middleware 輪詢時帶 `features=rules1`,MCP Gate 就會一併回傳這台 server 的 [tool 存取規則](#tool-存取規則)(格式 2);middleware 以自帶的評估器(`evaluate_access`,能算出標準向量)對呼叫者已驗證的 token(`jti`、`client_id`、`sub`、`scope` claim)檢查每個已核准的 tool。`tools/list` 時,這個 token 永遠不能呼叫的 tool(`hidden`:拒絕規則、不在限定規則內、server 要求 scope 而 tool 沒有)不會列出;多一個 scope 就能用的 tool(`needs_scope`)會列出。`tools/call` 時,隱藏的 tool 和不存在的 tool 一樣被拒絕;`needs_scope` 的 tool 則回覆 tool 錯誤 `Tool '<name>' requires the scope '<challenge>', which …`。前面再加上 [`MCPGateScopeGate`](#追加授權) 時,同樣的呼叫改為收到 HTTP `403 insufficient_scope` 追加授權要求。過期的規則到了 `expires_at` 就不再套用,不必等輪詢。MCP Gate 的 probe token 仍然看得到所有 tool。
- **規則與快取。** 規則和核准清單一起保存與快取(快取格式 2),所以連不到 MCP Gate 時,最後收到的規則會繼續套用,重啟後也一樣;從未收到則如上所述全部隱藏。為其他規則版本寫的快取會被忽略;1.5 middleware 寫的格式 1 快取只當作核准清單讀取。無法完整套用的回應(其他格式或規則版本、格式錯誤的 policy)會整份拒絕,繼續沿用先前的 policy。比 1.6 舊的 MCP Gate 回應格式 1:此時只執行核准,啟動 log 會寫 "no access rules"。
- **管理台。** server 頁面有一列 *Tool approvals*,和撤銷清單那列一樣:由 server 執行(附最後一次輪詢時間)、已停止輪詢、從未輪詢,或未執行。middleware 輪詢過之後,下方會顯示**存取規則已執行**,或是**存取規則未執行 — 請更新 middleware**:表示這台 server 有 resource server 上次輪詢時沒有宣告 `rules1`(1.5 的 middleware 不管規則,會把所有已核准的 tool 列給每個 token);若這台 server 有規則、有 scope 的 tool 或設了*必須有 scope*,會以警告樣式顯示。待核准 tool 的審核卡片會說明這台 server 是否執行核准。

給其他實作參考的 feed 與回報格式(form-encoded `POST`,驗證方式同 `/oauth/revoked`;只限呼叫者自己的 server):

- `POST /oauth/policy`(可帶 `etag` 與 `features`)回應 `{"format": 1, "hash_version": 1, "audience", "service_id", "tools": {"approved": [...], "pending": [...], "rejected": [...]}, "rules": [], "unchanged": false, "etag", "now"}`,每個清單都是 64 位十六進位雜湊。其他雜湊都算未知:隱藏並回報。不認得的欄位請忽略。帶上手上的 `etag`,若沒有變化就只回 `{"unchanged": true, "etag", "now"}`。server 被停用或刪除時,所有清單都是空的。
- **格式 2。** `features` 是以空白或逗號分隔、說明你的實作會執行哪些功能的清單;MCP Gate 會存在 client 上(`policy_features`,小寫、已知的排前面、最多 64 字元),並顯示在管理台。帶 `rules1` 時回應格式 2:同樣的欄位再加上 `"rules_version": 1`、`"unscoped_tools": "allow" | "require"`、`"tool_scopes": {"<tool>": {"any_of": [...], "challenge": "<scope>"}}` 與 `"rules": [{"id", "effect", "subject": {"kind": "pat" | "client" | "user", "id"}, "tools": [...] | ["*"], "expires_at": <unix 秒> | null}]`:正是評估器的輸入(見 [Tool 存取規則](#tool-存取規則)),只含未過期的規則,群組已展開成 `user` 規則。etag 涵蓋這些內容,所以規則、tool 的 scope、*必須有 scope*、群組成員有任何變動或刪除 scope,都會在 server 下一次輪詢時送到;只有規則變動時,格式 1 的回應不會改變。沒有 `rules1` 就維持格式 1,和 1.5 相同。格式 2 的回應要嘛整份套用、要嘛完全不用:不認得的 `rules_version` 不得套用(沿用先前的 policy),不認得的規則 `effect` 視為拒絕它列出的 tool。
- `POST /oauth/tool-report`,`tools` 是 `tools/list` 回傳格式的 tool 物件 JSON 陣列(最多 200 個、body 最大 2 MiB、每個 client 每分鐘 30 次、每份定義最大 64 KiB)。MCP Gate 會自己為每份定義計算雜湊:一併送來的 `hash` 只拿來比對,不同的會列在 `hash_mismatch`。回應是 `{"recorded": [{"name", "hash", "state", "new"}], "invalid": [{"index", "name", "reason"}], "hash_mismatch": [...]}`。回報和重新整理走同一套規則,只是它沒提到的 tool 不受影響。新的定義會以 `tool_report` 記入稽核日誌,執行者是該 resource server。

### 1.6 的 tool 存取控制:各部分如何搭配

1.6 決定誰可以呼叫 server 的哪個 tool。MCP Gate 從不在請求的路徑上:它儲存並評估 policy,透過 policy feed 送給每台 server,再由 server 用自己那份評估器執行。細節在後面幾節([Tool 存取規則](#tool-存取規則)、[追加授權](#追加授權),以及 [Server 上的 tool 核准](#server-上的-tool-核准) 裡的 feed 格式)。這一節跟著一次變更,從管理台一路走到被拒絕的呼叫。

1. **管理員設定 policy**:在 server 的 *存取控制* 分頁、*工具組合* 與 *群組* 頁,或透過 API。把 tool 放進 scope(放了 tool 的 scope 就是工具組合);`deny` 與 `only` 規則指定一個個人存取 token、一個 OAuth client、一位使用者或一個群組;`unscoped_tools` 決定不在任何 scope 裡的 tool 是否允許。每次變更都會記入稽核日誌。
2. **MCP Gate 組出這台 server 的 policy。** 它去掉過期的規則,並把每條群組規則展開成每位成員一條 `user` 規則,規則 id 不變、成員依序排列(`expand_groups`;由 `tests/fixtures/tool_policy_vectors.json` 裡的 `expansions` 釘住)。結果正是評估器的輸入;`GET /api/services/{id}/access` 以 `policy` 顯示它。
3. **Policy feed 把它送出去。** server 的 middleware 每 15 秒帶 `features=rules1` 輪詢 `POST /oauth/policy`,收到**格式 2**:已核准、待核准、已拒絕的雜湊,加上 `rules_version`、`unscoped_tools`、`tool_scopes` 與 `rules`,共用一個 `etag`。變更在一次輪詢內送到 server,已經簽發的 token 也適用(個人存取 token 的 jti 不變,所以針對它的規則下一次呼叫就生效)。沒有變化時,回應只有 `{"unchanged": true, "etag", "now"}`。
4. **Server 評估每個請求。** `MCPGateToolPinning` 用已驗證 token 的 `jti`、`client_id`、`sub` 與 `scope` 執行 `evaluate_access`:`hidden` 的 tool 不出現在 `tools/list`,`tools/call` 時和不存在的 tool 一樣被拒絕;`needs_scope` 的 tool 會列出,呼叫則回覆寫出所需 scope 的 tool 錯誤。
5. **追加授權。** `MCPGateScopeGate` 是放在 FastMCP 前面的 ASGI middleware,它對同一個呼叫回 HTTP `403 insufficient_scope` 與該 tool 的 challenge scope,支援追加授權的 client 就會請使用者同意這個 scope,然後重試。
6. **管理台回報狀態。** 每次輪詢都會記錄 server 執行哪些功能(`policy_features`);server 頁面與它的 *存取控制* 分頁會顯示**存取規則已執行**,或說明 server 的 middleware 太舊或沒有安裝。

**範例。** 兩條規則(群組 `contractors` 只有一位成員 `u-7`)和兩個有 scope 的 tool,會得到下面這份格式 2 回應(雜湊清單已省略):

```json
{"format": 2, "hash_version": 1, "audience": "http://127.0.0.1:8000/mcp", "service_id": "…",
 "tools": {"approved": ["…"], "pending": [], "rejected": []},
 "rules_version": 1, "unscoped_tools": "allow",
 "tool_scopes": {"delete_file": {"any_of": ["files:admin", "files:write"], "challenge": "files:write"},
                 "read_file": {"any_of": ["files:read"], "challenge": "files:read"}},
 "rules": [{"id": "r1", "effect": "deny", "subject": {"kind": "user", "id": "u-7"}, "tools": ["delete_file"], "expires_at": null},
           {"id": "r2", "effect": "only", "subject": {"kind": "client", "id": "https://ci.example/client.json"},
            "tools": ["search", "read_file"], "expires_at": null}],
 "unchanged": false, "etag": "…", "now": 1795000000}
```

| Token | `search` | `read_file` | `delete_file` |
|---|---|---|---|
| 使用者 `u-1` 透過 Claude Code,scope `files:read` | 允許 | 允許 | 會列出;呼叫 → `needs_scope`,challenge `files:write`(有 gate 時回 403) |
| 使用者 `u-7`(屬於 `contractors`),scope `files:read files:write` | 允許 | 允許 | 隱藏(`denied_by_rule`,`r1`) |
| client `https://ci.example/client.json`,scope `files:read files:write` | 允許 | 允許 | 隱藏(`outside_only_rule`,`r2`) |

**實作必須相符的版本。** 套用任何內容之前都會先檢查;不相符時整份回應(或快取)都不採用,繼續沿用先前的 policy,若還沒有任何 policy,所有 tool 維持隱藏。

| 欄位 | 1.6 的值 | 由誰釘住 | Server 不認得這個值時 |
|---|---|---|---|
| `hash_version` | 1 | `tests/fixtures/tool_hash_vectors.json`(每個 tool 的標準 JSON 與 SHA-256) | 拒絕這份回應 |
| `format` | 輪詢帶了 `rules1` 時為 2,否則為 1 | 本文件 | 拒絕這份回應;格式 1 代表只有核准清單 |
| `rules_version` | 1 | `tests/fixtures/tool_policy_vectors.json`(43 筆判定,加上群組展開) | 拒絕這份回應 |
| 規則的 `effect` | `deny`、`only` | 同一份向量 | 不認得的效果視為拒絕它列出的 tool(沒列出就是全部) |
| 快取檔的 `format` | 2(1 只當作核准清單讀取) | `examples/mcp_gate_hooks.py` | 忽略快取 |

MCP Gate 自己的測試會拿 `examples/mcp_gate_hooks.py` 跑這兩份向量檔,所以這個檔案的副本(或其他實作)只要能算出每一筆結果就是正確的。請把 fixtures 一起複製過去,在你的 server 的測試裡做同樣的檢查;MCP Gate 提高版本時,記得更新副本。

**缺少什麼或連不上時。**

| 狀況 | Server 的行為 |
|---|---|
| 從未連上 policy feed,也沒有可用的快取 | 所有 tool 隱藏(預設關閉);設 `fail_open=True` 則在收到第一份回應前列出所有 tool |
| feed 回應過一次,之後連不到 MCP Gate | 最後一份核准清單與規則繼續套用,重啟後也一樣(快取檔,權限 600);`max_cache_age` 可限制快取的最長時間 |
| 連不到 MCP Gate 期間,某條規則到了 `expires_at` | 到時就不再套用,不必等輪詢 |
| Server 用的是 1.5 middleware | 只執行核准;規則被忽略;管理台顯示*存取規則未執行 — 請更新 middleware* |
| Server 沒有 middleware | 什麼都不執行;管理台顯示這台 server 未執行核准 |
| 請求帶的是 MCP Gate 的 probe token(`mcp_gate_probe`) | 列出所有 tool,不論是否核准、不論規則;所有呼叫都拒絕 |
| 要立刻撤銷 | 用撤銷清單(撤銷 token 或授權):規則是長期的 policy,不是緊急切斷 |

**接上一台 server。** 把它註冊為服務,註冊一個綁定它為 resource server 的機密 `client_credentials` client(撤銷清單、policy feed 與 tool 回報都用這個 client),再照 README 的完整範例加上 `MCPGateVerifier`、`MCPGateToolPinning` 與 `MCPGateScopeGate`。自帶一份 hooks 檔的 server 用它自己的設定開啟,請見該 server 的設定文件。

### Tool 存取規則

*1.6。* MCP Gate 儲存並評估規則;執行 1.6 版 `MCPGateToolPinning` middleware 的 server 會從 policy feed(格式 2)收到規則,並在一次輪詢內執行(見 [Server 上的 tool 核准](#server-上的-tool-核准))。沒有這個 middleware,或用的是 1.5 版的 server 不會執行,管理台的 server 頁面會說明。缺少 scope 的呼叫:server 也執行 `MCPGateScopeGate` 時,會收到 HTTP 403 [追加授權](#追加授權)要求;否則會收到寫出所需 scope 的 tool 錯誤。

一個 token 能不能呼叫 server 的某個 tool,依下列順序決定,先符合者為準:

1. **未核准**([tool 釘選](#tool-釘選與核准)):隱藏。
2. 有針對這個 token 的**拒絕規則**列出這個 tool(或 `*`,即所有 tool):隱藏。
3. 有針對這個 token 的**限定規則**,而 tool 不在其中某一條裡(多條取交集):隱藏。
4. **Scope。** tool 可以放進 scope(server 可授予的全域 scope,或 server 自己的 scope)。token 持有其中**任一個**就能呼叫;否則 tool 仍會列出,但呼叫會被拒絕並寫出其中一個 scope([追加授權](#追加授權)要求)。不在任何 scope 裡的 tool 預設允許,除非 server 設為**必須有 scope**(`unscoped_tools: require`),此時會隱藏。
5. 其餘允許。

- **工具組合就是 scope。** 放了 tool 的 scope 就是一個工具組合;一個 tool 可以在多個組合裡,範圍較大的 scope 只是放了較多 tool。每個 tool 有一個**追加授權 scope**,也就是 step-up 時要求的那個:有標記就用標記的,否則用最窄的(tool 最少,再依名稱)。刪除 scope 時,所有 tool 都會移出。指派給 tool 的 scope 必須是 RFC 6749 scope-token(可列印 ASCII,不含空白、`"` 與 `\`),因為它會放進 `WWW-Authenticate: Bearer scope="…"`;新建的 scope 必須符合,舊名稱不符合的會在 1.6 migration 的 log 列出,且不能指派。scope 可以有顯示用的 `title`。
- **規則對象。** `pat`(這個 server 的個人存取 token,以 jti 指定;OAuth access token 無法單獨指定,因為每次 refresh 的 jti 都會變)、`client`(OAuth client id;所有 PAT 共用 `mcp-gate-console`)、`user`(管理台帳號的 id,也就是其 token 的 `sub`;`client_credentials` token 的 `sub` 是它的 client id)與 `group`。規則以名稱指定 tool(必須是這個 server 的 tool,目前有沒有列出都可以),或 `["*"]`(僅限拒絕);可以有 `note` 與 `expires_at`(UTC),過期後不再套用。
- **群組**是有名稱的管理台帳號集合。規則可以指定群組;MCP Gate 會在 server 收到之前把它展開成每個成員一條規則,所以 server 只比對 token 的 claim(`jti`、`client_id`、`sub`),成員變動會在下一次輪詢生效。被規則指定的群組不能刪除(否則它的拒絕會失效);帳號刪除時,其成員資格也會一併移除。
- **上限。** 每個 tool 32 個 scope、每條規則 500 個 tool;每個 server 在群組展開後最多 2,000 條規則、64 KiB 的規則 JSON(`409 access.rules_limit` / `access.rules_too_large`,加入成員會超過時也一樣)。過期的規則不計入。
- **評估器**是一個純函式 `src/tool_policy/evaluate.py`(只用標準函式庫,方便 server 端 middleware 帶一份),由 `tests/fixtures/tool_policy_vectors.json` 的標準向量釘住,其他實作必須算出相同結果(`rules_version` 1)。輸入:`{"unscoped_tools", "tool_scopes": {"<tool>": {"any_of": [...], "challenge"}}, "rules": [{"id", "effect", "subject": {"kind", "id"}, "tools", "expires_at": <unix 秒> | null}]}`、token 的 claim、tool 名稱、是否已核准與目前時間。輸出:`{"decision": "allowed" | "hidden" | "needs_scope", "reason": "ok" | "not_approved" | "denied_by_rule" | "outside_only_rule" | "missing_scope" | "unscoped_tool_requires_scope", "rule_ids", "scopes", "challenge"}`。效果不明的規則視為拒絕它列出的 tool(沒列出就是全部);對象種類不明的規則對所有 token 都成立。
- **API**(需管理台 session;寫入會記入稽核,並和 `/api` 其他端點一樣檢查來源):
  - `GET /api/services/{id}/access`:`unscoped_tools`、每個 tool 的 scope 與追加授權 scope、規則(含對象名稱與 `expired`)、tool 可放入的 scope(`challenge_safe`),以及 `policy`,也就是這個 server 的評估器輸入,群組已展開。`PUT /api/services/{id}/access` `{"unscoped_tools": "allow" | "require"}`(`service_unscoped_tools_set`)。
  - `GET/PUT /api/services/{id}/tools/{tool_id}/scopes` `{"scopes": [...], "challenge": null | "<其中之一>"}` 取代 tool 的 scope(`tool_scope_set`,記錄前後)。錯誤:`400 access.unknown_scope`、`access.scope_not_permitted`(server 的允許 scope 排除的全域 scope)、`access.scope_name_unsafe`、`access.challenge_not_in_scopes`、`access.too_many_scopes`。
  - `GET/POST /api/services/{id}/access-rules`、`GET/PUT/DELETE /api/services/{id}/access-rules/{rule_id}`,內容為 `{"effect": "deny" | "only", "subject": {"kind", "id"}, "tools": [...], "note", "expires_at"}`(`tool_rule_create`、`tool_rule_update`、`tool_rule_delete`)。錯誤:`400 access.invalid_effect`、`access.invalid_subject_kind`、`access.subject_not_found`、`access.pat_other_service`、`access.no_tools`、`access.unknown_tool`、`access.wildcard_not_alone`、`access.only_all_tools`、`access.too_many_tools`、`access.expires_in_past`;`404 access.rule_not_found`。
  - `GET/POST /api/groups`、`GET/PUT/DELETE /api/groups/{id}`、`PUT/DELETE /api/groups/{id}/members/{user_id}`(`group_create`、`group_update`、`group_delete`、`group_member_add`、`group_member_remove`);`409 groups.name_taken`(名稱不分大小寫不得重複)、`409 groups.in_use`、`404 groups.not_found` / `groups.member_not_found`。`GET /api/users` 列出可選的管理台帳號。
- **管理台。** server 頁面有 **存取控制** 分頁(`?tab=access`):最上方的橫幅說明 server 是否執行這裡的設定(已執行、已停止輪詢、middleware 太舊、沒有 middleware);「不在任何組合中的 tools:允許 / 必須在組合中」開關(會讓已核准的 tools 被隱藏時先確認);每個 tool 所屬的組合(↑ 標示追加授權要求的 scope)與規則數,可逐一編輯(所屬組合,以及追加授權要求的 scope,或由 MCP Gate 選範圍最小的);這台 server 可用的組合,可用「選擇 tools」從組合這一側指派 tools(tool 原本的其他組合不受影響),並可建立、編輯、刪除這台 server 專用的組合(帶標題的 scope);以及存取規則,編輯時可設定類型、對象(這台 server 的 Personal Access Token〔依標籤〕、OAuth Client、帳號或群組)、tools、備註與到期時間(當地時間),已過期的規則以淡色顯示。**工具組合** 頁列出所有 server 的組合(適用所有 server 的組合會列出每台能授予它的 server 的 tools),可建立適用所有 server 或只適用一台的組合。**群組** 頁可建立、改名、刪除群組,加入或移除成員,並列出使用該群組的規則;被規則使用中的群組無法刪除,畫面會列出那些規則。待核准 tool 的審查卡片可以 **核准並放入組合**,一步完成。「簽發 Personal Token」會先列出這台 server 的組合,並註明每個組合能呼叫哪些 tools。全域 scope 清單(OAuth Client 頁)也能編輯標題。server 專用的 scope 從「總覽」分頁移到「存取控制」分頁。
- **升級到 1.6。** Migration `b5d7f9a1c3e6` 新增資料表 `tool_scopes`、`tool_access_rules`、`user_groups`、`user_group_members`,新增欄位 `services.unscoped_tools`(既有 server 皆為 `allow`)、`oauth_clients.policy_features` 與兩個 scope 資料表的 `title`,並把 client、授權請求與授權碼、token、同意紀錄的 `scope` 欄位改為 `TEXT`(帶很多組合 scope 的 token 在 PostgreSQL 上會超過 `VARCHAR(512)`);`scope` 參數現在最長 4,096 字元。不回填任何資料,所以在管理員指派 scope 或新增規則之前,一切照舊。在 PostgreSQL 上,若之後存過超過 512 字元的 scope,降版會失敗。

### 追加授權

*1.6。* token 缺少某個 tool 需要的 scope 時,這個 tool 仍會列出,但呼叫會收到 **HTTP 403** 與 `WWW-Authenticate: Bearer error="insufficient_scope", scope="<challenge>", resource_metadata="<protected resource metadata 網址>", error_description="<原因>"`(RFC 6750 §3.1,MCP 授權的追加授權 step-up)。支援追加授權的 client 會請使用者再授權一次、加上這個 scope,然後重試呼叫。MCP client 只在真正的 403 時才會重新授權,HTTP 200 裡的 tool 錯誤不會觸發。所以這個 403 必須由一個在 FastMCP 回應之前執行的 ASGI middleware 送出。

[`examples/mcp_gate_hooks.py`](../examples/mcp_gate_hooks.py) 裡的 `MCPGateScopeGate` 就是這個 middleware。它和 `MCPGateToolPinning` 一起放在 server 的 HTTP app 上,使用同一個評估器:`mcp.run(transport="http", middleware=[Middleware(MCPGateScopeGate, pinning=pinning, server=mcp)])`(完整範例見 README)。

- **回覆什麼。** 每個 `POST` 它都會在 app 執行前先讀 JSON-RPC body。只有呼叫已核准 tool、而判定為 `needs_scope` 的 `tools/call` 會收到 403。body 是 JSON-RPC 錯誤(`code` -32001,`message` 是原因,`data` 是 `{"error": "insufficient_scope", "scope"}`),帶著請求的 `id`。其他請求原封不動交給 app:其他 method(有 MCP 2026-07-28 的 `Mcp-Method` header 時連 body 都不讀)、不存在、未核准或被規則隱藏的 tool(pinning middleware 仍會當成不存在的 tool 拒絕,所以 403 不會透露隱藏的 tool)、MCP Gate 的 probe token、缺少 server `required_scopes` 的 token(由 FastMCP 自己回應)、所有 `GET`(SSE 串流)與 `DELETE`。app 開始回應後它就不再改動,串流回應不受影響。
- **Body 上限。** `max_body`(預設 4 MiB)。超過的 body(依 `Content-Length` 或實際讀到的量)整個交給 app,由 pinning middleware 以下面的 tool 錯誤拒絕。
- **舊式 JSON-RPC batch。** 只有每則訊息都是需要同一個 scope 的 `tools/call` 時才回 403(body 是錯誤陣列);其他 batch 照常交給 app,逐一拒絕。
- **要求的 scope。** 預設只寫 tool 的 challenge scope,也就是 MCP 2026-07-28 與 RFC 6750 的定義:client 以這個 scope 和它已有的 scope 的聯集重新授權。Claude Code、FastMCP 的 `client_credentials` client 和 claude.ai 都這樣做。`challenge_includes_token_scopes=True` 會一併列出 token 目前的 scope(不含 `offline_access`),給會用要求內容取代原有 scope 的 client 使用,這是 MCP 2025-11-25 建議 server 對這類 client 採用的做法。代價是 Claude Code 用個人存取 token 時,會把列出的每個 scope 都顯示成「required」。
- **原因說明**寫出 scope,並說明這種 token 能怎麼做。個人存取 token(`client_id` 為 `mcp-gate-console`)無法增加 scope:要用這個 scope 發一個新的(*Tokens → Issue token*)。`client_credentials` token(`sub` 等於 `client_id`):申請帶這個 scope 的 token;MCP Gate 拒絕時,要由管理員允許這個 client 使用該 scope。使用者的 token:重新登入並同意這個 scope,或改用帶有它的個人存取 token。pinning middleware 的 tool 錯誤也是同一段文字(`Tool '<name>' requires the scope '<scope>', which …`),所以沒有 gate 的 server,或不理會 403 的 client,一樣會顯示它。
- **同意畫面。** 每個要求的 scope 會列出它在這台 server 上能使用的已核准 tool。使用者之前已同意過這個 client 存取這台 server(記住的同意,否則是透過它取得的最新 access token)時,畫面會顯示「要求更多權限」,標出新增的 scope,以及先前無法呼叫的 tool:在新 scope 裡的 tool,或在那次同意之後才加入已授予 scope 的 tool。「記住這次的決定」(和以前一樣)會保留記住過的 scope 與這次同意的 scope 的聯集,所以只要求新 scope 的追加授權不會讓舊的被忘掉。同意的稽核紀錄會記下 `step_up` 與 `added_scopes`。手動註冊(受信任)的 client 仍會略過同意畫面,所以它們的追加授權不會詢問,只受 client 允許的 scope 限制。
- **不會重複循環。** 一次呼叫只收到一次 403。拿不到 scope 的 client 會停下:允許的 scope 不含它的 `client_credentials` client 會收到 MCP Gate token endpoint 的 `invalid_scope`(`scope not permitted: <scope>`);個人存取 token 無法升級。

**實測過的 client**(2026-11-25,MCP Gate 1.6 開發版與 FastMCP 4.1.5,server 為 README 的完整範例):

| Client | 登入方式 | 結果 |
|---|---|---|
| Claude Code 2.1.318,互動模式 | OAuth(Client ID Metadata Document) | **會追加授權。** 詢問「needs additional permissions for this tool … Re-authenticate now?」,開啟同意畫面要求 challenge scope 加上它已有的 scope,然後重試一次呼叫,成功。 |
| Claude Code 2.1.318,`claude -p`(無介面) | OAuth | 不會自行追加授權。回報 `MCP server "<name>" needs additional permissions (scope: "<scope>") — run /mcp to re-authenticate`;執行 `claude mcp login <name>`(會要求聯集)後呼叫成功。 |
| Claude Code 2.1.318 | header 裡的個人存取 token | 一次 403,不會循環。顯示 `Insufficient scope: required "<scope>"`,不會顯示原因說明。請發一個帶這個 scope 的新 token。 |
| FastMCP 4.1.5 `ClientCredentialsOAuthProvider` | `client_credentials` | **會追加授權。** 以原有 scope 和 challenge 的聯集申請新 token,重試,成功。 |
| 同上,但 client 允許的 scope 不含它 | `client_credentials` | 一次 403,之後 MCP Gate 拒絕發 token:`OAuthTokenError … invalid_scope … scope not permitted: <scope>`。不會循環。 |
| FastMCP 4.1.5 `BearerAuth` | 個人存取 token | 一次 403。呼叫拋出 `MCPError`,內容是原因說明("A personal access token cannot gain scopes: issue a new one …")。 |
| VS Code、Codex、Cursor | | 未測試:測試機上沒有安裝。2026 年 2 月的回報指出 Cursor 不會追加授權。這些 client 的使用者會看到原因說明;也可以把該 scope 設為預設(首次登入時就授予)。 |

### 連接 MCP client

每台 server 頁面上的 **連接用戶端** 面板(服務列表的插頭圖示也會帶到這裡;列表上方的 **連接用戶端** 則一次產生所有 server),提供 **Claude Code、Cursor、VS Code 與 Codex** 的現成設定:每個 client 一個分頁,client 有指令就給指令,還有它讀取的設定檔(可複製或下載)與步驟。每個片段裡的 server 網址都是那台 server 的 **audience**:client 會把它連線的網址當成 RFC 8707 的 `resource` 送出,而 MCP Gate 只接受已登記的 audience,同一台 server 換個寫法就會得到 `invalid_target`。audience 不是 `http(s)` 網址時,改用 server 自己的位址。

| Client | 登入(預設) | 個人 token | 依據 |
|---|---|---|---|
| Claude Code | `claude mcp add --transport http <name> <url>`,再 `claude mcp login <name>`(或 `/mcp`);`.mcp.json` `{"mcpServers": {"<name>": {"type": "http", "url": …}}}` | `--header 'Authorization: Bearer ${MCP_GATE_PAT_<NAME>}'`;Claude Code 連線時才展開變數 | [Claude Code MCP](https://code.claude.com/docs/en/mcp) |
| Cursor | **加入 Cursor** 安裝連結(`cursor://anysphere.cursor-deeplink/mcp/install`),或 `~/.cursor/mcp.json` `{"mcpServers": {"<name>": {"url": …}}}`;從 *Needs login* 登入 | `"headers": {"Authorization": "Bearer ${env:MCP_GATE_PAT_<NAME>}"}` | [Cursor MCP](https://cursor.com/docs/context/mcp)、[安裝連結](https://cursor.com/docs/context/mcp/install-links) |
| VS Code | `code --add-mcp '{"name": …, "type": "http", "url": …}'`,或 `.vscode/mcp.json` `{"servers": {…}}` | `password: true` 的 `promptString` input,標頭裡用 `${input:mcp-gate-pat-<name>}`:VS Code 問一次,token 存在它的秘密儲存區 | [VS Code MCP 設定](https://code.visualstudio.com/docs/agents/reference/mcp-configuration) |
| Codex | `codex mcp add <name> --url <url>`,再 `codex mcp login <name>`;`~/.codex/config.toml` `[mcp_servers.<name>]` `url = …` | `bearer_token_env_var = "MCP_GATE_PAT_<NAME>"` | [Codex MCP](https://learn.chatgpt.com/docs/extend/mcp?surface=cli) |

**登入** 不需要事先做任何事:這些 client 都會讀 server 的 protected resource metadata、找到 MCP Gate、自行註冊(Client ID Metadata Document 或動態註冊),再開啟同意頁。片段不固定 scope;client 依 server 公告的去要,MCP Gate 給 server 允許的預設 scope。`dcr_auto_approve` 關閉時,新 client 要先等管理員在 *OAuth Clients* 核准,面板會提示。**個人 token** 給沒有瀏覽器的機器(CI、遠端 shell)。片段永遠不含 token:每個都引用以 server 命名的環境變數(或 VS Code 的密碼提示),而一張 personal access token 只適用於一台 server。

`GET /api/services/{id}/client-config?client=claude-code|cursor|vscode|codex&variant=oauth|pat` 回傳 `file`(`format`、`path`、`filename`、`content`)、`commands`、`install_links`、`servers`(名稱、設定鍵、網址、接受的 scope、PAT 變數)、`docs_url`、`issuer`、`dcr_auto_approve`、`requires_auth`,`pat` 另有 `pat_page`;加 `&download=1` 只回傳設定檔附件。`GET /api/client-config` 對所有啟用中的 server 做同樣的事(依名稱排序),沒有位址的列在 `skipped`。兩者都需要管理台登入(與讀取 server 相同),錯誤為 `409 client_config.no_url` / `422 client_config.unknown_client` / `422 client_config.unknown_variant`。設定鍵是 server 名稱只留 `A–Z a–z 0–9 - _`(重複時加編號),每個值都依它落入的 shell、JSON 或 TOML 正確跳脫。

## 使用管理台

| 頁面 | 在這裡做什麼 |
|---|---|
| **Dashboard** | 服務健康、token 活動、最近事件、系統狀態。 |
| **Services** | 登記或掃描 MCP server、設定 audience 與允許的 scope、宣告 server 專屬 scope、更新 tools 並核准新的或變更的 tool([Tool 釘選與核准](#tool-釘選與核准))、執行健康檢查、複製接入片段與用戶端設定([連接 MCP client](#連接-mcp-client))。 |
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
| Resource server | `POST /oauth/revoked`(撤銷清單)· `POST /oauth/usage`(使用回報)· `POST /oauth/policy`(tool policy feed)· `POST /oauth/tool-report`(tool 回報);需綁定到該 server 的 confidential client,見[撤銷清單](#撤銷清單)與 [Server 上的 tool 核准](#server-上的-tool-核准) |
| 管理台 session | `GET /api/session/status` · `POST /api/session/setup` · `POST /api/session/login` · `POST /api/session/logout` · `GET /api/session/me` · `PUT /api/session/me/{profile,password}` · `GET /api/session/oauth/{github,google}/{start,callback}` |
| 管理 API(需登入) | `/api/services*`(含 `/api/services/{id}/access`、`…/access-rules*`、`…/tools/{tool_id}/scopes`,見 [Tool 存取規則](#tool-存取規則))· `/api/groups*` · `/api/users` · `/api/client-config` · `/api/oauth/{clients,scopes,tokens,consents,keys,activity,overview,snippets}` · `/api/discovery/*` · `/api/marketplace*` · `/api/managed*` · `/api/byo-mcp*` · `/api/stats/*` · `/api/audit/*` · `/api/system/*` |
| 維運 | `GET /health` · `WS /ws/services`(服務狀態即時推播) |

用腳本呼叫管理 API 時,先 `POST /api/session/login`,之後每個請求都要帶 `mcp_session` cookie、以 `X-Session-Binding` 標頭帶上登入回應裡的 `session_binding` 值,寫入請求還要帶同源的 `Origin` 標頭。

設 `ENABLE_API_DOCS=true` 後 `/docs` 有完整 OpenAPI 參考。
