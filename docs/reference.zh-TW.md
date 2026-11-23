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
- **管理台。** server 頁面有一列 *Tool approvals*,和撤銷清單那列一樣:由 server 執行(附最後一次輪詢時間)、已停止輪詢、從未輪詢,或未執行。待核准 tool 的審核卡片會說明這台 server 是否執行核准。

給其他實作參考的 feed 與回報格式(form-encoded `POST`,驗證方式同 `/oauth/revoked`;只限呼叫者自己的 server):

- `POST /oauth/policy`(可帶 `etag`)回應 `{"format": 1, "hash_version": 1, "audience", "service_id", "tools": {"approved": [...], "pending": [...], "rejected": [...]}, "rules": [], "unchanged": false, "etag", "now"}`,每個清單都是 64 位十六進位雜湊。其他雜湊都算未知:隱藏並回報。`rules` 保留給 1.6 的 tool 層級 policy,目前是空的;不認得的欄位請忽略。帶上手上的 `etag`,若沒有變化就只回 `{"unchanged": true, "etag", "now"}`。server 被停用或刪除時,所有清單都是空的。
- `POST /oauth/tool-report`,`tools` 是 `tools/list` 回傳格式的 tool 物件 JSON 陣列(最多 200 個、body 最大 2 MiB、每個 client 每分鐘 30 次、每份定義最大 64 KiB)。MCP Gate 會自己為每份定義計算雜湊:一併送來的 `hash` 只拿來比對,不同的會列在 `hash_mismatch`。回應是 `{"recorded": [{"name", "hash", "state", "new"}], "invalid": [{"index", "name", "reason"}], "hash_mismatch": [...]}`。回報和重新整理走同一套規則,只是它沒提到的 tool 不受影響。新的定義會以 `tool_report` 記入稽核日誌,執行者是該 resource server。

## 使用管理台

| 頁面 | 在這裡做什麼 |
|---|---|
| **Dashboard** | 服務健康、token 活動、最近事件、系統狀態。 |
| **Services** | 登記或掃描 MCP server、設定 audience 與允許的 scope、宣告 server 專屬 scope、更新 tools 並核准新的或變更的 tool([Tool 釘選與核准](#tool-釘選與核准))、執行健康檢查、複製接入片段。 |
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
| 管理 API(需登入) | `/api/services*` · `/api/oauth/{clients,scopes,tokens,consents,keys,activity,overview,snippets}` · `/api/discovery/*` · `/api/marketplace*` · `/api/managed*` · `/api/byo-mcp*` · `/api/stats/*` · `/api/audit/*` · `/api/system/*` |
| 維運 | `GET /health` · `WS /ws/services`(服務狀態即時推播) |

用腳本呼叫管理 API 時,先 `POST /api/session/login`,之後每個請求都要帶 `mcp_session` cookie、以 `X-Session-Binding` 標頭帶上登入回應裡的 `session_binding` 值,寫入請求還要帶同源的 `Origin` 標頭。

設 `ENABLE_API_DOCS=true` 後 `/docs` 有完整 OpenAPI 參考。
