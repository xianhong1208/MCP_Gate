# 發展路線圖

[English](ROADMAP.md)

MCP Gate 在 1.3 之後的方向。計畫在 2026-11-13 定案;每一項寫的是使用者會得到什麼,而不是怎麼做出來。MCP Gate
專注在**管理 MCP server**,不打算變成通用的身分提供者。每個版本在 GitHub 上都有對應的
[milestone](https://github.com/xianhong1208/MCP_Gate/milestones),每一項各有一個 issue。

## 已發布

**1.0.0(2026-09-01),第一個公開版本。** 完整的 MCP 用 OAuth 2.1 授權伺服器:discovery、動態註冊 client、PKCE、
refresh token 輪替、撤銷、內省、resource indicator 與同意頁。server 拿 JWKS 離線驗證的 RS256 token。Personal access
token。管理台有服務登錄、健康檢查、工具同步、Marketplace 與稽核紀錄。預設 SQLite,也能用 PostgreSQL。

**1.0.1(2026-09-15)。** 服務頁上的 token scope 在任何螢幕寬度都看得到。

**1.1.0(2026-09-18)。** `private_key_jwt` client 驗證;給離線驗證 server 用的第一版撤銷清單與使用回報
(`MCPGateVerifier`);每台 server 可宣告自己的 scope;列出已記住同意的頁面;請求從 issuer 以外的主機名稱進來時會提醒;
「Inspect as」用某張 token 的身分查看 server 的工具;orchestrator 不用 Docker 的行程 runtime。

**1.2.0(2026-11-04)。** Client ID Metadata Documents(用 https 網址當 `client_id`,MCP 2026-07-28 的註冊方式)。
撤銷清單只給每台 server 自己的 token,管理台會顯示 server 有沒有在輪詢。Access token 預設 15 分鐘。在 SQLite 與
PostgreSQL 上跑的 CI,以及一輪針對 OAuth 端點、管理台 session、對外連線與 orchestrator 的安全強化。

**1.3.0(2026-11-09)。** 首次設定需要一次性設定碼,網路上的其他人沒辦法搶先取得擁有者帳號。CI 加入相依套件稽核。

**1.3.1(2026-11-09)。** 從同意頁登入後會回到原本的授權請求;兩個服務不能再共用同一個 audience。

細節見 [CHANGELOG.md](CHANGELOG.md)。

## 接下來幾版怎麼搭在一起

MCP Gate 會在同一個管理台管兩種 server:

- **你能改的 server** 依舊不經過 MCP Gate。規則透過**政策清單(policy feed)**送出,和現有的撤銷清單並列,由 server
  端的 `MCPGateVerifier` 與 FastMCP middleware 執行,也就是 [README 範例](README.zh-TW.md#快速開始)裡用的那一套。
  server 會把工具呼叫回報給 MCP Gate。
- **改不了的第三方 server** 走選用的 proxy(1.9)。

## 接下來

| 版本 | 你會得到 |
|---|---|
| **1.4:安全與維運** | `ENCRYPTION_KEY` 不再和資料庫一起放在 `data/`。簽章金鑰與加密金鑰都能輪替:現在簽章金鑰要手動輪替,加密金鑰一換,它保護的密鑰就讀不回來。官方 Docker image 與 compose 檔。 |
| **1.5:認識你的工具** | 每個工具的描述與輸入 schema 都用雜湊值釘住,**新出現或有變動的工具,在管理員核准前都不會被看到**。掃描工具描述裡的 prompt injection(「tool poisoning」)。支援 MCP 2026-07-28:`server/discover`、無狀態 server、動態註冊 client 的淘汰提醒、`application_type`。直接匯出 Claude Code、Cursor、VS Code 與 Codex 的 client 設定。 |
| **1.6:誰能呼叫什麼** | **工具層級的政策:** 把工具對應到 scope,依 token 或 client 允許或拒絕個別工具。規則透過政策清單送到你的 server,由 README 範例裡同一套 `MCPGateVerifier` / FastMCP middleware 擴充後執行,請求一樣不經過 MCP Gate。**Step-up:** 權限不夠的呼叫會回 `WWW-Authenticate: … scope=`,client 再去申請。**工具組合(bundle)**,一次授權一組工具。**「Inspect as」** 會列出一張 token 能呼叫和不能呼叫的工具。 |
| **1.7:看見每一次呼叫** | 工具呼叫的稽核紀錄(工具、呼叫者、結果與時間;預設不記錄參數)。每個工具的延遲與錯誤。配額。OpenTelemetry 匯出。告警。 |
| **1.8:目錄與供應鏈** | Marketplace 與官方 MCP Registry 同步。server 版本會固定,升級要先審查才會套用。檢查 image 簽章。MCP Gate 執行的 server 有沙箱限制。 |
| **1.9:給第三方 server 的 proxy** | 選用的 proxy `/mcp/<bundle>`,**預設關閉**,給你改不了的 server 用。它以 token exchange 或預先存好的上游憑證連到上游 server,絕不把 client 的 token 直接轉送過去。 |

## 之後

- orchestrator 支援**多台主機**:主機登錄與遠端 agent(#2)。
- **GitHub 與 Google 登入在真實 OAuth app 上驗證**(#1)。
- **REST → MCP:** 把現有的 REST API 包成 MCP server(#51)。

## 尚待驗證

- GitHub 與 Google 登入已實作並有單元測試,但從沒在真實的 OAuth app 上跑過(#1)。
- orchestrator 的 Docker runtime 在測試裡用的是假的 runtime,CI 只建置 `mcp-runtime` image 並做 smoke test;測試套件
  沒有在真的 Docker daemon 上跑過它。
