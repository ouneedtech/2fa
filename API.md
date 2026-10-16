# Agent API · v1

API 只传输密文。**服务端不提供明文密钥或“直接返回验证码”的接口**，因为这会要求服务器掌握解密密钥。Agent 可只通过 HTTP 取得密文，并在本地生成验证码。`scripts/agent.mjs` 已实现全部解密、TOTP 和可选新增。

## 建立信任与授权

用户在解锁网页后生成授权包（一次性显示）：

```json
{
  "version": 1,
  "api_base": "https://totp.example.com",
  "token": "<signed-agent-token>",
  "enc_key": "<64-lowercase-hex-characters>",
  "expires_at": 1800000000
}
```

示例全为占位符，不是可用凭证。授权包是敏感凭证，Token 和解密密钥都不要进入源码、工具日志、版本库、提示词记录或共享截图。通过自己的 Secret Manager / 安全 stdin 管道提供给执行进程；不要放命令行参数。`enc_key` 永不放在 HTTP 请求、Authorization、URL 或 Worker 中。

首次创建此授权仍由用户在网页完成；这之后 Agent 只需要 API，不再需要操作网页。Token 最长 30 天，无自动续期。到期需用户重新授权。API 不接受 Agent Token 创建新 Token。

## 零依赖 Node.js SDK

Node.js 22+（建议 24）。SDK 不自动打印密钥，网络重定向一律拒绝，默认只允许 HTTPS，有 20 秒请求超时。为本地测试显式传 `{ allowLocalhost: true }`。

```js
import { VaultAgent } from './scripts/agent.mjs';

// grant 由你的 Secret Manager 在本机提供，包含 token 和 enc_key。
const vault = new VaultAgent(grant);
const account = await vault.me();
const codes = await vault.codes();
// [{ id, label, issuer, code, remaining }]
// codes 本身敏感，不要发送到共享日志。

// 仅当用户创建 Token 时选择了“读取 + 新增”：
await vault.add({
  label: 'alice@example.com',
  issuer: 'Example',
  secret: '<BASE32_SECRET>',
  digits: 6, period: 30, algorithm: 'SHA1'
});

// 放弃当前 Agent 的 API 授权，不删除任何 TOTP 数据。
await vault.revokeSelf();
```

SDK 的 `list()` 返回解密后的记录（含 secret），`codes()` 只返回验证码和基本名称。尽量使用 `codes()`，不要输出整个 `list()`。SDK 没有删除条目、用户管理、创建 Token 的方法，服务端也拒绝这些请求；不仅是 SDK 限制。

CLI 从 stdin 读取 `{ "grant": { ... } }`，并输出 JSON：

```text
<你的安全凭证提供器> | node scripts/agent.mjs codes
<你的安全凭证提供器> | node scripts/agent.mjs me
<你的安全凭证提供器> | node scripts/agent.mjs add
<你的安全凭证提供器> | node scripts/agent.mjs revoke-self
```

`add` 的 stdin 对象另带 `entry`。`codes` 的 stdout 含实时验证码，接收方须按敏感数据处理。仅测试 localhost 时可附加 `--allow-localhost`。

## HTTP 权限矩阵

请求头：`Authorization: Bearer <token>`。不发送浏览器 Cookie。POST 操作使用 `Content-Type: application/json`；GET / DELETE 无需请求体。未配置 CORS，不允许跨站浏览器调用；服务端 Agent 不受浏览器 CORS 限制。

| 路径 | 方法 | 只读 Token | 读取 + 新增 Token | 本人浏览器会话 |
| --- | --- | --- | --- | --- |
| `/api/me` | GET | 允许 | 允许 | 允许 |
| `/api/entries` | GET | 本人密文 | 本人密文 | 本人密文 |
| `/api/entries` | POST | 403 | 新增本人条目 | 允许 |
| `/api/entries/:id` | DELETE | **403** | **403** | 仅本人条目 |
| `/api/logout` | POST | 撤销当前 Token | 撤销当前 Token | 撤销当前会话 |
| `/api/tokens` | GET / POST | **403** | **403** | 管理本人 Token |
| `/api/tokens/:id` | DELETE | **403** | **403** | 撤销本人 Token |
| `/api/users` | GET / POST | **403** | **403** | 仅管理员 |
| `/api/users/:id` | DELETE | **403** | **403** | 仅管理员，可删子用户 |

Token 与 Cookie 的类型被签名绑定：把 Agent Token 放进 Cookie、或把浏览器 Token 放进 Bearer，都返回 401。API Token 即使属于管理员，也不能管理用户。

### GET /api/me

```json
{
  "id": "<32-hex>", "username": "alice", "is_admin": false,
  "enc_salt": "<32-hex>", "key_check_iv": "<24-hex>",
  "key_check": "<hex-ciphertext>", "access": "agent", "can_add": false
}
```

`is_admin` 是账号属性，**不代表 Agent 能使用管理员功能**。权限按 Token 类型另行限制。

### GET /api/entries

```json
{"entries":[{"id":"<32-hex>","iv":"<24-hex>","ciphertext":"<hex>","created_at":1800000000}]}
```

本地用 `AES-256-GCM`，12 字节随机 IV，16 字节认证标签附在密文末尾。AAD 是 UTF-8 `still:entry:v1:<id>`。解密 JSON：

```json
{"label":"alice@example.com","issuer":"Example","secret":"<BASE32>","digits":6,"period":30,"algorithm":"SHA1"}
```

AAD 绑定条目 ID，不能把同一个密文换个 ID 复用。通过新随机 ID / IV 新增。只接受 SHA1 / SHA256 / SHA512、6 / 8 位、30 / 60 秒。Base32 必须合法、解码后 10–256 字节。

### POST /api/entries

```json
{"id":"<random-16-bytes-hex>","iv":"<random-12-bytes-hex>","ciphertext":"<AES-GCM-hex>"}
```

201：`{"id":"..."}`。409：ID 冲突或达到 1,000 条限制，**不会覆盖已有条目**。密文最多 8,192 个十六进制字符；整个请求体最多 16 KiB。服务端无法验证密文中的字段，合法明文校验由客户端完成。

### POST /api/logout

请求 `{}`，响应 `{"ok":true}`。立即使当前 Token 失效，既有密文保留。已下载到 Agent 的密文、明文和解密密钥无法远程收回。

## 浏览器登录协议（供代码审阅）

Agent **不需要也不应获取用户主密码**。以下接口只为说明网页实现，若把主密码交给 Agent，就不能再承诺 Agent 只有受限权限：它可以像完整用户一样登录。

1. `GET /api/status`：`{setup_required}`。
2. 首次设置：浏览器生成随机 16 字节 `enc_salt`，本地 PBKDF2-SHA256 600,000 次、64 字节。前 32 字节为 `auth_key`，后 32 字节为 AES 密钥。
3. 加密固定检查字符串 `still:key-check:v1`，AAD 也为该字符串，保存 `key_check_iv` / `key_check`。用于空 vault 的密码校验。
4. `POST /api/setup`：`{username, enc_salt, auth_key, key_check_iv, key_check, setup_token}`。仅空库且初始化令牌匹配时可用。
5. 登录：`POST /api/challenge {username}` → `{enc_salt, iterations:600000}`；未知用户名返回同样长度和结构的稳定伪盐。
6. 浏览器派生 `auth_key`，`POST /api/login {username, auth_key, remember}`，服务器比对 SHA-256(auth_key) 并设置 HttpOnly Cookie。**密码与 AES 密钥都不发送。**
7. 重新打开有效会话：`GET /api/me` 获取盐及 key check，用户在本机输入密码，验证 GCM 检查密文后解锁。

用户名统一为小写 ASCII；未知用户名和错误凭证都返回 `format_error`。用户名隐藏仅是界面约定，不保证流量时序层面的身份不可推断。挑战接口每 IP 5 分钟 40 次；登录 / 初始化各每 IP 5 分钟最多 5 次尝试，第 5 次失败后阻止后续尝试约 5 分钟。

## 错误码

错误统一为 `{"error":"code"}`，不返回数据库异常、堆栈或凭证。常见状态：400 输入不合法、401 无效 / 撤销 / 到期授权、403 权限或来源不允许、409 冲突 / 限额、413 过大、415 非 JSON、429 限流（`Retry-After: 300`）、503 未完成配置。Token 不会自动续期；Agent 不应在 401 后尝试用密码登录。
