# Still · Cloudflare TOTP Vault

一个轻量、自托管的 TOTP 验证器。运行时只有 **Cloudflare Worker + D1**，单个 HTML、原生 JavaScript、Web Crypto，无前端构建步骤、无运行时 npm 依赖、无外部字体或统计。

支持简体中文 / English / 한국어 / 繁體中文按钮切换、日间 / 夜间模式、移动端、独立用户空间，以及**无删除权限的 Agent API**。

> 测试版本。已完成本地代码审查、自动化测试和 Cloudflare 本地运行时验证，不代表绝对安全或第三方审计认证。先用测试账号验证，再导入真实 2FA。密码遗失无法恢复。

## 先选一种部署方式

| 方式 | 是否需要 GitHub | 适合场景 |
| --- | --- | --- |
| 本机 Wrangler → Cloudflare | 否 | 最少环节，推荐首次测试 |
| Cloudflare Workers Builds 连接 GitHub | 是 | 开源并随 push 自动部署，推荐长期使用 |
| GitHub Actions → Cloudflare | 是 | 希望部署记录与检查都在 GitHub |

**应用运行不依赖 GitHub。** 自动部署渠道只选一种，避免同一次 push 重复部署。不要把它部署成只托管静态文件的 Pages 项目。

## 本机快速预览（不连接 Cloudflare）

需要 Node.js 24。以下命令在项目根目录运行：

```powershell
node scripts/preview.mjs
```

打开 `http://127.0.0.1:8788`。首次设置的初始化令牌为 `local-preview-only-setup-token-000000000`，自行设置测试管理员用户名和至少 12 位密码。

此服务**仅绑定 127.0.0.1，数据库在内存中，重启即清空**。固定令牌仅供本地测试，生产环境绝不能使用。它使用 Node SQLite 测试适配器；生产运行路径和 Cloudflare 本地模拟请使用下述 Wrangler。

## 直接部署到 Cloudflare（无需 GitHub）

需要 Node.js 24、npm 和 Cloudflare 账号。在项目根目录逐条执行：

```powershell
npm ci
npx wrangler login
npx wrangler d1 create vault
```

把创建结果的 `database_id` 填入 `wrangler.toml`，替换全零占位符。`name` 可改成自己的 Worker 名称；绑定名 `DB` 保持不变。

```powershell
npm run db:remote
npm run deploy
npx wrangler secret put SERVER_SECRET
npx wrangler secret put SETUP_TOKEN
```

两个 Secret 分别设置为独立的随机字符串，建议各 32 个随机字节转十六进制。可在自己的终端使用下面的命令分别生成，不要放进源码、聊天、截图或 Git：

```powershell
node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"
```

`SERVER_SECRET` 用于会话签名。`SETUP_TOKEN` 防止新部署被他人抢先初始化，只在首次创建管理员时使用。打开部署 URL，填写初始化令牌和自己的管理员账号。首次初始化后建议删除 `SETUP_TOKEN`，关闭初始化凭证的后续暴露面：

```powershell
npx wrangler secret delete SETUP_TOKEN
```

设置过任何用户后，`/api/setup` 都不能再次创建管理员；并发初始化也不能建立第二个管理员。**不要清空生产 users 表来“重置密码”**。

### 自定义域名

先用 `workers.dev` 地址测试，再到 Worker → Settings → Domains & Routes → Add Custom Domain 绑定你账户中管理的域名。也可启用 `wrangler.toml` 末尾的 `routes` 示例并改成自己的域名。需要 Cloudflare 管理的 DNS 区域，不能只添加一条任意 CNAME 就认为绑定完成。使用 HTTPS。

## Cloudflare 原生 Git 集成（推荐开源后使用）

1. 将此脱敏源码推送到自己的 GitHub 仓库；不要提交 `.dev.vars`、授权包、数据库或 `.local`。
2. 先按上面的直接部署流程初始化 D1、Worker 和运行时 Secret。
3. Cloudflare 控制台打开这个 Worker，连接仓库，选择生产分支。
4. 根目录选 `/`；构建命令留空（如界面要求命令可填 `npm run check`），部署命令为 `npm run deploy`。依赖由 npm 根据锁文件安装，无应用构建步骤。
5. 关闭非生产分支的部署，或为其配置完全独立的测试 Worker / D1，避免预览分支接触生产数据。
6. **不要开启本仓库的 GitHub Actions 部署开关。** 数据库初次建表已完成；之后 schema 变化应先审阅迁移，再手动应用。

运行时 Secret 设在 Worker Settings → Variables and Secrets，**构建环境变量与运行时 Secret 不是同一个东西**。自动部署不需要把主密码、2FA 密钥或 `SETUP_TOKEN` 放进 GitHub。

## GitHub Actions（可选替代）

仓库自带 `.github/workflows/ci.yml` 和 `deploy.yml`：

- CI：push / PR 自动运行语法、体积、加密及权限回归测试。
- 部署：默认不启用。完成一次直接部署后，在 GitHub Repository Variables 设置 `ENABLE_CF_DEPLOY=true` 才会运行。
- GitHub Repository Secrets：`CLOUDFLARE_API_TOKEN`、`CLOUDFLARE_ACCOUNT_ID`。API Token 只给目标账户所需 Workers Scripts Edit 与 D1 Edit 权限；使用自定义域名时按需要添加相应路由 / DNS 权限。
- Worker 运行时 `SERVER_SECRET` 单独保存在 Cloudflare；工作流不会打印或同步它。
- 默认只部署 `main`；如果仓库使用其他默认分支，先修改工作流。
- 首次 D1 建表手动完成；部署工作流不会自动执行任意生产 SQL。
- 官方 Actions 固定到完整 commit SHA，npm 固定锁文件；不在 PR 上注入生产 Secret。

## 在真正的 Cloudflare 本地运行时测试

在项目根目录创建 `.dev.vars`（已被 Git 忽略）：

```dotenv
SERVER_SECRET=YOUR_OWN_RANDOM_SERVER_SECRET_AT_LEAST_32_CHARS
SETUP_TOKEN=YOUR_OWN_RANDOM_SETUP_TOKEN_AT_LEAST_32_CHARS
```

```powershell
npm ci
npm run db:local
npm run dev
```

本地状态保存在项目 `.local/state`。本地测试与 `--remote` 生产数据库相互独立。不要向开发服务器导入真实密钥。

## 使用方式

- 用户名只允许 3–48 位英文字母、数字、点、下划线、横线，统一小写。密码不做大小写或 Unicode 归一化。
- 未登录页外观是“添加验证器”：名称填写用户名，密钥字符串填写密码。错误统一提示格式不正确。**这是外观设计，不是安全防线；开源代码和 API 可看出登录逻辑。**
- 支持手动 Base32 或 `otpauth://totp/` 链接、SHA1 / SHA256 / SHA512、6 / 8 位、30 / 60 秒。未知 URI 参数忽略，未知算法 / 位数 / 周期回退为 SHA1 / 6 / 30。
- 点击验证码复制。剩余 5 秒提醒；请保持设备时钟同步。
- 刷新、关闭或锁定会清除页面中保存的密钥引用与明文；有效会话只让你免填用户名，仍需要密码解锁。
- “保留会话”只保存 30 天 Cookie，不保存解密密钥。不勾选时为 session cookie，签名有效期最多 24 小时；某些浏览器会恢复 session cookie，解密仍需密码。
- 管理员只能管理账号，不能通过 API 直接查看其他人的条目。创建者知道初始密码，本版本没有修改密码 / 忘记密码功能，请按这个边界使用。
- 用户删除会级联删除其条目与所有会话；网页删除需要确认。Agent Token 永远没有删除权限。
- 每用户最多 1,000 条条目、10 个有效 Agent Token；部署最多 100 用户。免费额度有请求与数据库配额，**不保证任意流量免费**。

## Agent 接入

解锁网页 → Agent API → 选择只读或读取 + 新增 → 选择 1 / 7 / 30 天 → 确认主动导出密钥 → 复制授权包。授权包只显示一次，包含 `api_base`、`token`、`enc_key`、到期时间。

**不要给 Agent 主密码、浏览器 Cookie、Cloudflare 或 GitHub 凭证。** 授权包相当于对这个账号所有条目的读取授权；建议给自动化单独创建子用户。Token 仅允许该用户读 / 可选新增，不允许删除、用户管理、续期或创建其他 Token。网页可立即撤销 Token。

零依赖 Node SDK / CLI 和完整 HTTP 协议见 [API.md](API.md)。Agent 运行时只需要 API 和本地 Web Crypto，不依赖网页或浏览器。

## 安全与验证

浏览器 PBKDF2-SHA256 600,000 次产生 64 字节，拆分登录凭证与 AES-256-GCM 密钥。Worker 不接收密码或解密密钥；D1 只存条目密文与登录校验材料。详情与无法消除的边界见 [SECURITY.md](SECURITY.md)；本次测试记录见 [AUDIT.md](AUDIT.md)。

```powershell
npm ci
npm run check
npm test
npm run test:browser
```

浏览器测试默认自动使用 Windows 上已安装的 Edge；否则需要本机已有 Playwright Chromium，可设置 `PLAYWRIGHT_CHANNEL=chrome` 或自行安装测试浏览器。浏览器结果写入 `.local/qa`，使用公开测试向量和虚构账号。Node SQLite 的 experimental warning 不影响测试。

## 打包

```powershell
npm run package
```

在项目 `release/` 创建源码 ZIP、内容清单与 SHA-256 校验文件。采用**文件白名单**，不包含 `.git`、依赖、缓存、`.dev.vars`、本地数据库、授权包、测试截图或用户环境。包内域名是 `example.com` 示例，D1 ID 是占位符。不会读取你的 Cloudflare/GitHub 凭据。

MIT License。后续计划与需求调整见 [PLAN.md](PLAN.md)。

参考：[Worker 原生静态资源](https://developers.cloudflare.com/workers/static-assets/binding/)、[Workers Builds](https://developers.cloudflare.com/workers/ci-cd/builds/configuration/)、[自定义域名](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/)、[Workers 配额](https://developers.cloudflare.com/workers/platform/limits/)。
