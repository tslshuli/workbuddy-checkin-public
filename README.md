# WorkBuddy 每日自动签到 · GitHub Actions 版

用 GitHub Actions 定时完成 WorkBuddy「Buddy 加油站」每日签到。**接口直签，无需常驻本机、无需开机、无需 GUI**。

> 安全说明：本仓库的代码（脚本 / workflow）**不含任何凭据**，可放心 Fork 与使用。登录凭据仅保存在你自己的 GitHub Secrets 中，绝不会出现在代码里。

---

## ⭐ 版本对照：你的客户端决定用哪种签到方式

WorkBuddy 客户端从 **5.6.2** 起对登录态做了静态加密（AtRestEncryption）。
这直接改变了「Secret 里该填什么」——**这是本项目最重要的一张表**：

| 项目 | 客户端 **5.5.x 及更早**（未加密） | 客户端 **5.6.2+**（登录态加密） |
|---|---|---|
| 登录态里 `auth.accessToken` 的形态 | 明文（JWT 字符串） | **AES-256-GCM 信封**：`{"$wbEncrypted":1,"envelope":"<base64>"}` |
| 本机能否直接读到明文 | ✅ 能 | ❌ **不能** —— 解密密钥不落盘，只在客户端进程内存里 |
| **该配哪个 Secret** | `WB_ACCESS_TOKEN`（短效令牌直通） | **`WB_REFRESH_TOKEN`（长效令牌，强烈推荐）** |
| 凭据有效期 | 约 2 个月 | 长效令牌约 **60 天**；轮换后旧值不会立即失效 |
| 配置命令 | `python scripts/sync_token_to_github.py` | 同上（脚本会自动导出**长效令牌**） |
| 旧版做法是否还能用 | ✅ | ❌ **把 accessToken 原样塞进 Secret 必然鉴权失败** |

> ⚠️ **最容易踩的坑**：在 5.6.2+ 上直接把登录态文件里的 `auth.accessToken` 复制出来填进 Secret。
> 你复制到的其实是一坨 JSON 信封，云端 runner **拿不到解密密钥**，只会一路鉴权失败。
> 本项目的脚本已能自动识别这种情形并**明确报错**，而不是静默失败。

**不知道自己属于哪一档？** 跑一次自检即可，它会直接告诉你要配哪个 Secret：

```bash
python scripts/workbuddy_checkin.py --diagnose
```

输出里的 `credential.mode` 会写明当前走的是哪条通道。

---

## 签到链路（v2.1.0-ci）

```
                        ┌─────────────────────────────────────────────┐
  Secret 中的凭据 ──────►│  ① WB_REFRESH_TOKEN（长效令牌，5.6.2+ 推荐） │
                        └──────────────────┬──────────────────────────┘
                                           │ POST /v2/plugin/auth/token/refresh
                                           │ （端点不校验 User-Agent，适合服务端场景）
                                           ▼
                                     accessToken（短效接口令牌）
                                           │
   本机登录态文件（仅明文时）───────────────┤
   ② WB_ACCESS_TOKEN（兼容 5.5.x）─────────┤
                                           ▼
                ┌──────────────────────────────────────────────────┐
                │ 查询状态  POST {base}/v2/billing/meter/           │
                │              checkin-activity-status              │
                │ 若未签到  POST {base}/v2/billing/meter/           │
                │              daily-checkin                        │
                └──────────────────────────────────────────────────┘
```

- 三条通道的优先级：**长效令牌 > 短效令牌 > 本机登录态文件**。
- 长效令牌**随用随换**：每次运行换取一个新的接口令牌。轮换出的新高令牌不会立即让旧值失效，
  因此 Actions 里存一份即可长期复用，**不需要回写 Secret**。
- 签到接口本身**幂等**：当日已签到返回 `code=10001`，脚本自动跳过，不会重复领取。

---

## 功能特性

- **云端定时签到**：每天北京时间 09:00 自动签到，领 100 积分；当日已签到则幂等跳过，不重复领取。
- **零硬编码凭据**：凭据全部走 GitHub Secrets / 环境变量，代码仓库里找不到任何密钥。
- **适配 5.6.2+ 加密登录态**：走长效令牌通道，不依赖客户端常驻、也不需要本机解密能力。
- **多渠道推送**：支持企业微信、PushPlus、Server酱（方糖）、Bark，成功 / 失败均可播报。
- **日志脱敏**：**输出层 + 摘要层双重白名单过滤** —— 接口响应在写进结果前即被压缩为结论字段，
  **完整响应永不进入 stdout / `result.json` / Actions 运行日志**；凭据**只报长度、连字符片段都不输出**。
- **零依赖**：仅用 Python 标准库，无需安装第三方包。
- **内置安全自检**：`security_audit.py` 在推送前扫描凭据泄露 / 危险代码 / 敏感文件。

---

## 前置条件

1. 已在本地**安装并登录 WorkBuddy 桌面客户端**（脚本需要读取本机登录态来取得凭据）。
2. 拥有一个 **GitHub 账号**。
3. （推荐）安装 [GitHub CLI](https://cli.github.com/) 并 `gh auth login`，用于一键把凭据写入 Secrets。未安装也可手动配置。

---

## 项目结构

```
.
├── .github/workflows/checkin.yml      # 工作流：定时 + 手动触发，结果写 Action 摘要
├── scripts/
│   ├── workbuddy_checkin.py           # 签到主脚本（长效令牌 / 短效令牌 / 文件，三通道）
│   ├── gen_notify_config.py           # CI 环境从环境变量生成推送配置
│   ├── sync_token_to_github.py        # 本机一键把凭据同步到 GitHub Secrets
│   ├── copy_token_to_clipboard.py     # 复制凭据到剪贴板（手动配置兜底）
│   └── summarize_result.py            # 白名单过滤，生成脱敏摘要
├── security_audit.py                  # 部署前自检：扫描凭据泄露 / 危险代码
├── requirements.txt                    # 零第三方依赖
├── .gitignore
├── LICENSE                            # MIT
└── README.md
```

---

## 快速开始

### 方式 A：Fork 本仓库（最简单）

1. 点击仓库右上角 **Fork**，把本仓库复制到你的账号下。
2. 进入你 Fork 出的仓库，按下方「配置 Secrets」添加凭据。
3. 到 **Actions** 页面启用工作流，手动 **Run workflow** 验证一次即可。

### 方式 B：手动新建仓库

```bash
git clone https://github.com/<你的用户名>/<新仓库名>.git
cd <新仓库名>
# 把本仓库的 .github/ scripts/ security_audit.py requirements.txt .gitignore LICENSE 复制进来
git add .
git commit -m "feat: WorkBuddy 每日自动签到 (GitHub Actions)"
git push -u origin main
```

### 配置 Secrets

凭据来自你本机 WorkBuddy 的登录态。最简单的方式是用自带脚本一键同步（需先 `gh auth login`）：

```bash
# 进入仓库目录，脚本自动读取本机登录态并写入 Secrets
python scripts/sync_token_to_github.py

# 或显式指定仓库
python scripts/sync_token_to_github.py --repo <用户名>/<仓库名>

# 只预览不写入
python scripts/sync_token_to_github.py --dry-run
```

脚本会自动区分登录态是**明文**还是**加密信封**，并据此选择正确的凭据：

| Secret 名 | 内容 | 适用客户端 | 必填 |
|---|---|---|---|
| **`WB_REFRESH_TOKEN`** | **长效令牌（明文）** —— 云端自行换取接口令牌 | **5.6.2+（推荐）** | 二选一 |
| `WB_ACCESS_TOKEN` | 短效接口令牌直通 | 5.5.x 及更早 | 二选一 |
| `WB_DOMAIN` | 接口域名，通常为 `www.codebuddy.cn` | 全部 | 可选（有默认值） |

> 注意：令牌很长，**不要手动框选复制**（极易漏字符导致 401）。脚本通过 `gh secret set` 的 stdin 写入，不会出现在命令行历史里。
>
> 旧变量名 `WORKBUDDY_ACCESS_TOKEN` / `WORKBUDDY_DOMAIN` 仍被脚本接受（向后兼容），但新配置请使用 `WB_` 前缀。

**没有安装 `gh`？** 脚本会自动降级为手动指引：

1. 仓库 `Settings → Secrets and variables → Actions → New repository secret`
2. 添加 `WB_REFRESH_TOKEN`：运行 `python scripts/copy_token_to_clipboard.py` 复制到剪贴板后粘贴（不在屏幕打印，避免凭据留存终端历史）
3. （可选）添加 `WB_DOMAIN`：值填本机登录态里的 `auth.domain`（也可用 `python scripts/copy_token_to_clipboard.py --domain` 复制）

> ⚠️ 若脚本提示「加密信封，无法解密」，说明本机登录态是 5.6.2+ 的加密形态。
> 此时**不要**把文件里的值直接复制粘贴 —— 请按脚本给出的指引先导出**明文长效令牌**。

### 手动验证

到仓库 **Actions** 页面 → 选择「WorkBuddy 每日自动签到」→ **Run workflow**。
首次建议勾选 `check_only`（仅查询，不领取）确认接口联通，再跑一次真实签到。看到 `status: ok` 即配置成功。

---

## 通知配置（可选）

在 Secrets 中添加以下任意通道（可同时配置多个）：

| Secret 名 | 用途 | 获取方式 |
|---|---|---|
| `WECOM_WEBHOOK` | 企业微信群机器人 | 群设置 → 群机器人 → 添加 → 复制 Webhook |
| `PUSHPLUS_TOKEN` | 个人微信推送 | 注册 https://www.pushplus.plus ，复制一对一推送 token |
| `BARK_URL` | iOS 推送 | 安装 Bark App，复制 `https://api.day.app/<KEY>/` |
| `SERVERCHAN_SENDKEY` | 个人微信推送（Server酱 / 方糖） | 微信扫码登录 https://sct.ftqq.com ，复制 SendKey（形如 `SCTxxxxx`） |
| `SUCCESS_NOTIFY` | 设为 `true` 时签到成功也播报（默认仅失败提醒） | 填 `true` |

```bash
# 也可在同步凭据时一并写入通知 Secret
python scripts/sync_token_to_github.py \
  --wecom "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxx"
```

全部留空则静默运行，仅靠 Actions 页面查看结果。

---

## 运行结果说明

签到脚本输出 JSON，关键字段：

| status | action | 含义 | 处理 |
|---|---|---|---|
| `ok` | `clicked` | 本次领取成功 | 查看 `points`（本次积分）、`balance`（余额） |
| `ok` | `skip_already_signed` | 今日已签到，自动跳过 | 正常，无需处理 |
| `ok` | `skip_check_only` | 仅查询模式 | 查看 `detail.today_signed` |
| `error` | `failed` | 签到失败 | 查看 `msg`，见下表 |

`detail.credential` 会写明本次实际使用的凭据通道（如 `refresh_token（长效令牌）`），便于排查。

**失败常见原因**

| msg 关键词 | 原因 | 解决 |
|---|---|---|
| 长效令牌刷新失败 | `WB_REFRESH_TOKEN` 已失效 | 本机重跑 `python scripts/sync_token_to_github.py` |
| 加密信封 / 云端无法解密 | Secret 里填的是 5.6.2+ 的登录态原始值 | 改用**明文长效令牌**：本机导出后填 `WB_REFRESH_TOKEN` |
| 401 / 未授权 / token 失效 | `WB_ACCESS_TOKEN` 已过期 | 重跑 `sync_token_to_github.py`，或改用长效令牌通道 |
| 404 | 域名错误 | 检查 `WB_DOMAIN` 是否为本机 `auth.domain` 的值 |
| 网络错误 | runner 网络问题 | 重跑 workflow，或临时改用手动触发 |
| 未配置任何凭据 | Secret 未配置 | 按「配置 Secrets」步骤操作 |

---

## 凭据续期

| 通道 | 有效期 | 续期方式 |
|---|---|---|
| `WB_REFRESH_TOKEN`（长效令牌） | 约 60 天 | 重新登录客户端后，本机重跑 `python scripts/sync_token_to_github.py` |
| `WB_ACCESS_TOKEN`（短效令牌） | 约 2 个月 | 同上 |

续期脚本会覆盖旧 Secret，无需其他操作。依赖「失败推送」通道即可在过期时收到提醒。

---

## 本地自测（可选）

```bash
# 1. 环境自检（读取本机登录态 / 检查凭据通道与网络）
python scripts/workbuddy_checkin.py --diagnose

# 2. 用环境变量模拟 CI 环境
export WB_ACCESS_TOKEN="你的短效令牌"     # 或 WB_REFRESH_TOKEN="你的长效令牌"
export WB_DOMAIN="www.codebuddy.cn"
python scripts/workbuddy_checkin.py --check-only   # 只查不领
python scripts/workbuddy_checkin.py                # 查 + 必要时领取

# 3. 推送前安全自检
python security_audit.py
```

---

## 安全说明

### 凭据保护

- 凭据通过 **GitHub Secrets 加密存储**，日志中永不回显。
- **日志脱敏已收紧到「只报长度、连字符片段都不输出」**：Actions 运行日志在公开仓库里人人可读，
  连 `eyJhbG...sw5c` 这种「看起来安全」的片段也属于白送信息，因此一律不回显。
  需要肉眼核对片段时，请在本机单独运行导出脚本（输出不落 CI 日志）。
- 通过 `gh secret set` 的 **stdin** 写入，避免密钥出现在命令行参数（`ps` 可见）中。
- 复制凭据用剪贴板脚本，避免凭据留存在终端历史中。

### 日志脱敏（多层防护）

Actions 运行日志与摘要会长期留存，因此做了多层防护：

| 层级 | 措施 |
|---|---|
| **输出层** | `_slim_resp()` 把接口响应**白名单压缩**后才写入 `detail`：只保留结论字段（`code` / `msg` / `credit` / `total_credits` / `today_checked_in` 等）与**字段名清单**，其余内容一律丢弃。**完整响应永不进入 stdout / `result.json` / artifact / 摘要**（本机调试可临时 `set WB_DUMP_RESP=1` 放开，CI 中永不设置） |
| 脚本层 | 输出 `detail.token_masked` 只含「已配置，长度 N」；`auth_file` 只含路径 / 变量名不含凭据 |
| 摘要层 | `summarize_result.py` **白名单过滤**，只输出结论字段，不输出原始接口响应 |
| 兜底层 | 任何长度 ≥80 的 base64url 风格长串替换为 `<REDACTED>`，防接口变更引入非预期字段 |
| 自检层 | `security_audit.py` 扫描硬编码凭据、**登录态加密信封**、危险代码、敏感文件 |

### 工作流安全

| 项 | 措施 |
|---|---|
| 权限 | `permissions: contents: read`（最小权限） |
| 触发 | 仅 `schedule` + `workflow_dispatch`，**无 `pull_request_target`**（防 PR 投毒） |
| 并发 | `concurrency` 固定组名，防止重复领取 |
| 超时 | `timeout-minutes: 10` |
| 退出码 | 用 `PIPESTATUS[0]` 精确取脚本退出码，确保失败必定告警，不会静默成功 |
| 凭据校验 | 独立的 guard 步骤先确认凭据已配置，缺失时立即失败并给出配置指引 |

### 部署前检查清单

- [ ] `notify_config.json` **未**被提交（`.gitignore` 已覆盖，可 `git status` 确认）
- [ ] 确认提交的文件中无凭据（运行 `python security_audit.py` 自检）
- [ ] 首次部署先用 `check_only` 手动跑一次，确认 `status: ok`
- [ ] 配好失败通知（企微 / PushPlus / Server酱 / Bark），否则失败只能靠 GitHub 邮件
- [ ] **仓库可见性自行评估**：若设为 public，Actions 运行日志对所有人可见（本项目已脱敏无敏感信息，但仍建议在 `Settings → Actions → General` 保持最小权限）；同时请自行评估平台对于自动化脚本刷分的规则风险

### 切勿做的事

- 不要把凭据硬编码进任何文件或 workflow。
- 不要把 `notify_config.json` 提交到仓库。
- **不要把登录态文件（`workbuddy-desktop.info`）或其内容复制进仓库** —— 5.6.2+ 下它是加密信封，既不可用也不该外传。
- 不要把凭据粘贴到聊天工具、Issue、PR 描述中。
- 凭据一旦疑似泄露：立即在本机退出并重新登录 WorkBuddy（使旧凭据失效），再更新 Secret。

---

## 常见问题

**Q：Fork 后需要改代码吗？**
A：不需要。直接配置自己的 Secrets 即可运行，所有凭据都走 Secrets。

**Q：我的客户端是新版，为什么旧教程说的 accessToken 用不了？**
A：5.6.2 起登录态已加密，`accessToken` 不再是明文。请改用**长效令牌** `WB_REFRESH_TOKEN`
（见本文开头「版本对照」表）。脚本会自动识别并提示。

**Q：凭据从哪来？**
A：来自你本机 WorkBuddy 桌面客户端的登录态。`sync_token_to_github.py` 会自动读取并选择正确的凭据类型。

**Q：公开仓库会不会泄露我的凭据？**
A：不会。凭据只存在于你自己的 Secrets，不进代码、不进日志（且日志已收紧为只报长度）。
你 Fork 的仓库别人也读不到你的 Secret。

**Q：签到时间能改吗？**
A：编辑 `.github/workflows/checkin.yml` 里的 `cron` 表达式即可（UTC 时间）。

**Q：一直接收不到失败提醒？**
A：检查是否配置了任一通知通道 Secret；否则失败只体现为 Actions 页面红灯与 GitHub 邮件。

---

## 更新记录

| 版本 | 变更 |
|---|---|
| **`workbuddy_checkin.py` v2.2.0-ci** | 修复**输出层脱敏缺口**：接口响应改为**白名单压缩**后才写入 `detail`，避免完整响应经 `tee` 进入公开的 Actions **运行日志**（此前只有摘要层做了过滤）。新增 `WB_DUMP_RESP=1` 本机调试开关；口径与摘要层统一。 |
| **`workbuddy_checkin.py` v2.1.0-ci** | ① 新增**长效令牌通道**（`WB_REFRESH_TOKEN`）：先向插件网关换取接口令牌再签到，适配套客户端 5.6.2+ 的加密登录态，且不依赖客户端常驻；② 识别登录态**加密信封**并给出明确报错与指引，不再静默鉴权失败；③ 余额字段补齐新版复数 `total_credits`（旧版只认单数，导致余额恒为空）；④ `mask_token()` 收紧为**只报长度**，适配公开仓库的日志可见性；⑤ `--diagnose` 改为报告凭据通道与刷新结果。<br>配套：`sync_token_to_github.py` / `copy_token_to_clipboard.py` 改为优先导出**长效令牌**；`security_audit.py` 新增登录态信封检测；workflow 更新 Secret 注入与 guard 步骤。 |
| v2.0.0 | 首个 GitHub Actions 版本：接口直签、多渠道推送、日志脱敏、部署前自检。 |

---

## 许可证

基于 [MIT 许可证](LICENSE) 开源。
