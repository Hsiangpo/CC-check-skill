<div align="center">

<img src="assets/logo.png" width="180" alt="CC-Check Logo">

# CC-Check

### Claude / Claude Code 系统环境审计与隐私加固工具

**50+ 自动化检测 · 100 分制评分 · 分级修复 · 跨平台支持**

[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-0a0a0a?style=flat-square&logo=apple&logoColor=white)](https://github.com/Hsiangpo/CC-check) [![Python](https://img.shields.io/badge/python-3.9+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/) [![Tests](https://img.shields.io/badge/tests-63%20passed-00C853?style=flat-square&logo=pytest&logoColor=white)](https://github.com/Hsiangpo/CC-check/actions) [![Version](https://img.shields.io/badge/version-1.3.0-FF6F00?style=flat-square&logo=semver&logoColor=white)](https://github.com/Hsiangpo/CC-check) [![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)

<br>

<p>
  <strong>在非支持地区使用 Claude Code？你的系统环境可能正在泄露你的真实位置。</strong>
</p>

<sub>DNS 泄露 · 中国镜像残留 · 时区错配 · IP 被标记为代理 — 这些信号让风控瞬间锁定你。</sub>

<br>
<br>

<h3>🏆 Score: 100 / 100 &nbsp;&nbsp; Grade: A+ &nbsp;&nbsp; (100.0%)</h3>

| 审计组 | 得分 | 权重 | 覆盖率 |
|:------|-----:|-----:|:------|
| 🎯 IP 纯净度 | **30** | 30 | 🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩 100% |
| 🌐 系统环境 | **21** | 21 | 🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩 100% |
| 🔒 DNS 防护 | **15** | 15 | 🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩 100% |
| 📡 网络一致性 | **10** | 10 | 🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩 100% |
| ⚙️ Clash 状态 | **8** | 8 | 🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩 100% |
| 📦 包管理器 | **6** | 6 | 🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩 100% |
| 🛡️ 隐私清洁 | **6** | 6 | 🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩 100% |
| 🟢 Node.js | **2** | 2 | 🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩 100% |
| 👤 身份信息 | **1** | 1 | 🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩 100% |
| 🤖 Claude | **1** | 1 | 🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩 100% |

</div>

---

> [!CAUTION]
> ## ⛔ 必须在登录前运行
> 
> **CC-Check 是登录前的环境自检工具，不是登录后的补救工具。**
> 
> 启动 Claude / Claude App / Claude Code 之前，你的系统环境必须已经通过审计。登录后再检测意味着你已经带着泄露风险完成了一次连接——风控系统可能已经记录了你的环境指纹。
> 
> **正确顺序：先审计 → 达到 A+ → 再启动 Claude**

---

## ⚡ 30 秒上手

```bash
git clone https://github.com/Hsiangpo/CC-check.git && cd CC-check

# 一行命令，完整闭环：审计 → 修复 → 验证
python scripts/cc_check.py full
```

> **零依赖** — 纯 Python 3.9+ 标准库，无需 `pip install`，开箱即用。
>
> **默认只自动执行低风险修复**：系统级网络改动、shell history 删除、输入法安装/移除，必须显式传入 `--allow-*` 旗标才会真正执行。

<details>
<summary>📦 更多命令</summary>

```bash
# 仅审计（推荐先跑一遍看看）
python scripts/cc_check.py inspect

# JSON 输出（接入 CI/CD 自动化）
python scripts/cc_check.py inspect --json

# 预览修复（不实际执行）
python scripts/cc_check.py fix-local --dry-run

# 显式允许系统级 DNS 修复
python scripts/cc_check.py fix-local --allow-static-dns --allow-dns-watchdog

# 显式允许删除 shell history 命中行
python scripts/cc_check.py fix-local --allow-shell-history-cleanup

# 显式允许输入法改动
python scripts/cc_check.py fix-local --allow-rime-install --allow-ime-removal

# 浏览器泄露检查（默认自动探测 Playwright，失败则回退为手工清单）
# 可自动化项：JS 时区/语言、WebRTC、浏览器出口 IP、字体、Canvas、WebGL、TLS 页面
python scripts/cc_check.py browser-leaks --json

# 强制关闭自动化，仅输出 Python 基线 + 手工清单
python scripts/cc_check.py browser-leaks --automation off

# 自定义目标参数
python scripts/cc_check.py inspect \
  --target-timezone America/Los_Angeles \
  --target-locale en_US.UTF-8 \
  --proxy-url http://127.0.0.1:7897 \
  --expected-ip-type residential

# 也可以作为 LLM Agent Skill 直接调用
> 帮我检查一下终端环境
> 修复 DNS 泄露
> 跑一轮完整的环境审计
```

</details>

---

## 🔬 检测什么？

<table>
<tr>
<td width="50%">

### 🔴 高危 — 直接触发风控

| 信号 | 检测方法 |
|------|---------|
| **中国 ISP DNS** | Google/Cloudflare DNS whoami |
| **IP = 机房/VPN** | 5 渠道交叉验证 |
| **伪住宅 IP** | ASN + proxycheck + 风险评分 |
| **时区/语言错配** | 系统 vs 代理目标对比 |

</td>
<td width="50%">

### 🟡 中危 — 间接暴露位置

| 信号 | 检测方法 |
|------|---------|
| **npm/pip 中国镜像** | registry 配置 + 缓存扫描 |
| **GOPROXY 中国源** | `go env` 检测 |
| **Docker 中国镜像** | daemon.json 扫描 |
| **Git remote (gitee)** | `.git/config` 扫描 |

</td>
</tr>
<tr>
<td>

### 🟢 低危 — 本地指纹残留

| 信号 | 检测方法 |
|------|---------|
| **VS Code 中文 locale** | settings.json |
| **SSH 连接过中国 IP** | known_hosts 扫描 |
| **非系统捆绑中文字体** | 字体目录扫描 |
| **Git 全局身份** | git config |

</td>
<td>

### ⚙️ 代理状态

| 信号 | 检测方法 |
|------|---------|
| **Clash 进程 / 模式** | 进程检测 + API 查询 |
| **TUN 模式开启** | 网络接口 + 配置检查 |
| **DNS 加固标记** | 运行时配置扫描 |
| **DNS 守护进程** | 守护文件存在性检查 |

</td>
</tr>
</table>

---

## 🎯 IP 纯净度 — 五渠道交叉验证

> 占总分 **30%**，权重最高。单一渠道容易被绕过，五渠道交叉几乎无法伪造。

```
                  +----------+
                  | Your  IP |
                  +----+-----+
                       |
          +------------+------------+
          |            |            |
     +----+-----+ +---+----+ +-----+-----+
     |ipinfo.io | |ip-api  | |proxycheck |
     | Geo+ASN  | |Type+ISP| | Risk+VPN  |
     +----+-----+ +---+----+ +-----+-----+
          |            |            |
          +------+-----+-----+-----+
                 |           |
          +------+---+ +----+-----+
          | bgpview  | |  whois   |
          | BGP/RIR  | | Country  |
          +------+---+ +----+-----+
                 |           |
                 +-----+-----+
                       |
              +--------+--------+
              |   Classification |
              | residential/idc  |
              +-----------------+
```

<details>
<summary>💡 伪住宅 IP 检测原理</summary>

IDC 隧道包装的"伪住宅"IP（标注为 residential，实际由数据中心中转）通过以下特征识别：

- ASN 不在已知住宅 ISP 白名单中（Comcast、AT&T、Verizon 等）
- `proxycheck.io` 返回类型 ≠ residential
- 风险评分 > 66/100

检测到伪住宅 IP 时会建议更换为真实家宽节点。

</details>

---

## 🔧 分级修复

CC-Check 不仅是扫描器，更是**按风险分层执行的修复引擎**：

```bash
python scripts/cc_check.py fix-local                                # 仅执行低风险修复
python scripts/cc_check.py fix-local --dry-run                      # 预览所有候选修复
python scripts/cc_check.py fix-local --allow-static-dns             # 允许系统级 DNS 锁定
python scripts/cc_check.py fix-local --allow-dns-watchdog           # 允许安装后台 DNS 守护
python scripts/cc_check.py fix-local --allow-shell-history-cleanup  # 允许删除命中 history 行
```

> 默认 `fix-local` 只会自动处理低风险项目：
> shell profile 环境变量、Claude telemetry、Git 全局身份、npm/pip/brew 镜像、Clash Verge `enable_dns_settings`。
>
> 下列高风险/系统级动作必须显式传入 `--allow-*`：
>
> | Flag | 动作 | 风险 |
> |------|------|------|
> | `--allow-static-dns` | 锁定系统静态 DNS | 会持久修改系统网络配置 |
> | `--allow-dns-watchdog` | 安装 DNS 守护任务 | 会创建持续运行的后台任务 |
> | `--allow-shell-history-cleanup` | 删除命中的 shell history 行 | 会改写历史记录文件 |
> | `--allow-rime-install` | 安装 RIME 输入法 | 会安装系统级软件 |
> | `--allow-ime-removal` | 移除系统中文输入法 | 会修改输入法配置，带不可逆风险 |

<table>
<tr><th>修复项</th><th>macOS</th><th>Linux</th><th>Windows</th></tr>
<tr>
  <td><strong>🌐 DNS 根治</strong><br><sub>DHCP 防覆盖静态 DNS</sub></td>
  <td>✅ <code>networksetup</code> + <code>scutil</code></td>
  <td>✅ <code>nmcli</code> + <code>ignore-auto-dns</code></td>
  <td>✅ <code>netsh static</code></td>
</tr>
<tr>
  <td><strong>⏱️ DNS 守护</strong><br><sub>自动检测并纠正 DNS 篡改</sub></td>
  <td>✅ LaunchAgent 15s</td>
  <td>✅ systemd timer 15s</td>
  <td>✅ Task Scheduler 60s</td>
</tr>
<tr>
  <td><strong>🐚 Shell 环境</strong><br><sub>TZ / LANG / PROXY 变量</sub></td>
  <td>✅ zsh / bash / fish</td>
  <td>✅ bash / zsh / fish</td>
  <td>✅ PowerShell</td>
</tr>
<tr>
  <td><strong>📦 包管理器</strong><br><sub>中国镜像源清除</sub></td>
  <td>✅ npm / pip / brew</td>
  <td>✅ npm / pip / brew</td>
  <td>✅ npm / pip</td>
</tr>
<tr>
  <td><strong>🔒 隐私清理</strong><br><sub>遥测 / Git 身份</sub></td>
  <td>✅</td>
  <td>✅</td>
  <td>✅</td>
</tr>
</table>

<details>
<summary>🛡️ 为什么 DNS 需要三层防护？</summary>

家用路由器会通过 DHCP 推送中国 ISP DNS（如 `114.114.114.114`），即使手动清除也会在网络重连时恢复：

| 层级 | 机制 | 作用 |
|------|------|------|
| **Layer 1** | `networksetup` / `nmcli` / `netsh` | 设置手动 DNS，覆盖 DHCP |
| **Layer 2** | `scutil` StaticDNS / `resolved.conf` | 创建更高优先级 DNS，DHCP 无法覆盖 |
| **Layer 3** | 守护进程 (15-60s) | 自动检测漂移并纠正 |

三层叠加后，路由器 DHCP 再怎么推 `114.114.114.114`，也写不进去了。

Windows 下 watchdog 会以 `Task Scheduler /RL HIGHEST` 创建任务，但仍建议用管理员 PowerShell 执行，避免任务创建成功但实际没有权限改 DNS。

</details>

---

## 📊 评分体系

<div align="center">

| 等级 | 分数 | 状态 | 含义 |
|:----:|:----:|:----:|------|
| **A+** | ≥ 95 | 🟢 | 生产安全，环境完全对齐 |
| **A** | ≥ 90 | 🟢 | 仅有轻微外观问题 |
| **B** | ≥ 80 | 🟡 | 可接受，存在已知 warn |
| **C** | ≥ 70 | 🟠 | 存在显著缺口 |
| **D** | ≥ 60 | 🔴 | 需要关注的失败项 |
| **F** | < 60 | ⛔ | 检测到关键风险 |

</div>

> **权重**：IP 纯净度 (30) > 系统 (21) > DNS (15) > 网络 (10) > Clash (8) > 包管理 (6) > 隐私 (6) > Node.js (2) > 身份 (1) > Claude (1)

---

## 🏗️ 架构

```
cc-check/
├── SKILL.md                       # LLM Agent skill 入口
├── agents/                        # 多平台 Agent 配置
│   ├── openai.yaml                #   OpenAI Codex
│   ├── claude.yaml                #   Claude Code
│   └── gemini.yaml                #   Gemini CLI
├── references/
│   ├── check-matrix.md            # 完整审计矩阵（50+ 检测项）
│   └── rationale.md               # 设计决策与修复逻辑
├── scripts/
│   ├── cc_check.py                # 🎯 主编排器 & CLI（~1100 行）
│   ├── platform_ops.py            # 💻 跨平台抽象层（~1500 行）
│   ├── ip_quality.py              # 🌐 5 渠道 IP 质量评估
│   ├── scoring.py                 # 📊 100 分制评分引擎
│   ├── vpn_adapter.py             # 🔌 VPN 项目适配器
│   ├── browser_leaks.py           # 🔍 浏览器泄露检测编排
│   ├── browser_automation.py      # 🤖 Playwright 能力探测与执行
│   └── browser_automation_runner.mjs # 🌐 浏览器数据采集 runner
└── tests/
    └── test_cc_check.py           # ✅ 63 个单元测试
```

---

## 🔒 安全设计

<table>
<tr>
<td>🔑</td>
<td><strong>零硬编码凭据</strong></td>
<td>所有路径通过 <code>Path.home()</code> 动态推导</td>
</tr>
<tr>
<td>🔏</td>
<td><strong>输出脱敏</strong></td>
<td><code>redact_text()</code> 过滤 SSH 凭据、订阅链接等敏感值</td>
</tr>
<tr>
<td>🛡️</td>
<td><strong>无 Shell 注入</strong></td>
<td><code>subprocess.run(cwd=)</code> 代替字符串拼接</td>
</tr>
<tr>
<td>👁️</td>
<td><strong>--dry-run</strong></td>
<td>所有修复命令支持预览模式</td>
</tr>
<tr>
<td>⚠️</td>
<td><strong>安全边界</strong></td>
<td>系统语言、输入法、hosts 文件只报告不自动修改</td>
</tr>
</table>

---

## 🧪 测试

```bash
# 运行全部 63 个单元测试
python -m unittest discover -s tests -v

# CI: macOS + Linux + Windows × Python 3.10/3.11/3.12 = 9 矩阵
# 参见 .github/workflows/test.yml
```

---

## 📋 修复策略分级

### ✅ 自动修复（安全，无需确认）

| 检测项 | 修复方式 |
|-------:|---------|
| Shell profile 环境变量 | 直接写入 |
| Claude 遥测数据 | 清理 `~/.claude/` |
| Git 全局身份 | 重写 `user.name` / `user.email` |
| npm / pip / brew 镜像 | 重置为官方源 |

### ⚠️ 需要显式 `--allow-*` 的系统级修复

| 检测项 | 旗标 | 风险说明 |
|-------:|------|---------|
| 系统静态 DNS | `--allow-static-dns` | 持久锁定 DNS，防止 DHCP 覆盖 |
| DNS 守护进程 | `--allow-dns-watchdog` | 安装系统后台任务（每 15-60 秒自动校正） |

### 🔒 需要用户明确同意才执行

| 检测项 | 旗标 | 原因 |
|-------:|------|------|
| Shell 历史清理 | `--allow-shell-history-cleanup` | 会改写历史记录文件；现已收紧为明确镜像/DNS/域名模式 |
| RIME 输入法安装 | `--allow-rime-install` | 系统级软件安装 |
| 系统中文输入法移除 | `--allow-ime-removal` | 会修改输入法配置 |

### ❌ 仅审计不修复（设计如此）

| 检测项 | 原因 |
|-------:|------|
| 系统语言 | 全局修改风险过高 |
| 度量单位 / 时间格式 | 系统级设置，不适合自动改 |
| /etc/hosts | 修改风险较高 |
| VS Code locale | 用户偏好 |
| SSH known_hosts | 可能合法连接中国服务器 |
| 字体指纹 | 系统字体无法安全移除 |

---

## 🤝 贡献

欢迎 PR 和 Issue！

<table>
<tr>
<td align="center">🐧<br><strong>Linux</strong><br><sub>新发行版适配验证</sub></td>
<td align="center">🪟<br><strong>Windows</strong><br><sub>修复逻辑实测</sub></td>
<td align="center">🔌<br><strong>VPN 适配器</strong><br><sub>新项目结构支持</sub></td>
<td align="center">🌐<br><strong>IP 质量</strong><br><sub>新检测渠道集成</sub></td>
</tr>
</table>

---

## 📄 License

[MIT](LICENSE) © [Hsiangpo](https://github.com/Hsiangpo)

---

<div align="center">

<sub>**CC-Check** — 让 API 风控无从下手</sub>

<sub>Built with ❤️ by [@Hsiangpo](https://github.com/Hsiangpo)</sub>

</div>
