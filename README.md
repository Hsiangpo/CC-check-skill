<div align="center">

<br>

<img src="https://img.shields.io/badge/%E2%9C%A6-CC--Check-0d1117?style=for-the-badge&labelColor=0d1117" height="60">

<br>
<br>

# 终端环境审计与加固工具

**在中国使用 Claude Code？这个工具帮你消除所有环境指纹。**

<br>

[![macOS](https://img.shields.io/badge/macOS-000000?style=flat-square&logo=apple&logoColor=white)](#)
[![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat-square&logo=linux&logoColor=black)](#)
[![Windows](https://img.shields.io/badge/Windows-0078D6?style=flat-square&logo=windows&logoColor=white)](#)
&nbsp;&nbsp;
[![Python 3.9+](https://img.shields.io/badge/Python_3.9+-3776AB?style=flat-square&logo=python&logoColor=white)](#)
[![Tests 44](https://img.shields.io/badge/测试_44_通过-00C853?style=flat-square&logo=checkmarx&logoColor=white)](#)
[![v1.3.0](https://img.shields.io/badge/v1.3.0-FF6F00?style=flat-square)](#)
[![MIT](https://img.shields.io/badge/MIT-blue?style=flat-square)](#)

<br>

---

**`50+ 项自动检测`**&emsp;·&emsp;**`100 分制量化评分`**&emsp;·&emsp;**`一键修复`**&emsp;·&emsp;**`三层 DNS 防护`**&emsp;·&emsp;**`零依赖`**

---

</div>

<br>

## 🎯 解决什么问题

在中国使用 Claude Code 时，你的终端环境中隐藏着大量地理位置指纹：

```
❌  系统 DNS 被路由器推送为 114.114.114.114（即使你开了代理）
❌  npm registry 指向 npmmirror.com / taobao 镜像
❌  pip 源还在用阿里云 / 清华 TUNA
❌  时区设置为 Asia/Shanghai，语言为 zh_CN
❌  IP 被识别为机房 / VPN / 代理（非住宅宽带）
❌  Git 全局身份暴露中文姓名
```

这些信号会被 AI 服务商的多维度风控模型捕获，导致 **限速、降级、甚至封号**。

**CC-Check 一键扫描全部问题，一键修复。**

<br>

## ⚡ 30 秒上手

```bash
git clone https://github.com/Hsiangpo/CC-check.git && cd CC-check

# 完整闭环：审计 → 修复 → 验证
python scripts/cc_check.py full
```

> 💡 **零依赖** — 纯 Python 标准库，无需 `pip install`，克隆即用。

<br>

<details>
<summary><strong>📦 更多命令</strong></summary>

<br>

```bash
# 仅审计
python scripts/cc_check.py inspect

# JSON 输出（可接 CI/CD）
python scripts/cc_check.py inspect --json

# 预览修复（不实际执行）
python scripts/cc_check.py fix-local --dry-run

# 自定义目标
python scripts/cc_check.py inspect \
  --target-timezone America/Los_Angeles \
  --target-locale en_US.UTF-8 \
  --proxy-url http://127.0.0.1:7897 \
  --expected-ip-type residential
```

也可作为 **LLM Agent Skill** 直接在 Codex / Claude Code / Gemini CLI 中使用：

```
> 帮我检查一下终端环境
> 修复 DNS 泄露
> 跑一轮完整的环境审计
```

</details>

<br>

## 📊 评分报告

每次审计生成量化评分，哪里有问题一目了然：

```
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║   CC-Check Score:  100 / 100    Grade: A+    (100.0%)    ║
║                                                          ║
╠══════════════════════════════════════════════════════════╣
║   ip-quality     30/30   ██████████████████████  100.0%  ║
║   system         21/21   ██████████████████████  100.0%  ║
║   dns            15/15   ██████████████████████  100.0%  ║
║   network        10/10   ██████████████████████  100.0%  ║
║   clash           8/8    ██████████████████████  100.0%  ║
║   packages        6/6    ██████████████████████  100.0%  ║
║   privacy         6/6    ██████████████████████  100.0%  ║
║   nodejs          2/2    ██████████████████████  100.0%  ║
║   identity        1/1    ██████████████████████  100.0%  ║
║   claude          1/1    ██████████████████████  100.0%  ║
╚══════════════════════════════════════════════════════════╝
```

<div align="center">

| 等级 | 分数 | 含义 |
|:----:|:----:|------|
| 🏆 **A+** | ≥ 95 | 环境完全对齐，安全生产 |
| 🟢 **A** | ≥ 90 | 仅有轻微外观问题 |
| 🟡 **B** | ≥ 80 | 可接受，存在已知 warn |
| 🟠 **C** | ≥ 70 | 存在显著缺口 |
| 🔴 **D** | ≥ 60 | 需要关注的失败项 |
| ⛔ **F** | < 60 | 存在关键风险 |

</div>

<br>

## 🔬 检测能力矩阵

<table>
<tr>
<td width="50%" valign="top">

### 🔴 高危 — 直接触发风控

```
检测项                  方法
─────────────────────────────────
中国 ISP DNS           Google/CF whoami
IP = 机房/VPN          5 渠道交叉验证
伪住宅 IP              ASN + 风险评分
时区/语言错配           系统 vs 目标对比
代理环境变量缺失        环境变量检查
```

</td>
<td width="50%" valign="top">

### 🟡 中危 — 间接暴露位置

```
检测项                  方法
─────────────────────────────────
npm/pip 中国镜像        registry 配置
GOPROXY 中国源          go env
Docker 中国镜像         daemon.json
brew 中国变量           HOMEBREW_* 环境
中国镜像缓存残留        npm 缓存扫描
```

</td>
</tr>
<tr>
<td valign="top">

### 🟢 低危 — 本地指纹残留

```
检测项                  方法
─────────────────────────────────
VS Code 中文 locale    settings.json
SSH 连过中国 IP         known_hosts
非捆绑中文字体          字体目录扫描
Git 全局身份            git config
Git remote (gitee)     .git/config
```

</td>
<td valign="top">

### ⚙️ 代理客户端状态

```
检测项                  方法
─────────────────────────────────
Clash 进程/模式         进程 + API
TUN 模式               网络接口 + 配置
DNS 加固标记            运行时配置
DNS 守护进程            文件存在性
Claude 设置语言         settings.json
```

</td>
</tr>
</table>

<br>

## 🎯 IP 质量检测 — 五渠道交叉验证

> 占总分 **30%**，权重最高。单渠道可绕过，五渠道交叉验证几乎不可能伪造。

```
                         ┌──────────┐
                         │  你的 IP  │
                         └─────┬────┘
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
       ┌────────────┐  ┌────────────┐  ┌──────────────┐
       │  ipinfo.io  │  │  ip-api.com │  │ proxycheck.io│
       │  地理 + ASN  │  │ 类型 + ISP  │  │  风险 + VPN   │
       └──────┬─────┘  └──────┬─────┘  └──────┬───────┘
              │               │               │
              ▼               ▼               ▼
       ┌────────────┐  ┌────────────┐
       │ bgpview.io  │  │   whois    │
       │  BGP / RIR  │  │  注册国家   │
       └──────┬─────┘  └──────┬─────┘
              │               │
              ▼               ▼
       ┌──────────────────────────────┐
       │      综合判定（共识机制）       │
       │   住宅宽带 / 代理 / 机房 IP    │
       └──────────────────────────────┘
```

<details>
<summary>💡 <strong>伪住宅 IP 检测原理</strong></summary>

<br>

IDC 隧道包装的"伪住宅"IP（标注为 residential，但实际由数据中心中转）通过以下特征识别：

- ASN 不在已知住宅 ISP 白名单（Comcast、AT&T、Verizon 等）
- `proxycheck.io` 返回类型 ≠ residential
- 风险评分 > 66/100

检测到伪住宅 IP 时会建议更换为真实家宽节点。

</details>

<br>

## 🔧 自动修复

CC-Check 不只是扫描器，它能**自动修复**绝大多数问题：

```bash
python scripts/cc_check.py fix-local          # 执行修复
python scripts/cc_check.py fix-local --dry-run  # 先预览再决定
```

<br>

### 🌐 DNS 三层防护

> 家用路由器 DHCP 会反复推送 `114.114.114.114`，清了又来。CC-Check 用三层防护**根治**这个问题。

| 层级 | macOS | Linux | Windows |
|:----:|-------|-------|---------|
| **L1 · 手动 DNS** | `networksetup` | `nmcli` + `ignore-auto-dns` | `netsh static` |
| **L2 · 系统级覆盖** | `scutil` StaticDNS | `resolved.conf` | — |
| **L3 · 守护进程** | LaunchAgent `15s` | systemd timer `15s` | Task Scheduler `60s` |

三层叠加后，DHCP 推什么都写不进去。

<br>

### 🛠️ 修复能力总览

| 修复项 | macOS | Linux | Windows |
|--------|:-----:|:-----:|:-------:|
| DNS 根治（DHCP 防覆盖） | ✅ | ✅ | ✅ |
| DNS 自动守护 | ✅ | ✅ | ✅ |
| Shell 环境（TZ/LANG/PROXY） | ✅ | ✅ | ✅ |
| npm / pip / brew 镜像 | ✅ | ✅ | ✅ |
| Claude 遥测清理 | ✅ | ✅ | ✅ |
| Git 身份清除 | ✅ | ✅ | ✅ |

> 所有修复支持 `--dry-run` 预览。不会修改系统语言、输入法、/etc/hosts 等高风险项。

<br>

## 🏗️ 项目结构

```
cc-check/
├── SKILL.md                       # LLM Agent Skill 入口
├── agents/
│   ├── openai.yaml                # OpenAI Codex 配置
│   ├── claude.yaml                # Claude Code 配置
│   └── gemini.yaml                # Gemini CLI 配置
├── references/
│   ├── check-matrix.md            # 完整审计矩阵（50+ 项）
│   └── rationale.md               # 设计决策文档
├── scripts/
│   ├── cc_check.py                # 主编排器 & CLI（~1100 行）
│   ├── platform_ops.py            # 跨平台抽象层（~1500 行）
│   ├── ip_quality.py              # 5 渠道 IP 质量评估
│   ├── scoring.py                 # 100 分制评分引擎
│   ├── vpn_adapter.py             # VPN 项目适配器
│   └── browser_leaks.py           # 浏览器泄露检测
└── tests/
    └── test_cc_check.py           # 44 个单元测试
```

<br>

## 🔒 安全设计

| | 措施 | 说明 |
|:-:|------|------|
| 🔑 | **零硬编码** | 所有路径通过 `Path.home()` 动态推导 |
| 🔏 | **输出脱敏** | `redact_text()` 过滤凭据、订阅链接等 |
| 🛡️ | **无注入** | `subprocess.run(cwd=)` 代替字符串拼接 |
| 👁️ | **预览模式** | 所有修复命令支持 `--dry-run` |
| ⚠️ | **安全边界** | 高风险项只报告，不自动修改 |

<br>

## 🧪 测试

```bash
python -m unittest discover -s tests -v   # 44 个单元测试

# GitHub Actions CI：macOS + Linux + Windows × Python 3.10/3.11/3.12
```

<br>

## 🤝 贡献

欢迎 PR 和 Issue！以下方向特别欢迎：

| 🐧 Linux | 🪟 Windows | 🔌 VPN 适配器 | 🌐 IP 检测 |
|:---------:|:----------:|:------------:|:----------:|
| 新发行版验证 | 修复逻辑实测 | 新项目结构 | 新检测渠道 |

<br>

## 📄 许可证

[MIT](LICENSE)

---

<div align="center">

<br>

**CC-Check** — 让环境指纹无处藏身

<sub>Made by [@Hsiangpo](https://github.com/Hsiangpo)</sub>

<br>

</div>
