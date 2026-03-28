# 🛡️ CC-Check

**专为国内开发者打造的 Claude Code 终端环境审计与加固工具**

[![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux%20%7C%20Windows-blue?style=flat-square)](https://github.com/Hsiangpo/CC-check)
[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/Tests-44%20passed-00C853?style=flat-square)](https://github.com/Hsiangpo/CC-check/actions)
[![Version](https://img.shields.io/badge/Version-1.3.0-FF6F00?style=flat-square)](https://github.com/Hsiangpo/CC-check)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)

> **在中国使用 Claude Code？这就意味着你需要警惕风险。**
> 
> DNS 泄露、中国镜像源残留、时区错配、代理 IP 质量低劣 —— 这些微小的终端特征，每天都在被海外 API 严格的风控系统捕获，最终导致账户被限速、风控甚至封禁。
> 
> **CC-Check 能一次性彻底扫描并解决这些问题。**

---

## ✨ 核心特性

- **🤖 为 LLM Agent 而生**：完美适配 Claude Code, Gemini CLI, OpenAI Codex 等工具。
- **🔍 50+ 深度检测项**：从系统时间到 `npm` 镜像，从底层 DNS 劫持到浏览器探针泄漏。
- **💯 100分制量化风险**：根据风控严重程度（高危/中危/低危）精确计算你的环境安全分。
- **🔨 一键自动修复**：跨平台（macOS/Linux/Windows）原生修复，支持 `--dry-run` 预览。
- **🛡️ 独家 DHCP 免疫 DNS 防护**：深入系统底层，锁定系统级 DNS，彻底解决路由器强推 `114.114.114.114` 导致的循环被黑问题（含自动守护 Watchdog）。

## 🚀 30 秒快速开始

**零额外依赖** — 仅需纯 Python 3.9+ 标准库环境。

```bash
git clone https://github.com/Hsiangpo/CC-check.git && cd CC-check

# 完整闭环：一键检测 → 自动修复 → 重新验证
python scripts/cc_check.py full
```

### 更多高阶用法

```bash
# 仅执行深度体检（推荐首次运行）
python scripts/cc_check.py inspect

# 返回 JSON 格式（适合作为 CI/CD 的一环）
python scripts/cc_check.py inspect --json

# 仅预览修复命令脚本（安全确认）
python scripts/cc_check.py fix-local --dry-run
```

---

## 🔬 到底检测了什么？

CC-Check 的审计矩阵涵盖 11 个细分领域，精准打击常见风控检测锚点。

### 🔴 高危信号（直接触发风控封号）

*   **中国 ISP DNS 劫持**：通过 Google/Cloudflare DNS whoami 深度校验。
*   **低质量伪装 IP**：5 大权威渠道（ipinfo / proxycheck 等）交叉识别机房 IP 与伪住宅 IP。
*   **时区与语言错位**：检测本地系统环境与代理出口目标地理位置的冲突。
*   **网络侧漏**：公网 IP 连通性、多源 IP 归属一致性校验、IPv6 裸连侧漏。

### 🟡 中危信号（间接暴露出境路径）

*   **包管理器国内源**：扫描并修复 `npm` / `pip` / `brew` 中的 Taobao、Tuna 等镜像。
*   **开发生态镜像**：检测 `GOPROXY`、Docker `daemon.json` 中的中国源加速配置。
*   **代码托管痕迹**：扫描 Git Remote 配置中的国内托管平台（Gitee、Coding 等）。

### 🟢 低危指纹（潜在的大数据关联）

*   **工具链本地化**：VS Code 的中文 Locale 检测、系统附加的非原生中文字体指纹。
*   **历史连接脚印**：扫描 SSH `known_hosts` 中指向国内服务器的连接历史。
*   **代理客户端状态**：Clash TUN 虚拟网卡状态、进程检测以及 DNS 加固标记。

---

## 🛠 一键修复与防护能力

只需执行 `python scripts/cc_check.py fix-local`，工具将为你解决下述全部问题。

| 防护层级 | macOS | Linux | Windows | 解决的痛点 |
| :--- | :--- | :--- | :--- | :--- |
| **🌐 静态 DNS 锁定** | `networksetup` + `scutil` | `nmcli` + `ignore-auto` | `netsh static` | 免疫底层网络环境 DHCP 强推的国内 DNS |
| **⏱️ DNS 动态守护进程** | LaunchAgent (15s) | systemd timer (15s) | Task Scheduler (60s) | 防止企业级网络软件或 VPN 客户端暴力篡改 |
| **🐚 Shell 变量清洗** | `.zshrc` / `.bashrc` | `.bashrc` / `.zshrc` | PowerShell Profile | 抹除终端里可能泄露的 `TZ` / `LANG` 痕迹 |
| **📦 镜像源修正** | `npm` / `pip` / `brew` | `npm` / `pip` / `brew` | `npm` / `pip` | 自动恢复官方海外源，掐断国内请求特征 |

> **DNS 三层立体防护解析**：路由器会不停地通过 DHCP 强推下发运营商 DNS (如 114) 或代理网关。CC-Check 会：通过底层网络命令锁定静态 DNS；创建最高优先级系统配置阻断修改；部署常驻守护进程检测微秒级漂移。**真正实现一劳永逸。**

---

## 📊 计分评级系统

量化环境的脆弱程度，总分 100 分。

```text
╔══════════════════════════════════════════════════════════╗
║   CC-Check Score:  100 / 100    Grade: A+    (100.0%)    ║
╠══════════════════════════════════════════════════════════╣
║   ip-quality     30/30   ██████████████████████  100.0%  ║
║   system         21/21   ██████████████████████  100.0%  ║
║   dns            15/15   ██████████████████████  100.0%  ║
║   network        10/10   ██████████████████████  100.0%  ║
║   ...                                                    ║
╚══════════════════════════════════════════════════════════╝
```

*   A+ (95~100): 🟢 极其安全，随便用
*   B (80~89): 🟡 比较安全，但有已知短板
*   D (60~69): 🔴 极度危险，极易被标记
*   F (<60): ⛔ 裸奔状态，立刻停止调用 API

---

## 🔒 你必须知道的安全边界

作为一个具有高级系统修改权限的安全脚本，CC-Check 坚守以下底线：

1. **绝对隐私**：不含任何硬编码秘钥，支持脱敏过滤（`redact_text`）。
2. **无注入**：全面采用安全的 `subprocess.run(cwd=)` 而非危险的壳层拼接。
3. **只读保护**：提供完全无损的 `--dry-run` 实况预览。
4. **人工界限**：系统级别的危险操作（如替换全局中文显示语言、全局删改 Hosts、清除输入法）只会报警提示，**不会**替用户自动修改。

---

## 🤝 参与项目

我们非常欢迎各位提交 PR 共同维护这份安全基线：

*   🐧 **Linux**：各大冷门发行版修复逻辑的边界兼容验证
*   🪟 **Windows**：PowerShell 执行策略与注册表修复实测
*   🌐 **IP 评价体系**：引入更新、更准的 IP 风险大数据接口检测

## 📄 License

[MIT License](LICENSE) © [Hsiangpo](https://github.com/Hsiangpo)
