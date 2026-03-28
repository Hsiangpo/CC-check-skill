---
name: cc-check
description: Use when auditing or repairing Claude Code proxy alignment, DNS leaks, system fingerprint, public IP quality, package mirrors, or VPN state, especially on macOS and in environments that use Clash Verge or a compatible VPN project.
---

# CC Check

## Overview

Claude Code environment auditor and hardener. It inspects the current machine first, derives a target profile from the public IP when possible, and only repairs items that inspection marks as failed.

Current reality:

- macOS support is the most complete
- Linux and Windows have partial inspection coverage
- VPN project checks work only for supported project layouts, otherwise they cleanly skip

## When to Use

- Claude Code starts failing after proxy, DNS, or locale changes
- A new machine needs to be aligned with the target VPN environment
- Clash Verge shows suspicious DNS values such as `114.114.114.114`
- You want a redacted end-to-end audit with a score, not ad hoc shell checks
- You updated a VPN subscription or node and need to confirm local + public + remote state
- You want to check if any package managers (npm/pip/brew) are using China mirrors
- You need to verify Node.js runtime timezone/locale alignment

Do NOT use this skill for:
- Browser anti-detect work (use dedicated fingerprint browser tools)
- App UI spoofing
- Unrelated VPN providers

## Workflow

1. **Inspect**: Run `inspect` to get a full audit with 100-point score.
2. **Review**: Pass / Fail / Warn / Skip grouped by category.
3. **Fix**: Run `fix-local` for local items, `fix-vpn` for VPN/remote items.
4. **Verify**: Run `verify` to confirm repairs.
5. **Full**: Or run `full` for the complete inspect → fix → verify cycle.

Use `--dry-run` on any fix command to preview changes without applying them.
High-risk/system-level repairs are skipped by default unless the matching `--allow-*` flag is present.

## ⚠️ LLM Interaction Requirements

Before running `fix-local` or `full`, the LLM **MUST** explain any risky flag it is about to add and get explicit consent. The CLI now enforces this boundary: risky actions are skipped unless the corresponding `--allow-*` flag is present.

### Explicit opt-in flags

| Flag | Operation | Risk | What to tell the user |
|------|-----------|------|----------------------|
| `--allow-static-dns` | `set_static_dns()` | Persists system DNS changes even for warn/cosmetic states. | "将锁定系统 DNS 为静态设置（防止 DHCP 覆盖）。这会持久修改系统网络配置。" |
| `--allow-dns-watchdog` | `install_dns_watchdog()` | Installs a persistent background repair task. | "将安装 DNS 守护进程。它会创建持续运行的后台任务；Windows 建议管理员权限执行。" |
| `--allow-shell-history-cleanup` | `clean_shell_history()` | Deletes matched shell history lines. Matching is now strict mirror/DNS/domain patterns, but it still mutates history files. | "将删除命中的 shell history 行。虽然现在只匹配明确的镜像/DNS/域名模式，但仍会改写历史记录文件。" |
| `--allow-rime-install` | `install_rime()` | Installs system input method software. | "将安装 RIME 输入法。这会在系统中新增输入法软件。" |
| `--allow-ime-removal` | `remove_system_chinese_ime()` | Directly edits user input-source configuration. | "将移除系统自带中文输入法（拼音/五笔等）。这是输入法配置变更，可能需要手动恢复。" |

## Commands

```bash
# Inspect with score
python3 <path>/scripts/cc_check.py inspect

# Inspect with JSON output
python3 <path>/scripts/cc_check.py inspect --json

# Preview fixes without applying
python3 <path>/scripts/cc_check.py fix-local --dry-run

# Apply only low-risk fixes
python3 <path>/scripts/cc_check.py fix-local

# Apply DNS-related high-risk fixes
python3 <path>/scripts/cc_check.py fix-local --allow-static-dns --allow-dns-watchdog

# Apply shell history cleanup
python3 <path>/scripts/cc_check.py fix-local --allow-shell-history-cleanup

# Apply input-method changes
python3 <path>/scripts/cc_check.py fix-local --allow-rime-install --allow-ime-removal

# Full cycle
python3 <path>/scripts/cc_check.py full

# Browser baseline + manual checklist
python3 <path>/scripts/cc_check.py browser-leaks --json

# With overrides
python3 <path>/scripts/cc_check.py inspect \
  --target-timezone America/Los_Angeles \
  --target-locale en_US.UTF-8 \
  --proxy-url http://127.0.0.1:7897 \
  --expected-ip-type residential
```

## Audit Groups

The skill currently groups checks into:

- `network`: public IP, multi-source IP, IPv6 leakage
- `ip-quality`: residential / proxy / hosting confidence
- `dns`: actual DNS path, displayed DNS state (TUN-aware: cosmetic DNS downgraded to warn when TUN active)
- `system`: timezone, locale, proxy env, input method, hostname, VS Code locale, font fingerprints
- `nodejs`: Node runtime timezone and locale when Node is available
- `packages`: npm / pip / brew mirror checks, GOPROXY, Docker daemon.json mirrors
- `privacy`: telemetry residue, privacy env, SSH known_hosts China IP scan, shell history
- `identity`: git identity, git remote China-host scan
- `clash`: process, mode, TUN, runtime markers, DNS watchdog
- `claude`: Claude settings
- `vpn`: supported VPN project and remote deployment checks when a compatible project is detected

## Scoring

Each check has a weight (total = 100). Groups and weights:

| Group | Weight | Key checks |
|-------|--------|------------|
| ip-quality | 30 | IP classification (residential/proxy/idc) |
| system | 21 | timezone, locale, proxy-env, hostname, hosts |
| dns | 15 | Google DNS, Cloudflare DNS, system DNS display |
| network | 10 | public IP, multi-source IP, IPv6 leak |
| clash | 8 | process, mode, TUN, markers, watchdog |
| packages | 6 | npm, pip, brew |
| privacy | 6 | telemetry, sessions, env, shell-history |
| nodejs | 2 | node TZ, node locale |
| identity | 1 | git identity |
| claude | 1 | Claude language |

Realistic example (first-time audit, DNS cosmetic + pip mirror + shell history issues):

```
╔════════════════════════════════════════════╗
║  CC-Check Score:  86 / 100  Grade: B   (86.0%)  ║
╠════════════════════════════════════════════╣
║  ip-quality     30/30   ██████████  100.0%  ║
║  system         21/21   ██████████  100.0%  ║
║  dns            10/15   ██████░░░░   66.7%  ║
║  network        10/10   ██████████  100.0%  ║
║  clash           7/8    █████████░   87.5%  ║
║  packages        4/6    ██████░░░░   66.7%  ║
║  privacy         5/6    ████████░░   83.3%  ║
║  nodejs          2/2    ██████████  100.0%  ║
║  identity        1/1    ██████████  100.0%  ║
║  claude          1/1    ██████████  100.0%  ║
╚════════════════════════════════════════════╝
```

Note: 6 informational checks (GOPROXY, Docker mirror, git remotes, VS Code locale, SSH known_hosts, font fingerprint) have `weight=0` and appear as ⚠️ warnings but do not affect the score.

## Fix Policy

### `fix-local` auto-executes (no user consent needed):
- Shell profile files (`~/.zprofile`, `~/.zshrc`, `~/.bashrc`, `~/.bash_profile`, or PowerShell `$PROFILE`)
- `~/.claude/` telemetry data
- Global git config (`user.name`, `user.email`)
- npm / pip / brew registry reset
- Clash Verge `enable_dns_settings` toggle when safe

### `fix-local` requires explicit `--allow-*` opt-in:
- System DNS: DHCP-resistant static DNS (`set_static_dns()`)
  - macOS: `networksetup` + `scutil` StaticDNS override
  - Linux: `nmcli` with `ignore-auto-dns=yes` or `resolved.conf` fallback
  - Windows: `netsh` static DNS mode (⚠️ requires admin privileges)
- DNS cleanup watchdog (macOS LaunchAgent / Linux systemd timer / Windows Task Scheduler)
- Shell history cleanup (`clean_shell_history()`) — strict mirror/DNS/domain pattern deletion, still mutates history files
- RIME input method installation (`install_rime()`) — installs system software
- System Chinese IME removal (`remove_system_chinese_ime()`) — irreversible input method change

`--dry-run` still previews these items without applying them.

### `fix-vpn` may safely mutate:
- Generated files in the detected VPN project root
- Public subscription state via detected deploy script
- Remote VPN service state on configured host

## Low-Risk Findings (reported as `warn`, score impact varies)

- Claude settings language is Chinese
- Google DNS whoami returns Cloudflare Asia PoP
- IP quality uncertain but not flagged
- System measurement units / time format mismatch
- 0-weight informational items: GOPROXY, Docker mirror, git remotes, VS Code locale, SSH known_hosts, font fingerprint

## Privacy Rules

- Never print passwords, tokens, private keys, or subscription secrets
- Never dump full secret-bearing config files
- Summaries must redact sensitive values as `***`
- Remote deployment logs are sanitized before output

## Cross-Platform Notes

- **macOS**: fullest inspection and repair support (3-layer DNS protection)
- **Linux**: full inspection + nmcli/resolved DNS fix + systemd watchdog
- **Windows**: full inspection + netsh static DNS fix + Task Scheduler watchdog
  - ⚠️ DNS watchdog is now created with `schtasks /RL HIGHEST`, but DNS mutation still needs an elevated shell to actually succeed

Do not promise full parity across platforms unless the implementation actually has it.

## Browser Leak Detection

The `browser-leaks` subcommand currently runs **Python-level baseline checks** plus returns a **manual browser checklist** (URLs + pass/fail guidance) in both text and JSON modes. The WebRTC / JavaScript / Canvas / font fingerprint analysis logic exists in `browser_leaks.py` but is NOT automatically invoked by the CLI — it still requires a browser automation layer (Playwright/Selenium/CDP MCP) that is not bundled. Describe this capability as "browser leak detection framework" rather than "full automated browser detection".

## Architecture

```
scripts/
├── cc_check.py        # Main orchestrator & CLI (~1100 lines)
├── ip_quality.py      # Multi-channel IP quality assessment
├── platform_ops.py    # Cross-platform abstraction layer (~1500 lines)
├── scoring.py         # 100-point scoring system
├── vpn_adapter.py     # VPN project adapter
└── browser_leaks.py   # Browser leak detection
```

## References

- Audit matrix and grouped checks: `references/check-matrix.md`
- Repair rationale and low-risk exceptions: `references/rationale.md`
