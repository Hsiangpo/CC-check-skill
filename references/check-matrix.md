# CC-Check Audit Matrix v1.3.0

> 11 groups, 50+ checks, 100-point scale (exact), 88 unit tests

## 1. IP Quality (weight: 30/100) 🔴 最高优先级

| Key | Check | Weight | Method |
|-----|-------|--------|--------|
| classification | IP type/risk/ISP check | 30 | 5 channels: ipinfo, ip-api, proxycheck, bgpview, whois |

Criteria for pass:
- Not flagged as proxy/VPN/hosting by any source
- IP type matches expected (residential/mobile/isp)
- Risk score < 66/100
- Country code consistent between geo and whois
- ISP matches known residential whitelist (Comcast, AT&T, Verizon, etc.)

Pseudo-residential (伪住宅) detection:
- ASN not in residential ISP whitelist
- proxycheck type != residential
- Risk score > 66

## 2. System (weight: 21/100)

| Key | Check | Weight | Method |
|-----|-------|--------|--------|
| timezone | TZ env + system TZ | 5 | `$TZ` + `/etc/localtime` / `timedatectl` / `Get-TimeZone` |
| locale | LANG + LC_ALL | 5 | Environment variables |
| proxy-env | HTTP_PROXY/HTTPS_PROXY/ALL_PROXY (6 vars) | 3 | Environment variables |
| system-languages | System UI language list | 2 | `AppleLanguages` / `localectl` / `Get-Culture` |
| measurement-units | Imperial vs Metric | 1 | `AppleMeasurementUnits` / `RegionInfo.IsMetric` |
| time-format | 12h vs 24h | 1 | `AppleICUForce24HourTime` |
| hostname | Hostname not suspicious | 1 | `socket.gethostname()` |
| input-method | No Chinese IME active | 1 | `HIToolbox.plist` / `gsettings` |
| hosts-file | No suspicious /etc/hosts entries | 1 | File scan |
| user-identity | Username/RealName info | 1 | `id` / `getent` / Windows identity |
| vscode-locale | VS Code not set to Chinese | 0 | `settings.json` locale field |
| font-fingerprint | No non-bundled Chinese fonts | 0 | `system_profiler` / `fc-list` / Registry |

## 3. DNS (weight: 15/100)

| Key | Check | Weight | Method |
|-----|-------|--------|--------|
| dns-google | Google DNS whoami | 7 | `dig TXT o-o.myaddr.l.google.com @ns1.google.com` |
| dns-cloudflare | Cloudflare DNS whoami | 4 | `dig CH TXT whoami.cloudflare @1.1.1.1` |
| system-dns-display | System DNS not China ISP | 4 | `networksetup`/`resolvectl`/PowerShell per platform |

TUN-aware: When Clash TUN is active with dns-hijack, system DNS is cosmetic (downgraded to `warn` instead of `fail`).

Suspicious DNS:
- 114.114.114.114 (China 114DNS)
- 223.5.5.5 / 223.6.6.6 (Alibaba AliDNS)
- 119.29.29.29 (Tencent DNSPod)

## 4. Network (weight: 10/100)

| Key | Check | Weight | Method |
|-----|-------|--------|--------|
| public-ip | External IP reachable | 5 | Multi-source fetch (ifconfig.me, ipify, icanhazip) |
| multi-source-ip | IP consistent across sources | 3 | Compare 2+ independent sources |
| ipv6-leak | IPv6 matches IPv4 exit | 2 | api64.ipify.org |

## 5. Clash (weight: 8/100)

| Key | Check | Weight | Method |
|-----|-------|--------|--------|
| process | Clash Verge running | 2 | `pgrep` / `Get-Process` |
| mode | Not in direct mode | 1 | Clash API `/configs` |
| tun-enabled | TUN interface exists | 2 | `ifconfig`/`ip link`/`Get-NetAdapter` + config |
| runtime-markers | Hardened DNS markers in config | 2 | Config file content scan |
| dns-cleanup-watchdog | Watchdog installed | 1 | macOS LaunchAgent / Linux systemd / Windows Task Scheduler |

## 6. Packages (weight: 6/100)

| Key | Check | Weight | Method |
|-----|-------|--------|--------|
| npm-registry | npm not China mirror | 2 | `npm config get registry` |
| pip-index | pip not China mirror | 1 | `pip3 config` + config file scan |
| brew-mirrors | Homebrew vars default | 1 | `HOMEBREW_*` environment variables |
| china-mirror-residue | No taobao/npmmirror refs in npm cache | 2 | `find ~/.npm -exec grep ...` |
| goproxy | GOPROXY not China mirror | 0 | `go env GOPROXY` |
| docker-mirror | Docker daemon.json no China mirror | 0 | `/etc/docker/daemon.json` scan |

China mirror keywords: taobao, npmmirror, cnpm, tencent, aliyun, tuna.tsinghua, ustc.edu.cn, huaweicloud, 163.com, douban, bfsu.edu.cn, goproxy.cn, goproxy.io

## 7. Privacy (weight: 6/100)

| Key | Check | Weight | Method |
|-----|-------|--------|--------|
| telemetry | Claude telemetry dir clean | 2 | `~/.claude/telemetry/` |
| privacy-env | DISABLE_TELEMETRY et al. set | 2 | Environment variables |
| session-residue | Claude sessions clean | 1 | `~/.claude/sessions/` |
| shell-history | No China domain refs in history | 1 | `.zsh_history` / `.bash_history` scan |
| ssh-known-hosts | No China IPs/domains in known_hosts | 0 | `~/.ssh/known_hosts` scan |

## 8. Node.js (weight: 2/100)

| Key | Check | Weight | Method |
|-----|-------|--------|--------|
| node-tz | Node.js Intl timezone | 1 | `node -e 'Intl.DateTimeFormat().resolvedOptions().timeZone'` |
| node-locale | Node.js Intl locale | 1 | `node -e 'Intl.DateTimeFormat().resolvedOptions().locale'` |

## 9. Identity (weight: 1/100)

| Key | Check | Weight | Method |
|-----|-------|--------|--------|
| git-identity | No global git user.name/email | 1 | `git config --global` |
| git-remotes | No China Git hosts (gitee/coding.net) | 0 | Scan `~/` for `.git/config` remotes |

## 10. Claude (weight: 1/100)

| Key | Check | Weight | Method |
|-----|-------|--------|--------|
| language | Claude settings not Chinese | 1 | `~/.claude/settings.json` |

## 11. VPN (weight: 0 — informational only, not scored)

| Key | Check | Weight | Method |
|-----|-------|--------|--------|
| project-root | VPN project detected | 0 | Explicit `--vpn-root` / env only |
| unit-tests | VPN project tests pass | 0 | `python3 -m unittest` |
| generated-subscription | Generated output has markers | 0 | File content scan |
| public-subscription | Public URL matches output | 0 | URL fetch + marker check |
| remote-service | Remote VPN service active | 0 | SSH + `systemctl` |
| remote-listener | Port owned by Xray | 0 | SSH + `ss -lntup` |

## Total: 100 weight points (exact, no normalization needed)
