# CC-Check Rationale & Decision Log v2

## Why These Checks Matter

### API Wind-Risk Detection Model

Modern API providers (Anthropic, OpenAI) use multi-signal fingerprinting to detect misuse:

1. **IP Layer**: IP type (residential vs datacenter), ASN, risk score, geographic consistency
2. **DNS Layer**: DNS resolver source, DNS over HTTPS leaks, resolver geo
3. **System Layer**: TZ/locale in API headers, Node.js runtime timezone
4. **Behavioral Layer**: Telemetry patterns, session activity, request timing
5. **Identity Layer**: Git config, hostname, username patterns

### Signal Priority

| Signal | Risk Level | Detection Difficulty |
|--------|-----------|---------------------|
| Chinese ISP DNS (114/223) | 🔴 Critical | Trivial for API |
| IP type = hosting/VPN | 🔴 Critical | Trivial for API |
| TZ / Locale mismatch | 🟡 Medium | Moderate |
| npm China mirror | 🟡 Medium | Indirect (via registry requests) |
| Git identity | 🟢 Low | Only in error stacks |
| Username/hostname | 🟢 Low | Only in error stacks |
| Input method | 🟢 Low | Not transmitted |

## Platform-Specific Decisions

### macOS
- Use `networksetup` for DNS (more reliable than `scutil --dns` for display values)
- LaunchAgent for DNS watchdog (Clash Verge periodically overrides display DNS)
- `plistlib` for input method detection

### Linux
- Use `resolvectl` first, fall back to `/etc/resolv.conf`
- No DNS watchdog needed (NetworkManager doesn't have the display bug)
- `gsettings` for input method (GNOME)

### Windows
- PowerShell for everything (avoid cmd.exe encoding issues)
- Registry for system proxy detection
- No DNS watchdog needed

## Important Repair Logic (from original rationale)

### Actual DNS vs displayed DNS are different problems

`scutil --dns` or `networksetup -getdnsservers` may show a suspicious resolver even when actual DNS requests are already being hijacked and proxied correctly by Clash Verge.

Treat these as separate checks:
- **Actual DNS path**: authoritative for real leakage risk
- **Displayed DNS path**: important for hygiene and consistency; can be repaired without changing the working proxy chain

### Why VPN deploy logs must be redacted

The VPN project contains:
- SSH host credentials
- Panel credentials
- Shadowsocks passwords

The skill may use those files locally, but normal output must never expose them. The `redact_text()` function and `vpn_redaction_tokens()` ensure all sensitive values are replaced with `***` before any error output is shown.

### Current stable end-state

The stable end-state this skill is trying to preserve is:
- Public egress aligned with the active target VPN host
- Actual DNS path no longer routed through China ISP resolvers
- Clash Verge runtime config contains hardened DNS/TUN settings
- Public subscription serves the hardened config
- Active remote listener on the expected VPN port belongs to the intended runtime
- System DNS display no longer shows `114.114.114.114`

## Fix Safety Decisions

### Why `--dry-run` exists
- Shell profile modifications can break login shells
- DNS changes can break network connectivity
- git config changes are destructive
- Users want to see what will change before applying

### Why we don't auto-fix warnings
- Chinese IME: legitimate for bilingual users
- Cloudflare Asia PoP: NOT equivalent to China ISP
- Shell history: past data, not current state
- System language: risky to change globally

## IP Quality Assessment Logic

### Multi-Channel Validation
1. **ipinfo.io**: Geo + ASN + org (most reliable geo)
2. **ip-api.com**: proxy/hosting/mobile flags (most reliable type)
3. **proxycheck.io**: VPN detection + risk score (most granular)
4. **bgpview.io**: BGP prefix analysis (ASN validation)
5. **whois**: Country cross-check (independent verification)

### Residential ISP Whitelist
US residential ISPs that should pass cleanly: Comcast/Xfinity, AT&T, Verizon, Spectrum, Cox, CenturyLink, Frontier, Mediacom, etc.

### Pseudo-Residential Detection
IDC-tunneled "residential" IPs (伪住宅) are detected by:
- ASN not matching known residential ISPs
- `proxycheck.io` type != residential
- Risk score > 66

## Scoring Rationale

### Weight Distribution (Total: 100 points)
- **IP Quality (30)**: Highest priority — direct risk signal to API providers, includes multi-channel type/risk/ISP validation
- **DNS (15)**: Most common leak vector
- **Network (10)**: IP reachability and consistency
- **System (21)**: TZ, locale, proxy, language, hostname, user identity
- **Packages (6)**: China mirrors = strong geo signal
- **Privacy (6)**: Telemetry control
- **Clash (8)**: Proxy client state and TUN
- **Node.js (2)**: Runtime verification
- **Identity (1)**: Low risk but still checked
- **Claude (1)**: Settings file

### Grading Scale
- A+ (≥95): Production-safe
- A (≥90): Minor cosmetic issues only
- B (≥80): Acceptable with known warnings
- C (≥70): Significant gaps
- D (≥60): Failing items need attention
- F (<60): Critical issues detected
