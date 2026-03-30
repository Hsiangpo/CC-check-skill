#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CC-check v1.3.0 — 跨平台 Claude Code / 代理环境审计与修复工具。

支持 macOS / Linux / Windows。
功能：inspect → fix → verify 闭环，100分制评分，dry-run 预览。
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone as dt_tz
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import urlopen

# Ensure sibling modules are importable
sys.path.insert(0, str(Path(__file__).resolve().parent))

from ip_quality import assess_ip_quality
from scoring import compute_score, count_scored_failures, format_score_report, has_scored_failures
import platform_ops as plat
import vpn_adapter as vpnops
import browser_leaks as bleaks


# ---------------------------------------------------------------------------
# ANSI Colors
# ---------------------------------------------------------------------------

def _supports_color() -> bool:
    """检测终端是否支持 ANSI 颜色。"""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


class _C:
    """ANSI 颜色常量。"""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    CYAN = "\033[36m"
    MAGENTA = "\033[35m"
    WHITE = "\033[97m"
    BG_GREEN = "\033[42m"
    BG_RED = "\033[41m"
    BG_YELLOW = "\033[43m"


USE_COLOR = _supports_color()


def _c(color: str, text: str) -> str:
    """Wrap text with ANSI color if terminal supports it."""
    if not USE_COLOR:
        return text
    return f"{color}{text}{_C.RESET}"


# ---------------------------------------------------------------------------
# History tracking
# ---------------------------------------------------------------------------

HISTORY_FILE = Path.home() / ".cc-check" / "history.json"


def save_history(score: int, grade: str, fail_count: int, warn_count: int) -> None:
    """保存审计分数到历史文件。"""
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    history: list[dict] = []
    if HISTORY_FILE.exists():
        try:
            history = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            history = []
    history.append({
        "timestamp": datetime.now(dt_tz.utc).isoformat(),
        "score": score,
        "grade": grade,
        "fail": fail_count,
        "warn": warn_count,
    })
    # 保留最近 100 条
    history = history[-100:]
    HISTORY_FILE.write_text(json.dumps(history, indent=2, ensure_ascii=False), encoding="utf-8")


def format_history() -> str:
    """格式化历史分数趋势。"""
    if not HISTORY_FILE.exists():
        return "No history yet. Run 'inspect' to start tracking."
    try:
        history = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return "History file corrupted."
    if not history:
        return "No history yet."
    lines = [_c(_C.BOLD, "\n📈 Score History (last 20):"), ""]
    lines.append(f"  {'Date':<20} {'Score':>5}  {'Grade':>5}  {'Fail':>4}  {'Warn':>4}")
    lines.append(f"  {'─'*20} {'─'*5}  {'─'*5}  {'─'*4}  {'─'*4}")
    for entry in history[-20:]:
        ts = entry.get("timestamp", "?")[:19].replace("T", " ")
        score = entry.get("score", 0)
        grade = entry.get("grade", "?")
        fail = entry.get("fail", 0)
        warn = entry.get("warn", 0)
        # Color based on grade
        if score >= 95:
            score_str = _c(_C.GREEN + _C.BOLD, f"{score:>5}")
        elif score >= 80:
            score_str = _c(_C.GREEN, f"{score:>5}")
        elif score >= 60:
            score_str = _c(_C.YELLOW, f"{score:>5}")
        else:
            score_str = _c(_C.RED, f"{score:>5}")
        lines.append(f"  {ts:<20} {score_str}  {grade:>5}  {fail:>4}  {warn:>4}")
    # Trend
    if len(history) >= 2:
        delta = history[-1]["score"] - history[-2]["score"]
        if delta > 0:
            lines.append(_c(_C.GREEN, f"\n  ↑ +{delta} since last run"))
        elif delta < 0:
            lines.append(_c(_C.RED, f"\n  ↓ {delta} since last run"))
        else:
            lines.append(_c(_C.DIM, "\n  → No change since last run"))
    lines.append("")
    return "\n".join(lines)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ENV_BLOCK_START = "# >>> cc-check env >>>"
ENV_BLOCK_END = "# <<< cc-check env <<<"

GENERIC_PUBLIC_MARKERS = [
    "dns-hijack",
    "respect-rules: true",
    "proxy-server-nameserver",
]

LOW_RISK_GOOGLE_MARKERS = ("2400:cb00:", "192.178.", "172.69.", "108.162.", "172.71.")
FAIL_GOOGLE_MARKERS = ("124.220.", "124.23.", "210.87.", "223.6.6.6", "114.114.114.114")


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    group: str
    key: str
    status: str       # pass | fail | warn | skip
    summary: str
    details: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Context:
    skill_root: Path
    home: Path
    claude_dir: Path
    clash_dir: Path | None
    vpn_root: Path | None
    public_subscription_url: str | None
    target_timezone: str | None
    target_locale: str | None
    target_language: str | None
    proxy_url: str | None
    expected_ip_type: str
    dry_run: bool
    allow_static_dns: bool = False
    allow_dns_watchdog: bool = False
    allow_shell_history_cleanup: bool = False
    allow_rime_install: bool = False
    allow_ime_removal: bool = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def fetch_public_ip() -> str | None:
    for url in ("https://ifconfig.me/ip", "https://api.ipify.org", "https://icanhazip.com"):
        try:
            with urlopen(url, timeout=8) as resp:
                val = resp.read().decode("utf-8", errors="ignore").strip()
                if val:
                    return val
        except (URLError, TimeoutError, socket.timeout, OSError):
            continue
    return None


def fetch_text_url(url: str, timeout: int = 12, retries: int = 2) -> str | None:
    for _ in range(retries):
        try:
            with urlopen(url, timeout=timeout) as resp:
                text = resp.read().decode("utf-8", errors="ignore")
                if text:
                    return text
        except (URLError, TimeoutError, socket.timeout, OSError):
            continue
    return None


def fetch_google_dns_lines() -> list[str]:
    """获取 Google DNS whoami 输出，Windows 下无 dig 时回退到 DoH。"""
    r = plat.run_shell("dig +time=3 +tries=1 +short TXT o-o.myaddr.l.google.com @ns1.google.com 2>/dev/null")
    lines = [line.strip().strip('"') for line in r.stdout.splitlines() if line.strip()]
    if lines:
        return lines

    text = fetch_text_url("https://dns.google/resolve?name=o-o.myaddr.l.google.com&type=TXT", timeout=8, retries=1)
    if not text:
        return []
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return []
    answers = payload.get("Answer", [])
    return [item.get("data", "").strip().strip('"') for item in answers if item.get("data")]


def fetch_cloudflare_dns_ip() -> str:
    """获取 Cloudflare whoami IP，Windows 下无 dig 时回退到 trace 接口。"""
    r = plat.run_shell("dig +time=3 +tries=1 +short CH TXT whoami.cloudflare @1.1.1.1 2>/dev/null")
    cf = r.stdout.strip().replace('"', "")
    if cf:
        return cf

    text = fetch_text_url("https://1.1.1.1/cdn-cgi/trace", timeout=8, retries=1)
    if not text:
        return ""
    for line in text.splitlines():
        if line.startswith("ip="):
            return line.split("=", 1)[1].strip()
    return ""


def classify_google_dns(lines: list[str], clash_running: bool = False) -> tuple[str, str]:
    """分类 Google DNS whoami 结果。

    当 Clash 在运行时，Cloudflare 边缘 IP 是预期行为（DNS 走加密 DoH 通道），
    应判定为 pass 而不是 warn。
    """
    text = " | ".join(lines)
    effective_lines = [line for line in lines if "edns0-client-subnet" not in line.lower()]
    effective_text = " | ".join(effective_lines)
    if not text:
        return "warn", "Google DNS whoami returned empty output"
    if any(m in text for m in FAIL_GOOGLE_MARKERS):
        return "fail", f"Google DNS whoami shows China ISP: {text}"
    if any(m in effective_text for m in LOW_RISK_GOOGLE_MARKERS) or "edns0-client-subnet" in text:
        if clash_running:
            return "pass", f"Google DNS via Clash DoH (expected): {text}"
        return "warn", f"Google DNS PoP acceptable but not ideal: {text}"
    if effective_text:
        return "pass", f"Google DNS whoami clean: {effective_text}"
    return "warn", f"Google DNS whoami returned subnet hint only: {text}"


# ---------------------------------------------------------------------------
# Build context
# ---------------------------------------------------------------------------

def make_context(args: argparse.Namespace) -> Context:
    skill_root = Path(__file__).resolve().parents[1]
    home = Path.home()
    vpn_root = vpnops.detect_root(getattr(args, "vpn_root", None))
    clash_dir = plat.detect_clash_dir(getattr(args, "clash_dir", None))
    pub_sub = vpnops.detect_public_subscription_url(vpn_root, getattr(args, "public_subscription_url", None))
    return Context(
        skill_root=skill_root, home=home,
        claude_dir=home / ".claude",
        clash_dir=clash_dir, vpn_root=vpn_root,
        public_subscription_url=pub_sub,
        target_timezone=getattr(args, "target_timezone", None),
        target_locale=getattr(args, "target_locale", None),
        target_language=getattr(args, "target_language", None),
        proxy_url=getattr(args, "proxy_url", None) or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy"),
        expected_ip_type=getattr(args, "expected_ip_type", "residential"),
        dry_run=getattr(args, "dry_run", False),
        allow_static_dns=getattr(args, "allow_static_dns", False),
        allow_dns_watchdog=getattr(args, "allow_dns_watchdog", False),
        allow_shell_history_cleanup=getattr(args, "allow_shell_history_cleanup", False),
        allow_rime_install=getattr(args, "allow_rime_install", False),
        allow_ime_removal=getattr(args, "allow_ime_removal", False),
    )


def build_target_profile(ctx: Context, public_ip: str | None, ip_q: dict[str, Any] | None = None) -> dict[str, Any]:
    profile: dict[str, Any] = {
        "timezone": ctx.target_timezone,
        "locale": ctx.target_locale,
        "language": ctx.target_language,
        "proxy_url": ctx.proxy_url,
        "locale_candidates": [ctx.target_locale] if ctx.target_locale else [],
        "language_candidates": [ctx.target_language] if ctx.target_language else [],
    }
    if public_ip:
        q = ip_q or assess_ip_quality(public_ip, ctx.expected_ip_type)
        if not profile["timezone"]:
            profile["timezone"] = q.get("target_timezone")
        if not profile["locale"]:
            profile["locale"] = q.get("target_locale")
        if not profile["language"]:
            profile["language"] = q.get("target_language")
        if not profile["locale_candidates"]:
            profile["locale_candidates"] = q.get("target_locale_candidates", [])
        if not profile["language_candidates"]:
            profile["language_candidates"] = q.get("target_language_candidates", [])
    if not profile["proxy_url"]:
        configs = plat.get_clash_api_json("configs")
        if isinstance(configs, dict) and configs.get("mixed-port"):
            profile["proxy_url"] = f"http://127.0.0.1:{configs['mixed-port']}"
    return profile


# ---------------------------------------------------------------------------
# INSPECTION: All check groups
# ---------------------------------------------------------------------------

def inspect_network(public_ip: str | None) -> list[Finding]:
    findings: list[Finding] = []

    # Public IP
    if public_ip:
        findings.append(Finding("network", "public-ip", "pass", f"Public IP is {public_ip}"))
    else:
        findings.append(Finding("network", "public-ip", "fail", "Cannot determine public IP"))
        return findings

    # Multi-source consistency
    alt_ip = None
    for url in ("https://api64.ipify.org", "https://ifconfig.me/ip"):
        try:
            with urlopen(url, timeout=8) as resp:
                alt_ip = resp.read().decode("utf-8", errors="ignore").strip()
                if alt_ip:
                    break
        except Exception:
            continue
    if alt_ip and alt_ip == public_ip:
        findings.append(Finding("network", "multi-source-ip", "pass", f"Multi-source IP consistent: {alt_ip}"))
    elif alt_ip:
        findings.append(Finding("network", "multi-source-ip", "fail", f"IP mismatch: primary={public_ip} alt={alt_ip}"))
    else:
        findings.append(Finding("network", "multi-source-ip", "warn", "Could not verify IP from alternative source"))

    # IPv6 leak
    ipv6_ip = None
    try:
        with urlopen("https://api64.ipify.org", timeout=8) as resp:
            ipv6_ip = resp.read().decode("utf-8", errors="ignore").strip()
    except Exception:
        pass
    if ipv6_ip and ipv6_ip == public_ip:
        findings.append(Finding("network", "ipv6-leak", "pass", f"IPv6 consistent with IPv4: {ipv6_ip}"))
    elif ipv6_ip:
        findings.append(Finding("network", "ipv6-leak", "warn", f"IPv6 response differs: {ipv6_ip}"))
    else:
        findings.append(Finding("network", "ipv6-leak", "skip", "IPv6 check unavailable"))
    return findings


def inspect_dns(public_ip: str | None) -> list[Finding]:
    findings: list[Finding] = []

    # Google DNS whoami
    lines = fetch_google_dns_lines()
    status, summary = classify_google_dns(lines, clash_running=plat.is_clash_running())
    findings.append(Finding("dns", "dns-google", status, summary))

    # Cloudflare DNS whoami
    cf = fetch_cloudflare_dns_ip()
    if public_ip and cf == public_ip:
        findings.append(Finding("dns", "dns-cloudflare", "pass", f"Cloudflare DNS matches egress: {cf}"))
    elif cf:
        findings.append(Finding("dns", "dns-cloudflare", "warn", f"Cloudflare DNS returned: {cf}"))
    else:
        findings.append(Finding("dns", "dns-cloudflare", "fail", "Cloudflare DNS whoami returned empty"))

    # System DNS display
    dns_map = plat.get_dns_servers()
    suspicious_services = []
    for svc, servers in dns_map.items():
        if any(s in plat.SUSPICIOUS_DNS for s in servers):
            suspicious_services.append(f"{svc}: {', '.join(servers)}")
    if suspicious_services:
        # When Clash TUN is active with dns-hijack, system DNS display is
        # cosmetic — all DNS is hijacked by TUN regardless. Downgrade to warn.
        tun_active = bool(plat.get_tun_interfaces()) and plat.is_clash_running()
        if tun_active:
            findings.append(Finding("dns", "system-dns-display", "warn",
                                    f"Cosmetic DNS (TUN active): {'; '.join(suspicious_services)}"))
        else:
            findings.append(Finding("dns", "system-dns-display", "fail",
                                    f"Suspicious DNS on: {'; '.join(suspicious_services)}"))
    else:
        findings.append(Finding("dns", "system-dns-display", "pass", "System DNS display is clean"))
    return findings


def inspect_system(ctx: Context, targets: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    tz = targets.get("timezone")
    locale = targets.get("locale")
    proxy = targets.get("proxy_url")
    locale_candidates = [item for item in targets.get("locale_candidates", []) if item]

    # Timezone
    if tz:
        env_tz = os.environ.get("TZ", "")
        sys_tz = plat.get_system_timezone()
        if env_tz == tz and (sys_tz == tz or not sys_tz):
            findings.append(Finding("system", "timezone", "pass", f"Timezone aligned: {tz}"))
        else:
            findings.append(Finding("system", "timezone", "fail", f"Timezone not aligned to {tz}",
                                    [f"TZ={env_tz}", f"system={sys_tz}"]))
    else:
        findings.append(Finding("system", "timezone", "warn", "Target timezone unknown"))

    # Locale
    if locale:
        candidates = locale_candidates or [locale]
        lang_ok = os.environ.get("LANG") in candidates
        lc_value = os.environ.get("LC_ALL", "")
        lc_ok = lc_value in candidates or lc_value == ""
        if lang_ok and lc_ok:
            findings.append(Finding("system", "locale", "pass", f"Locale aligned: {os.environ.get('LANG') or locale}"))
        else:
            findings.append(Finding("system", "locale", "fail", f"Locale not aligned to {locale}",
                                    [f"expected one of: {', '.join(candidates)}", f"LANG={os.environ.get('LANG', '')}", f"LC_ALL={os.environ.get('LC_ALL', '')}"]))
    else:
        findings.append(Finding("system", "locale", "warn", "Target locale unknown"))

    # Proxy env
    cur_proxy = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
    if proxy:
        if cur_proxy == proxy:
            findings.append(Finding("system", "proxy-env", "pass", f"Proxy env aligned: {proxy}"))
        else:
            findings.append(Finding("system", "proxy-env", "fail", f"Proxy env not aligned",
                                    [f"HTTP_PROXY={cur_proxy or '(unset)'}"]))
    else:
        findings.append(Finding("system", "proxy-env", "warn", "Target proxy unknown"))

    # System languages
    locale_info = plat.get_locale_info()
    if locale_info.system_languages:
        langs = locale_info.system_languages
        if any("zh" in l.lower() or "cn" in l.lower() for l in langs):
            findings.append(Finding("system", "system-languages", "warn",
                                    f"System language includes Chinese: {langs}"))
        else:
            findings.append(Finding("system", "system-languages", "pass", f"System languages: {langs}"))
    else:
        findings.append(Finding("system", "system-languages", "skip", "Cannot read system languages"))

    # Measurement units
    if locale_info.measurement_units:
        findings.append(Finding("system", "measurement-units", "pass",
                                f"Units: {locale_info.measurement_units} / {locale_info.temperature_unit}"))
    else:
        findings.append(Finding("system", "measurement-units", "skip", "Measurement units not available"))

    # Time format
    if locale_info.time_format_24h is not None:
        findings.append(Finding("system", "time-format", "pass",
                                f"{'24h' if locale_info.time_format_24h else '12h'} format"))
    else:
        findings.append(Finding("system", "time-format", "skip", "Time format not detectable"))

    # Hostname
    host_info = plat.get_hostname_info()
    findings.append(Finding("system", "hostname", "pass", f"Hostname: {host_info.get('hostname', '?')}"))

    # Input method
    ims = plat.get_active_input_methods()
    china_ime_keywords = ("SCIM", "ITABC", "Pinyin", "Chinese", "Wubi", "Shuangpin", "Zhuyin")
    has_chinese = any(any(kw.lower() in im.lower() for kw in china_ime_keywords) for im in ims)
    has_rime = any("rime" in im.lower() for im in ims)
    if has_chinese and not has_rime:
        findings.append(Finding("system", "input-method", "warn", f"Chinese IME active: {ims[0] if ims else '?'}"))
    elif has_rime:
        findings.append(Finding("system", "input-method", "pass", f"Input method: RIME (stealth Chinese IME)"))
    else:
        findings.append(Finding("system", "input-method", "pass", f"Input method: {ims[0] if ims else 'default'}"))

    # /etc/hosts
    suspicious_hosts = plat.check_hosts_file()
    if suspicious_hosts:
        findings.append(Finding("system", "hosts-file", "warn",
                                f"{len(suspicious_hosts)} non-standard entries in hosts file",
                                suspicious_hosts[:5]))
    else:
        findings.append(Finding("system", "hosts-file", "pass", "hosts file is clean"))

    # User identity
    user = plat.get_user_info()
    findings.append(Finding("system", "user-identity", "pass",
                            f"User: {user.get('username', '?')} / {user.get('real_name', '?')}"))
    return findings


def inspect_nodejs(targets: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    node_env = plat.get_nodejs_env()
    tz = targets.get("timezone")

    if not node_env:
        findings.append(Finding("nodejs", "node-tz", "skip", "Node.js not available"))
        findings.append(Finding("nodejs", "node-locale", "skip", "Node.js not available"))
        return findings

    node_tz = node_env.get("tz", "")
    if tz and node_tz == tz:
        findings.append(Finding("nodejs", "node-tz", "pass", f"Node.js TZ: {node_tz}"))
    elif tz:
        findings.append(Finding("nodejs", "node-tz", "fail", f"Node.js TZ mismatch: {node_tz} vs expected {tz}"))
    else:
        findings.append(Finding("nodejs", "node-tz", "pass", f"Node.js TZ: {node_tz}"))

    node_locale = node_env.get("locale", "")
    locale_candidates = [str(item) for item in targets.get("locale_candidates", []) if item]
    language_candidates = [str(item) for item in targets.get("language_candidates", []) if item]
    expected_prefixes = [
        candidate.split(".")[0].replace("_", "-")
        for candidate in locale_candidates
    ] + [
        candidate.replace("_", "-")
        for candidate in language_candidates
    ]
    if expected_prefixes and any(node_locale.startswith(prefix.split("-")[0]) for prefix in expected_prefixes):
        findings.append(Finding("nodejs", "node-locale", "pass", f"Node.js locale: {node_locale}"))
    elif expected_prefixes:
        findings.append(Finding("nodejs", "node-locale", "fail",
                                f"Node.js locale mismatch: {node_locale} vs expected {', '.join(expected_prefixes)}"))
    else:
        findings.append(Finding("nodejs", "node-locale", "pass", f"Node.js locale: {node_locale}"))
    return findings


def inspect_packages() -> list[Finding]:
    findings: list[Finding] = []
    mirrors = plat.check_package_mirrors()

    npm = mirrors.get("npm", {})
    if npm.get("is_china_mirror"):
        findings.append(Finding("packages", "npm-registry", "fail",
                                f"npm uses China mirror: {npm.get('registry')}"))
    else:
        findings.append(Finding("packages", "npm-registry", "pass",
                                f"npm registry: {npm.get('registry', '?')}"))

    pip = mirrors.get("pip", {})
    if pip.get("is_china_mirror"):
        findings.append(Finding("packages", "pip-index", "fail",
                                f"pip uses China mirror: {pip.get('index')}"))
    else:
        findings.append(Finding("packages", "pip-index", "pass",
                                f"pip index: {pip.get('index', '?')}"))

    brew = mirrors.get("brew", {})
    if brew.get("is_china_mirror"):
        findings.append(Finding("packages", "brew-mirrors", "fail", "brew uses China mirrors"))
    elif "brew" in mirrors:
        findings.append(Finding("packages", "brew-mirrors", "pass", "brew mirrors: default"))

    # cnpm/taobao residue in ~/.npm
    residue_files = plat.find_china_mirror_residue()
    if residue_files:
        findings.append(Finding("packages", "china-mirror-residue", "fail",
                                f"{len(residue_files)} files with China mirror refs", residue_files[:3]))
    else:
        findings.append(Finding("packages", "china-mirror-residue", "pass", "No China mirror residue"))
    return findings


def inspect_privacy(ctx: Context) -> list[Finding]:
    findings: list[Finding] = []

    # Claude telemetry
    tel_dir = ctx.claude_dir / "telemetry"
    if tel_dir.exists() and any(tel_dir.iterdir()):
        count = sum(1 for _ in tel_dir.iterdir())
        findings.append(Finding("privacy", "telemetry", "fail", f"Claude telemetry: {count} files"))
    else:
        findings.append(Finding("privacy", "telemetry", "pass", "Claude telemetry clean"))

    # Session residue
    sess_dir = ctx.claude_dir / "sessions"
    if sess_dir.exists() and any(sess_dir.iterdir()):
        count = sum(1 for _ in sess_dir.iterdir())
        findings.append(Finding("privacy", "session-residue", "warn", f"Claude sessions: {count} files"))
    else:
        findings.append(Finding("privacy", "session-residue", "pass", "Claude sessions clean"))

    # Privacy env vars
    missing = [k for k in ("DISABLE_TELEMETRY", "DISABLE_ERROR_REPORTING",
                            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
                            "CLAUDE_CODE_PROXY_RESOLVES_HOSTS",
                            "DISABLE_INSTALLATION_CHECKS")
               if os.environ.get(k) != "1"]
    if missing:
        findings.append(Finding("privacy", "privacy-env", "fail", f"Missing: {', '.join(missing)}"))
    else:
        findings.append(Finding("privacy", "privacy-env", "pass", "Privacy env aligned"))

    # Shell history
    history_hits = plat.scan_shell_history()
    if history_hits:
        total = sum(history_hits.values())
        top = sorted(history_hits.items(), key=lambda x: -x[1])[:3]
        findings.append(Finding("privacy", "shell-history", "warn",
                                f"Shell history: {total} China domain refs",
                                [f"{k}: {v}" for k, v in top]))
    else:
        findings.append(Finding("privacy", "shell-history", "pass", "Shell history clean"))
    return findings


def inspect_extended() -> list[Finding]:
    """扩展检查：包管理镜像、开发工具指纹、SSH 残留、字体指纹。"""
    findings: list[Finding] = []

    # GOPROXY
    goproxy = plat.check_goproxy()
    if goproxy["installed"]:
        if goproxy["china"]:
            findings.append(Finding("packages", "goproxy", "fail",
                                    f"GOPROXY → China mirror: {goproxy['proxy']}"))
        else:
            findings.append(Finding("packages", "goproxy", "pass",
                                    f"GOPROXY clean: {goproxy['proxy']}"))
    else:
        findings.append(Finding("packages", "goproxy", "skip", "Go not installed"))

    # Docker mirrors
    docker = plat.check_docker_mirrors()
    if docker["found"]:
        if docker["china"]:
            findings.append(Finding("packages", "docker-mirror", "fail",
                                    f"Docker China mirrors in {docker.get('path', 'daemon.json')}",
                                    docker["mirrors"][:5]))
        else:
            findings.append(Finding("packages", "docker-mirror", "pass",
                                    "Docker mirrors configured (non-China)"))
    else:
        findings.append(Finding("packages", "docker-mirror", "pass",
                                "No Docker mirror config found"))

    # Git remotes
    china_remotes = plat.scan_git_remotes()
    if china_remotes:
        findings.append(Finding("identity", "git-remotes", "warn",
                                f"{len(china_remotes)} China Git host(s) found",
                                china_remotes[:10]))
    else:
        findings.append(Finding("identity", "git-remotes", "pass",
                                "No China Git hosts in local repos"))

    # VS Code locale
    vscode = plat.check_vscode_locale()
    if vscode["found"]:
        if vscode["china"]:
            findings.append(Finding("system", "vscode-locale", "fail",
                                    f"VS Code locale: {vscode['locale']} ({vscode.get('path', '')})"))
        else:
            findings.append(Finding("system", "vscode-locale", "pass",
                                    f"VS Code locale: {vscode['locale']}"))
    else:
        findings.append(Finding("system", "vscode-locale", "pass",
                                "VS Code locale not set (default English)"))

    # SSH known_hosts
    ssh_hits = plat.scan_ssh_known_hosts()
    if ssh_hits:
        findings.append(Finding("privacy", "ssh-known-hosts", "warn",
                                f"{len(ssh_hits)} China IP/domain(s) in known_hosts",
                                ssh_hits[:10]))
    else:
        findings.append(Finding("privacy", "ssh-known-hosts", "pass",
                                "SSH known_hosts clean"))

    # Font fingerprints
    fonts = plat.check_system_fonts()
    if fonts["total_cjk"] > 0:
        findings.append(Finding("system", "font-fingerprint", "warn",
                                f"{fonts['total_cjk']} non-bundled Chinese font(s) detected",
                                fonts["china_fonts"]))
    else:
        findings.append(Finding("system", "font-fingerprint", "pass",
                                "No non-bundled Chinese fonts detected"))

    return findings


def inspect_identity() -> list[Finding]:
    findings: list[Finding] = []
    name = plat.get_git_global_value("user.name")
    email = plat.get_git_global_value("user.email")
    if name or email:
        findings.append(Finding("identity", "git-identity", "fail",
                                f"Global git identity set: {name} <{email}>"))
    else:
        findings.append(Finding("identity", "git-identity", "pass", "Global git identity clean"))
    return findings


def inspect_clash(ctx: Context, public_ip: str | None) -> list[Finding]:
    findings: list[Finding] = []
    if ctx.clash_dir is None:
        return [Finding("clash", "process", "skip", "Clash Verge not detected")]

    if not plat.is_clash_running():
        findings.append(Finding("clash", "process", "fail", "Clash Verge not running"))
        return findings
    findings.append(Finding("clash", "process", "pass", "Clash Verge running"))

    # Mode
    configs = plat.get_clash_api_json("configs")
    if isinstance(configs, dict):
        mode = configs.get("mode", "unknown")
        if mode == "direct":
            findings.append(Finding("clash", "mode", "fail", "Clash mode is direct"))
        else:
            findings.append(Finding("clash", "mode", "pass", f"Clash mode: {mode}"))

    # TUN
    tuns = plat.get_tun_interfaces()
    runtime = ctx.clash_dir / "clash-verge.yaml"
    runtime_text = runtime.read_text(errors="ignore") if runtime.exists() else ""
    tun_in_config = "tun:" in runtime_text and "enable: true" in runtime_text
    if tuns and tun_in_config:
        findings.append(Finding("clash", "tun-enabled", "pass",
                                f"TUN enabled, interfaces: {', '.join(tuns[:3])}"))
    elif tuns:
        findings.append(Finding("clash", "tun-enabled", "warn",
                                f"TUN interfaces exist ({', '.join(tuns[:3])}) but config unclear"))
    else:
        findings.append(Finding("clash", "tun-enabled", "fail", "No TUN interfaces detected"))

    # Runtime markers
    missing_markers = [m for m in GENERIC_PUBLIC_MARKERS if m not in runtime_text]
    if missing_markers:
        findings.append(Finding("clash", "runtime-markers", "fail",
                                f"Missing: {', '.join(missing_markers)}"))
    else:
        findings.append(Finding("clash", "runtime-markers", "pass", "Runtime config has hardened markers"))

    # DNS watchdog
    if plat.PLATFORM == "darwin":
        watchdog = ctx.clash_dir / "cleanup_system_dns.sh"
        agent = ctx.home / "Library/LaunchAgents" / f"{plat.LAUNCH_AGENT_LABEL}.plist"
        if watchdog.exists() and agent.exists():
            findings.append(Finding("clash", "dns-cleanup-watchdog", "pass", "DNS watchdog installed"))
        else:
            findings.append(Finding("clash", "dns-cleanup-watchdog", "warn", "DNS watchdog not installed"))
    elif plat.PLATFORM == "win32":
        findings.append(Finding("clash", "dns-cleanup-watchdog", "pass", "DNS watchdog not required on Windows"))
    else:
        findings.append(Finding("clash", "dns-cleanup-watchdog", "skip", "DNS watchdog N/A on this platform"))
    return findings


def inspect_claude(ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    settings = load_json(ctx.claude_dir / "settings.json")
    if settings is None:
        return [Finding("claude", "language", "skip", "Claude settings.json not found")]
    lang = settings.get("language")
    if lang and str(lang).lower() not in ("english", ""):
        findings.append(Finding("claude", "language", "warn", f"Claude language: {lang}"))
    else:
        findings.append(Finding("claude", "language", "pass", "Claude language OK"))
    return findings


def inspect_vpn(ctx: Context) -> list[Finding]:
    """检查 VPN 项目与远端状态。"""
    return [Finding("vpn", item["key"], item["status"], item["summary"], item.get("details", [])) for item in vpnops.inspect(ctx.vpn_root, ctx.public_subscription_url, plat.run_shell, fetch_text_url)]


# ---------------------------------------------------------------------------
# Collect all findings
# ---------------------------------------------------------------------------

def collect_findings(ctx: Context, include_vpn: bool = True) -> list[Finding]:
    public_ip = fetch_public_ip()
    findings: list[Finding] = []

    # IP quality
    # IP quality — emit sub-findings for granular scoring
    ip_q: dict[str, Any] | None = None
    if public_ip:
        ip_q = assess_ip_quality(public_ip, ctx.expected_ip_type)
        # Emit individual sub-findings (ip-not-proxy, ip-not-hosting, etc.)
        for sf in ip_q.get("sub_findings", []):
            findings.append(Finding("ip-quality", sf["key"], sf["status"],
                                    sf["summary"], ip_q["details"]))

    targets = build_target_profile(ctx, public_ip, ip_q)

    findings.extend(inspect_network(public_ip))
    findings.extend(inspect_dns(public_ip))
    findings.extend(inspect_system(ctx, targets))
    findings.extend(inspect_nodejs(targets))
    findings.extend(inspect_packages())
    findings.extend(inspect_privacy(ctx))
    findings.extend(inspect_identity())
    findings.extend(inspect_extended())
    findings.extend(inspect_clash(ctx, public_ip))
    findings.extend(inspect_claude(ctx))
    if include_vpn:
        findings.extend(inspect_vpn(ctx))
    return findings


# ---------------------------------------------------------------------------
# FIX: Repair functions
# ---------------------------------------------------------------------------

def build_env_block(targets: dict[str, str | None]) -> str:
    lines = [ENV_BLOCK_START]
    is_windows = plat.PLATFORM == "win32"

    def add_env(name: str, value: str) -> None:
        if is_windows:
            escaped = value.replace("'", "''")
            lines.append(f"$env:{name} = '{escaped}'")
        else:
            lines.append(f'export {name}="{value}"')

    if targets.get("timezone"):
        add_env("TZ", targets["timezone"])
    if targets.get("locale"):
        add_env("LANG", targets["locale"])
        add_env("LC_ALL", targets["locale"])
    if targets.get("language"):
        add_env("LANGUAGE", targets["language"])
    if targets.get("proxy_url"):
        add_env("HTTP_PROXY", targets["proxy_url"])
        if is_windows:
            lines.append("$env:HTTPS_PROXY = $env:HTTP_PROXY")
            lines.append("$env:http_proxy = $env:HTTP_PROXY")
            lines.append("$env:https_proxy = $env:HTTP_PROXY")
            lines.append("$env:ALL_PROXY = $env:HTTP_PROXY")
            lines.append("$env:all_proxy = $env:HTTP_PROXY")
        else:
            lines.append('export HTTPS_PROXY="$HTTP_PROXY"')
            lines.append('export http_proxy="$HTTP_PROXY"')
            lines.append('export https_proxy="$HTTP_PROXY"')
            lines.append('export ALL_PROXY="$HTTP_PROXY"')
            lines.append('export all_proxy="$HTTP_PROXY"')
    add_env("DISABLE_TELEMETRY", "1")
    add_env("DISABLE_ERROR_REPORTING", "1")
    add_env("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1")
    add_env("CLAUDE_CODE_PROXY_RESOLVES_HOSTS", "1")
    add_env("DISABLE_INSTALLATION_CHECKS", "1")
    lines.append(ENV_BLOCK_END)
    return "\n".join(lines)


def upsert_env_block(path: Path, targets: dict[str, str | None], dry_run: bool = False) -> str | None:
    original = path.read_text(encoding="utf-8", errors="ignore") if path.exists() else ""
    pattern = re.compile(rf"{re.escape(ENV_BLOCK_START)}.*?{re.escape(ENV_BLOCK_END)}\n?", re.DOTALL)
    cleaned = pattern.sub("", original).strip()
    block = build_env_block(targets)
    updated = block + "\n\n" + cleaned + "\n" if cleaned else block + "\n"
    if dry_run:
        return f"[DRY RUN] Would update {path}:\n{block}"
    path.write_text(updated, encoding="utf-8")
    return None


def _is_ip_literal(value: str) -> bool:
    """判断字符串是否为 IP 字面量。"""
    candidate = value.strip().strip('"').strip("'").strip("[]")
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def runtime_has_domain_proxies(runtime_text: str) -> bool:
    """检查运行时配置里是否存在域名型代理节点。"""
    for match in re.finditer(r"^\s*server:\s*([^\s#]+)", runtime_text, re.MULTILINE):
        server = match.group(1).strip().strip('"').strip("'")
        if server and not _is_ip_literal(server) and server.lower() != "localhost":
            return True
    return False


def ensure_verge_dns_toggle(clash_dir: Path) -> bool:
    """检查 Clash Verge DNS 设置状态（不再修改）。

    之前的实现会强制设置 enable_dns_settings: false，但这会导致
    订阅自带的中国 DNS (223.5.5.5/114.114.114.114) 无法被 Global Merge
    覆盖，进而破坏 fake-ip 模式下的节点切换。现在只做检查不做修改。
    """
    verge_yaml = clash_dir / "verge.yaml"
    if not verge_yaml.exists():
        return False
    # 不再修改 enable_dns_settings，避免破坏节点切换
    return False


def redact_text(text: str, tokens: list[str]) -> str:
    """脱敏输出。"""
    redacted = text
    for token in sorted({t for t in tokens if t}, key=len, reverse=True):
        redacted = redacted.replace(token, "***")
    redacted = re.sub(r'("password"\s*:\s*")[^"]+(")', r'\1***\2', redacted)
    redacted = re.sub(r"(-password\s+)\S+", r"\1***", redacted)
    return redacted


def has_failure(findings: list[Finding], keys: set[str]) -> bool:
    return any(f.status == "fail" and f.key in keys for f in findings)


def find_item(findings: list[Finding], key: str, statuses: tuple[str, ...]) -> Finding | None:
    for finding in findings:
        if finding.key == key and finding.status in statuses:
            return finding
    return None


def append_risk_skip(actions: list[str], label: str, flag: str, reason: str) -> None:
    actions.append(f"Skipped {label}: {reason}. Re-run with {flag} to allow this higher-risk repair")


def fix_local(ctx: Context, findings: list[Finding] | None = None) -> list[str]:
    findings = findings or collect_findings(ctx, include_vpn=False)
    public_ip = fetch_public_ip()
    targets = build_target_profile(ctx, public_ip)
    actions: list[str] = []

    # Shell env block
    if has_failure(findings, {"timezone", "locale", "proxy-env", "privacy-env"}):
        for path in plat.get_shell_profile_paths():
            msg = upsert_env_block(path, targets, ctx.dry_run)
            if msg:
                actions.append(msg)
            else:
                actions.append(f"Updated {path.name} env block")

    # Telemetry
    if has_failure(findings, {"telemetry"}):
        tel = ctx.claude_dir / "telemetry"
        if tel.exists():
            if ctx.dry_run:
                count = sum(1 for _ in tel.iterdir())
                actions.append(f"[DRY RUN] Would remove {tel} ({count} files)")
            else:
                if plat.remove_tree(tel):
                    actions.append("Removed Claude telemetry")
                else:
                    actions.append("Failed to remove Claude telemetry")

    # Git
    if has_failure(findings, {"git-identity"}):
        if ctx.dry_run:
            actions.append("[DRY RUN] Would unset git user.name and user.email")
        else:
            plat.unset_git_global_value("user.name")
            plat.unset_git_global_value("user.email")
            actions.append("Cleared global git identity")

    # Clash Verge DNS toggle
    if ctx.clash_dir is not None and has_failure(findings, {"system-dns-display"}):
        if ctx.dry_run:
            runtime = ctx.clash_dir / "clash-verge.yaml"
            runtime_text = runtime.read_text(encoding="utf-8", errors="ignore") if runtime.exists() else ""
            if plat.PLATFORM == "darwin" and runtime_has_domain_proxies(runtime_text):
                actions.append("[DRY RUN] Would skip Clash Verge DNS toggle because runtime proxies use domains")
            else:
                actions.append("[DRY RUN] Would set Clash Verge enable_dns_settings to false")
        else:
            if ensure_verge_dns_toggle(ctx.clash_dir):
                actions.append("Set Clash Verge enable_dns_settings to false")
            else:
                actions.append("Skipped Clash Verge DNS toggle to avoid breaking domain-based proxies")

    # DNS display — fix on both fail and warn (TUN cosmetic)
    dns_display = find_item(findings, "system-dns-display", ("fail", "warn"))
    dns_needs_fix = dns_display is not None
    if dns_needs_fix:
        if ctx.dry_run:
            actions.append("[DRY RUN] Would set DHCP-resistant static DNS (cross-platform)")
        elif ctx.allow_static_dns:
            static_actions = plat.set_static_dns()
            actions.extend(static_actions)
        else:
            append_risk_skip(
                actions,
                "static DNS lock",
                "--allow-static-dns",
                f"system-dns-display is {dns_display.status}",
            )

    # DNS watchdog — backup layer (auto-corrects if DHCP still overrides)
    watchdog_needed = ctx.clash_dir and (
        dns_needs_fix or
        any(f.key == "dns-cleanup-watchdog" and f.status != "pass" for f in findings)
    )
    if watchdog_needed:
        if ctx.dry_run:
            actions.append("[DRY RUN] Would install DNS cleanup watchdog")
        elif ctx.allow_dns_watchdog:
            actions.extend(plat.install_dns_watchdog(ctx.clash_dir))
        else:
            append_risk_skip(
                actions,
                "DNS watchdog installation",
                "--allow-dns-watchdog",
                "this creates a persistent background repair task",
            )

    # Package mirrors: npm
    if has_failure(findings, {"npm-registry"}):
        if ctx.dry_run:
            actions.append("[DRY RUN] Would reset npm registry to https://registry.npmjs.org/")
        else:
            plat.set_npm_registry("https://registry.npmjs.org/")
            actions.append("Reset npm registry to https://registry.npmjs.org/")

    # Package mirrors: pip
    if has_failure(findings, {"pip-index"}):
        if ctx.dry_run:
            actions.append("[DRY RUN] Would remove China pip index-url from config")
        else:
            plat.unset_pip_global_index()
            for pip_conf in [ctx.home / ".pip" / "pip.conf", ctx.home / ".config" / "pip" / "pip.conf"]:
                if pip_conf.exists():
                    text = pip_conf.read_text(errors="ignore")
                    cleaned = re.sub(r'index-url\s*=\s*\S+\n?', '', text)
                    pip_conf.write_text(cleaned)
            actions.append("Removed China pip mirror from config")

    # Package mirrors: brew
    if has_failure(findings, {"brew-mirrors"}):
        brew_keys = ["HOMEBREW_API_DOMAIN", "HOMEBREW_BOTTLE_DOMAIN", "HOMEBREW_BREW_GIT_REMOTE"]
        if ctx.dry_run:
            actions.append(f"[DRY RUN] Would remove brew mirror env vars from shell profiles: {', '.join(brew_keys)}")
        else:
            for profile_path in plat.get_shell_profile_paths():
                if not profile_path.exists():
                    continue
                text = profile_path.read_text(errors="ignore")
                modified = text
                for key in brew_keys:
                    modified = re.sub(rf'export\s+{key}=\S+\n?', '', modified)
                if modified != text:
                    profile_path.write_text(modified)
            actions.append("Removed brew China mirror env vars from shell profiles")

    # Shell history: surgically remove only China domain lines
    if any(f.key == "shell-history" and f.status in ("fail", "warn") for f in findings):
        if ctx.dry_run:
            preview = plat.clean_shell_history(dry_run=True)
            for path, count in preview.items():
                actions.append(f"[DRY RUN] Would remove {count} China-domain lines from {path}")
        elif ctx.allow_shell_history_cleanup:
            removed = plat.clean_shell_history(dry_run=False)
            for path, count in removed.items():
                actions.append(f"Removed {count} China-domain lines from {path} (backup: {path}.bak)")
        else:
            append_risk_skip(
                actions,
                "shell history cleanup",
                "--allow-shell-history-cleanup",
                "this deletes matching history lines",
            )

    # Input method: install RIME and remove system Chinese IME
    if any(f.key == "input-method" and f.status == "warn" for f in findings):
        if ctx.dry_run:
            actions.extend(plat.install_rime(dry_run=True))
            actions.extend(plat.remove_system_chinese_ime(dry_run=True))
        elif ctx.allow_rime_install:
            actions.extend(plat.install_rime(dry_run=False))
        else:
            append_risk_skip(
                actions,
                "RIME installation",
                "--allow-rime-install",
                "this installs system input-method software",
            )
        if any(f.key == "input-method" and f.status == "warn" for f in findings) and not ctx.dry_run:
            if ctx.allow_ime_removal:
                actions.extend(plat.remove_system_chinese_ime(dry_run=False))
            else:
                append_risk_skip(
                    actions,
                    "system Chinese IME removal",
                    "--allow-ime-removal",
                    "this permanently edits the input-source list",
                )

    return actions or ["No local repairs needed"]


def fix_vpn(ctx: Context, findings: list[Finding] | None = None) -> list[str]:
    """执行 VPN 修复（含脱敏输出）。"""
    findings = findings or inspect_vpn(ctx)
    return vpnops.fix(ctx.vpn_root, findings, ctx.dry_run, plat.run_shell, redact_text)


# ---------------------------------------------------------------------------
# Report & CLI
# ---------------------------------------------------------------------------

def print_report(findings: list[Finding], show_score: bool = True, save: bool = True) -> None:
    grouped: dict[str, list[Finding]] = {}
    for f in findings:
        grouped.setdefault(f.group, []).append(f)

    status_icon = {
        "pass": _c(_C.GREEN, "✅"),
        "fail": _c(_C.RED, "❌"),
        "warn": _c(_C.YELLOW, "⚠️ "),
        "skip": _c(_C.DIM, "⏭️ "),
    }

    for group in sorted(grouped):
        print(_c(_C.BOLD + _C.CYAN, f"\n[{group}]"))
        for f in grouped[group]:
            icon = status_icon.get(f.status, "?")
            key_str = _c(_C.WHITE, f.key) if USE_COLOR else f.key
            print(f"  {icon} {key_str}: {f.summary}")
            for d in f.details:
                print(_c(_C.DIM, f"      · {d}"))

    if show_score:
        report = compute_score(findings)
        print(format_score_report(report))

    fail_count = sum(1 for f in findings if f.status == "fail")
    warn_count = sum(1 for f in findings if f.status == "warn")
    pass_count = sum(1 for f in findings if f.status == "pass")

    summary_parts = [
        _c(_C.GREEN, f"{pass_count} pass"),
        _c(_C.YELLOW, f"{warn_count} warn"),
        _c(_C.RED, f"{fail_count} fail") if fail_count else f"{fail_count} fail",
    ]
    print(f"Summary: {', '.join(summary_parts)}")

    # Save to history
    if show_score and save:
        report = compute_score(findings)
        save_history(report.total_score, report.grade, fail_count, warn_count)


def main() -> int:
    parser = argparse.ArgumentParser(description="CC-check v1.3.0 — Cross-platform environment auditor")
    sub = parser.add_subparsers(dest="command", required=True)

    command_parsers: dict[str, argparse.ArgumentParser] = {}
    for name in ("inspect", "fix-local", "fix-vpn", "verify", "full"):
        sp = sub.add_parser(name)
        sp.add_argument("--vpn-root", help="Explicit VPN project root for optional VPN checks")
        sp.add_argument("--clash-dir", help="Override Clash Verge directory")
        sp.add_argument("--public-subscription-url", help="Override subscription URL")
        sp.add_argument("--target-timezone", help="Expected timezone (Olson)")
        sp.add_argument("--target-locale", help="Expected locale, e.g. en_US.UTF-8")
        sp.add_argument("--target-language", help="Expected language, e.g. en_US")
        sp.add_argument("--proxy-url", help="Expected proxy URL")
        sp.add_argument("--expected-ip-type", default="residential", help="Expected IP type")
        sp.add_argument("--json", action="store_true", help="Output as JSON")
        sp.add_argument("--dry-run", action="store_true", help="Preview changes without applying")
        command_parsers[name] = sp

    for name in ("fix-local", "full"):
        sp = command_parsers[name]
        sp.add_argument("--allow-static-dns", action="store_true", help="Allow static DNS lock (system-level network change)")
        sp.add_argument("--allow-dns-watchdog", action="store_true", help="Allow persistent DNS watchdog installation")
        sp.add_argument("--allow-shell-history-cleanup", action="store_true", help="Allow deletion of matching shell history lines")
        sp.add_argument("--allow-rime-install", action="store_true", help="Allow RIME input method installation")
        sp.add_argument("--allow-ime-removal", action="store_true", help="Allow removal of system Chinese IMEs")

    history_sp = sub.add_parser("history", help="Show score history and trends")

    bl_sp = sub.add_parser("browser-leaks", help="Run browser leak baseline checks plus manual checklist")
    bl_sp.add_argument("--json", action="store_true", help="Output as JSON")
    bl_sp.add_argument(
        "--automation",
        choices=("auto", "off"),
        default="auto",
        help="Whether to auto-run optional Playwright browser checks",
    )
    bl_sp.add_argument(
        "--browser-cdp-url",
        help="Attach to an already-running Chromium-compatible browser via CDP (for example http://127.0.0.1:9222)",
    )

    dns_sp = sub.add_parser("fix-system-dns-display")
    dns_sp.add_argument("--quiet", action="store_true")
    dns_sp.add_argument("--dry-run", action="store_true")

    args = parser.parse_args()
    ctx = make_context(args)

    try:
        if args.command == "history":
            print(format_history())
            return 0

        if args.command == "browser-leaks":
            findings, report_meta = bleaks.run_browser_checks(
                getattr(args, "automation", "auto"),
                browser_cdp_url=getattr(args, "browser_cdp_url", None),
            )
            if getattr(args, "json", False):
                print(json.dumps(bleaks.build_report_payload(findings, report_meta), ensure_ascii=False, indent=2))
            else:
                bleaks.print_browser_report(findings, report_meta)
            return 0

        if args.command == "inspect":
            findings = collect_findings(ctx)
            if getattr(args, "json", False):
                print(json.dumps([f.to_dict() for f in findings], ensure_ascii=False, indent=2))
            else:
                print_report(findings)
            return 0 if not has_scored_failures(findings) else 2

        if args.command == "fix-local":
            for a in fix_local(ctx):
                print(a)
            if not ctx.dry_run:
                print(_c(_C.BOLD, "\n=== Auto-Verify ==="))
                verify_findings = collect_findings(ctx, include_vpn=False)
                print_report(verify_findings)
                return 0 if not has_scored_failures(verify_findings) else 2
            return 0

        if args.command == "fix-vpn":
            for a in fix_vpn(ctx):
                print(a)
            return 0

        if args.command == "verify":
            findings = collect_findings(ctx)
            if getattr(args, "json", False):
                print(json.dumps([f.to_dict() for f in findings], ensure_ascii=False, indent=2))
            else:
                print_report(findings)
            return 0 if not has_scored_failures(findings) else 2

        if args.command == "full":
            print("=== Phase 1: Inspect ===")
            initial = collect_findings(ctx)
            fail_count = count_scored_failures(initial)
            if fail_count == 0:
                print_report(initial)
                return 0

            print_report(initial, show_score=False)
            print(f"\n=== Phase 2: Fix ({fail_count} issues) ===")
            local_fail = any(f.group in {"claude", "system", "clash", "dns", "privacy", "identity", "packages"} and f.status == "fail" for f in initial)
            vpn_fail = any(f.group == "vpn" and f.status == "fail" for f in initial)
            if local_fail:
                for a in fix_local(ctx, initial):
                    print(f"  {a}")
            if vpn_fail:
                for a in fix_vpn(ctx, initial):
                    print(f"  {a}")

            print("\n=== Phase 3: Verify ===")
            final = collect_findings(ctx)
            print_report(final)
            return 0 if not has_scored_failures(final) else 2

        if args.command == "fix-system-dns-display":
            dns_map = plat.get_dns_servers()
            actions = []
            for svc, servers in dns_map.items():
                if any(s in plat.SUSPICIOUS_DNS for s in servers):
                    if getattr(args, "dry_run", False):
                        actions.append(f"[DRY RUN] Would clear DNS for {svc}")
                    else:
                        plat.clear_dns_for_service(svc)
                        actions.append(f"Cleared DNS for {svc}")
            if not getattr(args, "quiet", False):
                for a in actions or ["No suspicious DNS found"]:
                    print(a)
            return 0

    except Exception as exc:
        print(f"CC-check failed: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 1

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
