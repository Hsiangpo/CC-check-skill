#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CC-check 浏览器泄露检测模块。

层级策略：
1. Python 可直接测试的项目：自动执行
2. 需要浏览器的项目：
   - 如果 LLM 有 Chrome DevTools MCP → 自动化测试
   - 如果没有 → 输出手动测试指引
"""

from __future__ import annotations

import json
import re
import ssl
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.request import urlopen

from browser_automation import detect_playwright_support, execute_playwright_runner


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class BrowserFinding:
    test: str          # webrtc | ip | javascript | tls | fonts | canvas
    key: str
    status: str        # pass | fail | warn | skip | manual
    summary: str
    details: list[str] = field(default_factory=list)


SCRIPT_DIR = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# Python-testable: TLS capabilities
# ---------------------------------------------------------------------------

def check_tls_support() -> list[BrowserFinding]:
    """检测本机 Python SSL 支持的 TLS 版本。"""
    findings: list[BrowserFinding] = []
    ctx = ssl.create_default_context()

    # Check supported protocol versions
    tls13_ok = hasattr(ssl, "TLSVersion") and ssl.TLSVersion.TLSv1_3 is not None
    findings.append(BrowserFinding(
        "tls", "tls-1.3-support",
        "pass" if tls13_ok else "warn",
        f"TLS 1.3 support: {'available' if tls13_ok else 'not available'}",
    ))

    # Test actual TLS connection to a known server
    try:
        with socket.create_connection(("browserleaks.com", 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname="browserleaks.com") as ssock:
                ver = ssock.version()
                cipher = ssock.cipher()
                findings.append(BrowserFinding(
                    "tls", "tls-negotiated",
                    "pass" if ver == "TLSv1.3" else "warn",
                    f"Negotiated: {ver}, cipher: {cipher[0] if cipher else '?'}",
                ))
    except Exception as e:
        findings.append(BrowserFinding(
            "tls", "tls-negotiated", "fail",
            f"TLS connection failed: {e}",
        ))

    return findings


# ---------------------------------------------------------------------------
# Python-testable: IP from browser perspective (via different endpoints)
# ---------------------------------------------------------------------------

def check_ip_consistency() -> list[BrowserFinding]:
    """检测从不同端点获取的 IP 是否一致。"""
    findings: list[BrowserFinding] = []
    ips: dict[str, str] = {}

    endpoints = {
        "ifconfig.me": "https://ifconfig.me/ip",
        "ipify": "https://api.ipify.org",
        "icanhazip": "https://icanhazip.com",
        "httpbin": "https://httpbin.org/ip",
    }

    for name, url in endpoints.items():
        try:
            with urlopen(url, timeout=8) as resp:
                text = resp.read().decode("utf-8", errors="ignore").strip()
                if name == "httpbin":
                    data = json.loads(text)
                    text = data.get("origin", "").split(",")[0].strip()
                if text:
                    ips[name] = text
        except Exception:
            continue

    unique_ips = set(ips.values())
    if len(unique_ips) == 1:
        ip = list(unique_ips)[0]
        findings.append(BrowserFinding(
            "ip", "multi-endpoint-consistency", "pass",
            f"All {len(ips)} endpoints return same IP: {ip}",
            [f"{k}: {v}" for k, v in ips.items()],
        ))
    elif len(unique_ips) > 1:
        findings.append(BrowserFinding(
            "ip", "multi-endpoint-consistency", "fail",
            f"IP inconsistency: {len(unique_ips)} different IPs detected",
            [f"{k}: {v}" for k, v in ips.items()],
        ))
    else:
        findings.append(BrowserFinding(
            "ip", "multi-endpoint-consistency", "skip",
            "Could not reach any IP endpoint",
        ))

    return findings


# ---------------------------------------------------------------------------
# Browser-required tests: URLs and extraction instructions
# ---------------------------------------------------------------------------

BROWSER_TESTS = [
    {
        "test": "webrtc",
        "name": "WebRTC Leak Test",
        "url": "https://browserleaks.com/webrtc",
        "critical": True,
        "description": "检测 WebRTC 是否泄露真实 IP（绕过 VPN）",
        "pass_criteria": "WebRTC Leak Test 显示 'No Leak'，Local/Public IP 为空或 '-'",
        "fail_indicators": ["显示了非 VPN 的 IP 地址", "Local IP 暴露了内网地址如 192.168.x.x"],
        "js_extract": """
            () => {
                const rows = document.querySelectorAll('table tr');
                const data = {};
                rows.forEach(row => {
                    const cells = row.querySelectorAll('td');
                    if (cells.length >= 2) {
                        const key = cells[0].textContent.trim();
                        const value = cells[1].textContent.trim();
                        data[key] = value;
                    }
                });
                return JSON.stringify(data);
            }
        """,
    },
    {
        "test": "javascript",
        "name": "JavaScript Browser Information",
        "url": "https://browserleaks.com/javascript",
        "critical": True,
        "description": "检测浏览器 JS 环境的 locale/timezone 是否暴露非目标地区",
        "pass_criteria": "locale=en-US, timeZone=America/*, hourCycle=h12",
        "fail_indicators": ["locale 包含 zh-CN", "timeZone 显示 Asia/Shanghai", "hourCycle 为 h23"],
        "js_extract": """
            () => {
                const intl = Intl.DateTimeFormat().resolvedOptions();
                return JSON.stringify({
                    locale: intl.locale,
                    timeZone: intl.timeZone,
                    hourCycle: intl.hourCycle,
                    calendar: intl.calendar,
                    numberingSystem: intl.numberingSystem,
                    userAgent: navigator.userAgent,
                    language: navigator.language,
                    languages: navigator.languages,
                    platform: navigator.platform,
                });
            }
        """,
    },
    {
        "test": "ip",
        "name": "IP Address Lookup",
        "url": "https://browserleaks.com/ip",
        "critical": False,
        "description": "检测浏览器出口 IP 的地理位置和 ISP 信息",
        "pass_criteria": "Country=US, Usage Type=Residential/Cable/DSL",
        "fail_indicators": ["Country 显示 CN/China", "Usage Type 显示 Hosting/Datacenter"],
        "js_extract": """
            () => {
                const rows = document.querySelectorAll('table tr');
                const data = {};
                rows.forEach(row => {
                    const cells = row.querySelectorAll('td');
                    if (cells.length >= 2) {
                        data[cells[0].textContent.trim()] = cells[1].textContent.trim();
                    }
                });
                return JSON.stringify(data);
            }
        """,
    },
    {
        "test": "fonts",
        "name": "Font Fingerprinting",
        "url": "https://browserleaks.com/fonts",
        "critical": False,
        "description": "检测字体列表是否包含中文字体（暴露中文系统）",
        "pass_criteria": "字体列表中不包含宋体、黑体、微软雅黑等中文字体",
        "fail_indicators": ["SimSun", "SimHei", "Microsoft YaHei", "STSong", "PingFang SC", "Noto Sans CJK"],
        "js_extract": None,  # Font test needs full page load, extract from snapshot
    },
    {
        "test": "canvas",
        "name": "Canvas Fingerprinting",
        "url": "https://browserleaks.com/canvas",
        "critical": False,
        "description": "检测 Canvas 指纹的唯一性",
        "pass_criteria": "Canvas 指纹存在（正常），关键是唯一性不会跨会话追踪",
        "fail_indicators": [],
        "js_extract": None,
    },
    {
        "test": "tls",
        "name": "TLS Client Test",
        "url": "https://browserleaks.com/tls",
        "critical": False,
        "description": "检测 TLS 指纹和协议支持",
        "pass_criteria": "TLS 1.3 Enabled, TLS 1.0/1.1 Disabled",
        "fail_indicators": ["TLS 1.0 Enabled", "TLS 1.1 Enabled"],
        "js_extract": None,
    },
]


def get_browser_tests() -> list[dict]:
    """返回需要浏览器的测试清单。"""
    return BROWSER_TESTS


# ---------------------------------------------------------------------------
# Analyze browser-extracted results
# ---------------------------------------------------------------------------

CHINA_FONTS = {
    "simsun", "simhei", "microsoft yahei", "microsoft jhenghei",
    "fangsong", "kaiti", "stsong", "stheiti", "stkaiti", "stfangsong",
    "pingfang sc", "pingfang tc", "noto sans cjk sc", "noto sans cjk tc",
    "hiragino sans gb", "heiti sc", "heiti tc", "songti sc", "songti tc",
    "wqy-microhei", "wqy-zenhei", "wenquanyi",
    "source han sans sc", "source han serif sc",
}


def analyze_webrtc(data: dict) -> list[BrowserFinding]:
    """分析 WebRTC 测试结果 (来自浏览器 JS 提取)。"""
    findings: list[BrowserFinding] = []
    if "localCandidates" in data or "publicCandidates" in data:
        if not data.get("supported", True):
            findings.append(BrowserFinding("webrtc", "webrtc-leak", "skip", "WebRTC API not available"))
            findings.append(BrowserFinding("webrtc", "webrtc-local-ip", "skip", "WebRTC local IP check unavailable"))
            return findings

        error = str(data.get("error", "")).strip()
        local_candidates = data.get("localCandidates", []) or []
        public_candidates = data.get("publicCandidates", []) or []
        if error:
            findings.append(BrowserFinding("webrtc", "webrtc-leak", "warn", f"WebRTC collection error: {error}"))
        elif public_candidates:
            findings.append(BrowserFinding(
                "webrtc",
                "webrtc-leak",
                "fail",
                f"WebRTC exposes public candidates: {', '.join(public_candidates[:3])}",
                public_candidates[:5],
            ))
        else:
            findings.append(BrowserFinding("webrtc", "webrtc-leak", "pass", "WebRTC public IP not exposed"))

        if local_candidates:
            findings.append(BrowserFinding(
                "webrtc",
                "webrtc-local-ip",
                "fail",
                f"WebRTC exposes local IP: {', '.join(local_candidates[:3])}",
                local_candidates[:5],
            ))
        else:
            findings.append(BrowserFinding("webrtc", "webrtc-local-ip", "pass", "WebRTC local IP not exposed"))
        return findings

    leak = data.get("WebRTC Leak Test", "").lower()
    local_ip = data.get("Local IP Address", "-")
    public_ip = data.get("Public IP Address", "-")

    if "no leak" in leak:
        findings.append(BrowserFinding("webrtc", "webrtc-leak", "pass",
                                       "WebRTC: No leak detected"))
    else:
        findings.append(BrowserFinding("webrtc", "webrtc-leak", "fail",
                                       f"WebRTC leak detected! Local={local_ip} Public={public_ip}"))

    if local_ip and local_ip != "-" and local_ip != "n/a":
        findings.append(BrowserFinding("webrtc", "webrtc-local-ip", "fail",
                                       f"WebRTC exposes local IP: {local_ip}"))
    else:
        findings.append(BrowserFinding("webrtc", "webrtc-local-ip", "pass",
                                       "WebRTC local IP not exposed"))

    return findings


def analyze_javascript(data: dict) -> list[BrowserFinding]:
    """分析 JavaScript 环境测试结果。"""
    findings: list[BrowserFinding] = []

    locale = data.get("locale", "")
    tz = data.get("timeZone", "")
    lang = data.get("language", "")
    langs = data.get("languages", [])
    hour = data.get("hourCycle", "")

    # Locale check
    if "zh" in locale.lower():
        findings.append(BrowserFinding("javascript", "js-locale", "fail",
                                       f"Browser locale is Chinese: {locale}"))
    elif locale.startswith("en"):
        findings.append(BrowserFinding("javascript", "js-locale", "pass",
                                       f"Browser locale: {locale}"))
    else:
        findings.append(BrowserFinding("javascript", "js-locale", "warn",
                                       f"Browser locale: {locale}"))

    # Timezone check
    if "asia/shanghai" in tz.lower() or "asia/chongqing" in tz.lower():
        findings.append(BrowserFinding("javascript", "js-timezone", "fail",
                                       f"Browser timezone is Chinese: {tz}"))
    elif tz.startswith("America/"):
        findings.append(BrowserFinding("javascript", "js-timezone", "pass",
                                       f"Browser timezone: {tz}"))
    else:
        findings.append(BrowserFinding("javascript", "js-timezone", "warn",
                                       f"Browser timezone: {tz}"))

    # Language
    if isinstance(langs, list):
        china_langs = [l for l in langs if "zh" in l.lower()]
        if china_langs:
            findings.append(BrowserFinding("javascript", "js-languages", "fail",
                                           f"Browser languages contain Chinese: {langs}"))
        else:
            findings.append(BrowserFinding("javascript", "js-languages", "pass",
                                           f"Browser languages: {langs}"))

    return findings


def analyze_browser_ip(data: dict) -> list[BrowserFinding]:
    """分析浏览器上下文发出的多端点 IP 结果。"""
    findings: list[BrowserFinding] = []
    endpoints = data.get("endpoints", data if isinstance(data, dict) else {})
    ips = {name: str(value).strip() for name, value in endpoints.items() if str(value).strip()}
    unique_ips = set(ips.values())

    if len(unique_ips) == 1 and ips:
        findings.append(BrowserFinding(
            "ip",
            "browser-multi-endpoint-consistency",
            "pass",
            f"Browser endpoints agree on IP: {next(iter(unique_ips))}",
            [f"{name}: {ip}" for name, ip in ips.items()],
        ))
    elif len(unique_ips) > 1:
        findings.append(BrowserFinding(
            "ip",
            "browser-multi-endpoint-consistency",
            "fail",
            f"Browser endpoints returned {len(unique_ips)} different IPs",
            [f"{name}: {ip}" for name, ip in ips.items()],
        ))
    else:
        findings.append(BrowserFinding(
            "ip",
            "browser-multi-endpoint-consistency",
            "skip",
            "Browser context could not reach any IP endpoint",
        ))
    return findings


def analyze_fonts(font_data: Any) -> list[BrowserFinding]:
    """分析字体列表是否包含中文字体。"""
    findings: list[BrowserFinding] = []
    if isinstance(font_data, dict):
        found_china = [str(font) for font in font_data.get("detectedFonts", []) if str(font).strip()]
    else:
        lower = str(font_data).lower()
        found_china = [f for f in CHINA_FONTS if f in lower]
    if found_china:
        findings.append(BrowserFinding("fonts", "china-fonts", "warn",
                                       f"Found {len(found_china)} Chinese font(s) in browser",
                                       found_china[:5]))
    else:
        findings.append(BrowserFinding("fonts", "china-fonts", "pass",
                                       "No Chinese fonts detected in browser"))
    return findings


def analyze_canvas(data: dict[str, Any]) -> list[BrowserFinding]:
    """分析 Canvas 指纹采集结果。"""
    findings: list[BrowserFinding] = []
    fingerprint = str(data.get("fingerprintHash", "")).strip()
    secondary = str(data.get("secondaryHash", "")).strip()
    urls_match = bool(data.get("dataUrlsMatch"))

    if fingerprint:
        findings.append(BrowserFinding(
            "canvas",
            "canvas-fingerprint",
            "pass",
            f"Canvas fingerprint collected: {fingerprint[:16]}...",
        ))
    else:
        findings.append(BrowserFinding(
            "canvas",
            "canvas-fingerprint",
            "warn",
            "Canvas fingerprint could not be collected",
        ))

    if fingerprint and secondary:
        stable = urls_match and fingerprint == secondary
        findings.append(BrowserFinding(
            "canvas",
            "canvas-fingerprint-stability",
            "pass" if stable else "warn",
            "Canvas fingerprint is stable within the current run" if stable else "Canvas fingerprint drift detected within the current run",
            [f"primary={fingerprint[:16]}", f"secondary={secondary[:16]}"],
        ))
    else:
        findings.append(BrowserFinding(
            "canvas",
            "canvas-fingerprint-stability",
            "skip",
            "Canvas stability check unavailable",
        ))
    return findings


def analyze_tls_page(data: dict[str, Any]) -> list[BrowserFinding]:
    """分析浏览器 TLS 检测页面文本。"""
    findings: list[BrowserFinding] = []
    text = str(data.get("text", "")).strip()
    if not text:
        return [
            BrowserFinding("tls", "tls-browser-version", "skip", "Browser TLS page text unavailable"),
            BrowserFinding("tls", "tls-browser-legacy", "skip", "Browser TLS legacy protocol check unavailable"),
        ]

    lower = text.lower()
    if "tls 1.3 enabled" in lower or "tlsv1.3" in lower:
        findings.append(BrowserFinding("tls", "tls-browser-version", "pass", "Browser TLS page reports TLS 1.3"))
    elif "tls 1.2" in lower:
        findings.append(BrowserFinding("tls", "tls-browser-version", "warn", "Browser TLS page did not confirm TLS 1.3"))
    else:
        findings.append(BrowserFinding("tls", "tls-browser-version", "warn", "Browser TLS version could not be confirmed"))

    legacy_hits = []
    for version in ("1.0", "1.1"):
        if re.search(rf"tls\s*{re.escape(version)}\s*enabled", lower):
            legacy_hits.append(version)
    findings.append(BrowserFinding(
        "tls",
        "tls-browser-legacy",
        "fail" if legacy_hits else "pass",
        f"Legacy TLS enabled: {', '.join(legacy_hits)}" if legacy_hits else "Legacy TLS 1.0/1.1 not detected",
    ))
    return findings


# ---------------------------------------------------------------------------
# Run all Python-testable checks
# ---------------------------------------------------------------------------

def run_python_checks() -> list[BrowserFinding]:
    """运行所有 Python 可测试的浏览器泄露检测。"""
    findings: list[BrowserFinding] = []
    findings.extend(check_ip_consistency())
    findings.extend(check_tls_support())
    return findings


def _default_report_meta() -> dict[str, Any]:
    """返回浏览器检测报告的默认元数据。"""
    return {
        "mode": "python-baseline-plus-manual-checklist",
        "automation_supported": False,
        "automation_used": False,
        "provider": "playwright",
        "reason": "",
        "executed_tests": [],
        "errors": [],
    }


def _manual_checklist(executed_tests: list[str] | None = None) -> list[dict[str, Any]]:
    """返回仍需要人工确认的浏览器检测项。"""
    executed = set(executed_tests or [])
    return [
        {
            "test": item["test"],
            "name": item["name"],
            "url": item["url"],
            "critical": item["critical"],
            "description": item["description"],
            "pass_criteria": item["pass_criteria"],
            "fail_indicators": item["fail_indicators"],
        }
        for item in BROWSER_TESTS
        if item["test"] not in executed
    ]


def detect_playwright_automation() -> dict[str, Any]:
    """探测是否可使用 Playwright 自动化浏览器检测。"""
    return detect_playwright_support(SCRIPT_DIR)


def run_playwright_automation() -> dict[str, Any]:
    """执行 Playwright 自动化并将原始结果转换为浏览器发现项。"""
    payload = execute_playwright_runner(SCRIPT_DIR)
    findings: list[BrowserFinding] = []
    executed_tests = list(payload.get("executed_tests", []))
    results = payload.get("results", {})

    analyzers = {
        "javascript": analyze_javascript,
        "webrtc": analyze_webrtc,
        "ip": analyze_browser_ip,
        "fonts": analyze_fonts,
        "canvas": analyze_canvas,
        "tls": analyze_tls_page,
    }
    for test_name in executed_tests:
        analyzer = analyzers.get(test_name)
        if not analyzer:
            continue
        raw_data = results.get(test_name, {})
        findings.extend(analyzer(raw_data))

    return {
        "provider": payload.get("provider", "playwright"),
        "findings": findings,
        "executed_tests": executed_tests,
        "errors": payload.get("errors", []),
        "ok": payload.get("ok", False),
    }


def run_browser_checks(automation: str = "auto") -> tuple[list[BrowserFinding], dict[str, Any]]:
    """运行浏览器检测并在可用时自动接入 Playwright。"""
    findings = run_python_checks()
    meta = _default_report_meta()
    if automation == "off":
        meta["reason"] = "automation disabled"
        return findings, meta

    capability = detect_playwright_automation()
    meta["provider"] = capability.get("provider", "playwright")
    meta["automation_supported"] = bool(capability.get("available"))
    meta["reason"] = capability.get("reason", "")
    if not capability.get("available"):
        return findings, meta

    automation_result = run_playwright_automation()
    meta["errors"] = automation_result.get("errors", [])
    executed_tests = automation_result.get("executed_tests", [])
    if not executed_tests:
        if meta["errors"]:
            meta["reason"] = meta["errors"][0]
        return findings, meta

    findings.extend(automation_result.get("findings", []))
    meta.update({
        "mode": "playwright-automation-plus-python-baseline",
        "automation_used": True,
        "executed_tests": executed_tests,
    })
    return findings, meta


def build_report_payload(findings: list[BrowserFinding], report_meta: dict[str, Any] | None = None) -> dict[str, Any]:
    """构建带自动项和手工清单的结构化结果。"""
    report_meta = {**_default_report_meta(), **(report_meta or {})}
    automated = [
        {
            "test": finding.test,
            "key": finding.key,
            "status": finding.status,
            "summary": finding.summary,
            "details": finding.details,
        }
        for finding in findings
    ]
    return {
        "mode": report_meta["mode"],
        "automation_supported": report_meta["automation_supported"],
        "automation_used": report_meta["automation_used"],
        "provider": report_meta["provider"],
        "reason": report_meta["reason"],
        "executed_tests": report_meta["executed_tests"],
        "errors": report_meta["errors"],
        "automated": automated,
        "manual": _manual_checklist(report_meta["executed_tests"]),
    }


# ---------------------------------------------------------------------------
# Print results
# ---------------------------------------------------------------------------

def print_browser_report(findings: list[BrowserFinding], report_meta: dict[str, Any] | None = None) -> None:
    """输出浏览器泄露检测报告。"""
    report_meta = {**_default_report_meta(), **(report_meta or {})}
    status_icon = {"pass": "✅", "fail": "❌", "warn": "⚠️ ", "skip": "⏭️ ", "manual": "🔍"}

    print("\n" + "=" * 50)
    print("  🌐 BrowserLeaks Report")
    print("=" * 50)

    for f in findings:
        icon = status_icon.get(f.status, "?")
        print(f"  {icon} [{f.test}] {f.key}: {f.summary}")
        for d in f.details:
            print(f"      · {d}")

    if report_meta["automation_used"]:
        executed = ", ".join(report_meta["executed_tests"]) or "none"
        print("\n" + "-" * 50)
        print(f"  🤖 Automation: {report_meta['provider']} ({executed})")
    elif report_meta["reason"]:
        print("\n" + "-" * 50)
        print(f"  ℹ️  Automation unavailable: {report_meta['reason']}")

    manual_items = _manual_checklist(report_meta["executed_tests"])
    if manual_items:
        print("\n" + "-" * 50)
        print("  📋 Browser-only tests (requires manual check or extra browser tooling):")
        print()
        for t in manual_items:
            emoji = "🔴" if t["critical"] else "🟡"
            print(f"  {emoji} {t['name']}")
            print(f"     URL: {t['url']}")
            print(f"     检查: {t['pass_criteria']}")
            print()
        print("  💡 Remaining manual checks focus on tests that are not yet automated.")
    print()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    findings, report_meta = run_browser_checks()
    print_browser_report(findings, report_meta)
