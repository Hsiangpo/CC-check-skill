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
from typing import Any
from urllib.request import urlopen
from urllib.error import URLError


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


def analyze_fonts(font_list_text: str) -> list[BrowserFinding]:
    """分析字体列表是否包含中文字体。"""
    findings: list[BrowserFinding] = []
    lower = font_list_text.lower()
    found_china = [f for f in CHINA_FONTS if f in lower]
    if found_china:
        findings.append(BrowserFinding("fonts", "china-fonts", "warn",
                                       f"Found {len(found_china)} Chinese font(s) in browser",
                                       found_china[:5]))
    else:
        findings.append(BrowserFinding("fonts", "china-fonts", "pass",
                                       "No Chinese fonts detected in browser"))
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


def build_report_payload(findings: list[BrowserFinding]) -> dict[str, Any]:
    """构建带自动项和手工清单的结构化结果。"""
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
    manual = [
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
    ]
    return {
        "mode": "python-baseline-plus-manual-checklist",
        "automation_supported": False,
        "automated": automated,
        "manual": manual,
    }


# ---------------------------------------------------------------------------
# Print results
# ---------------------------------------------------------------------------

def print_browser_report(findings: list[BrowserFinding], browser_available: bool = False) -> None:
    """输出浏览器泄露检测报告。"""
    status_icon = {"pass": "✅", "fail": "❌", "warn": "⚠️ ", "skip": "⏭️ ", "manual": "🔍"}

    print("\n" + "=" * 50)
    print("  🌐 BrowserLeaks Report")
    print("=" * 50)

    for f in findings:
        icon = status_icon.get(f.status, "?")
        print(f"  {icon} [{f.test}] {f.key}: {f.summary}")
        for d in f.details:
            print(f"      · {d}")

    if not browser_available:
        print("\n" + "-" * 50)
        print("  📋 Browser-only tests (requires manual check or Chrome DevTools MCP):")
        print()
        for t in BROWSER_TESTS:
            emoji = "🔴" if t["critical"] else "🟡"
            print(f"  {emoji} {t['name']}")
            print(f"     URL: {t['url']}")
            print(f"     检查: {t['pass_criteria']}")
            print()
        print("  💡 Instructions for LLM agents:")
        print("     If Chrome DevTools MCP is available, navigate to each URL")
        print("     and use evaluate_script with the provided js_extract functions")
        print("     to automatically extract and analyze results.")
        print("     Otherwise, prompt the user to open the URLs manually.")
    print()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    findings = run_python_checks()
    print_browser_report(findings, browser_available=False)
