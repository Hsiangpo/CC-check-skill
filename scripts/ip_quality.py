#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IP 质量检测辅助模块（增强版）。

多权威渠道评估 IP 类型、风险值、是否真实住宅。
"""

from __future__ import annotations

import json
import socket
import subprocess
from typing import Any
from urllib.error import URLError
from urllib.request import urlopen

from country_profiles import IANA_TIMEZONE_TO_LOCALE, resolve_country_profile

GOOD_IP_TYPES = {"residential", "mobile", "isp"}
BAD_IP_TYPES = {"hosting", "vpn", "proxy", "datacenter", "tor"}

# 真实住宅 ISP 白名单（美国常见家宽）
US_RESIDENTIAL_ISPS = {
    "comcast", "xfinity", "at&t", "verizon", "spectrum", "cox",
    "centurylink", "frontier", "windstream", "mediacom", "optimum",
    "charter", "altice", "suddenlink", "wow!", "rcn", "astound",
}

def fetch_json(url: str, timeout: int = 8) -> dict[str, Any] | None:
    try:
        with urlopen(url, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8", errors="ignore"))
    except (URLError, TimeoutError, socket.timeout, OSError, json.JSONDecodeError):
        return None


def run_whois(ip: str) -> str:
    try:
        result = subprocess.run(
            ["/usr/bin/env", "whois", ip],
            capture_output=True, text=True, timeout=20, check=False,
        )
        return (result.stdout or "")[:6000]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def parse_whois_country(text: str) -> str | None:
    for line in text.splitlines():
        if line.lower().startswith("country:"):
            value = line.split(":", 1)[1].strip()
            if value:
                return value
    return None


def assess_ip_quality(ip: str, expected_ip_type: str = "residential") -> dict[str, Any]:
    """用多权威渠道评估 IP 质量（并行加速）。"""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    # 并行请求 5 个渠道
    def _fetch_ipinfo() -> dict | None:
        return fetch_json(f"https://ipinfo.io/{ip}/json")

    def _fetch_ip_api() -> dict | None:
        return fetch_json(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,"
            f"timezone,isp,org,as,asname,proxy,hosting,mobile,query"
        )

    def _fetch_proxycheck() -> dict | None:
        return fetch_json(
            f"https://proxycheck.io/v2/{ip}?vpn=1&asn=1&risk=1&port=1&seen=1&days=7&tag=cc-check"
        )

    def _fetch_bgpview() -> dict | None:
        return fetch_json(f"https://api.bgpview.io/ip/{ip}")

    def _fetch_whois() -> str:
        return run_whois(ip)

    results: dict[str, Any] = {}
    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = {
            pool.submit(_fetch_ipinfo): "ipinfo",
            pool.submit(_fetch_ip_api): "ip_api",
            pool.submit(_fetch_proxycheck): "proxycheck",
            pool.submit(_fetch_bgpview): "bgpview",
            pool.submit(_fetch_whois): "whois",
        }
        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result()
            except Exception:
                results[name] = None

    ipinfo = results.get("ipinfo")
    ip_api = results.get("ip_api")
    proxycheck = results.get("proxycheck")
    bgpview = results.get("bgpview")
    whois_text = results.get("whois", "")
    whois_country = parse_whois_country(whois_text) if whois_text else None

    proxy_data = None
    if proxycheck and proxycheck.get("status") == "ok":
        proxy_data = proxycheck.get(ip, {})

    # Extract geo
    timezone = None
    country = None
    country_code = None
    city = None
    isp_name = ""

    if ipinfo:
        timezone = ipinfo.get("timezone")
        country_code = ipinfo.get("country")
        city = ipinfo.get("city")
        isp_name = ipinfo.get("org", "")
    if ip_api and ip_api.get("status") == "success":
        timezone = timezone or ip_api.get("timezone")
        country = ip_api.get("country")
        country_code = country_code or ip_api.get("countryCode")
        city = city or ip_api.get("city")
        isp_name = isp_name or ip_api.get("isp", "")

    # Derive locale from country
    profile = resolve_country_profile(country_code)
    locale_pair = IANA_TIMEZONE_TO_LOCALE.get(country_code or "", (None, None))
    target_locale = locale_pair[0]
    target_language = locale_pair[1]
    locale_candidates = list(profile.locales) if profile else ([target_locale] if target_locale else [])
    language_candidates = list(profile.languages) if profile else ([target_language] if target_language else [])

    # Build details
    details: list[str] = []
    if ipinfo:
        details.append(
            f"ipinfo: country={ipinfo.get('country', '?')} city={ipinfo.get('city', '?')} "
            f"tz={ipinfo.get('timezone', '?')} org={ipinfo.get('org', '?')}"
        )
    else:
        details.append("ipinfo: unavailable")

    if ip_api and ip_api.get("status") == "success":
        details.append(
            f"ip-api: proxy={ip_api.get('proxy', '?')} hosting={ip_api.get('hosting', '?')} "
            f"mobile={ip_api.get('mobile', '?')} isp={ip_api.get('isp', '?')}"
        )
    else:
        details.append("ip-api: unavailable")

    if isinstance(proxy_data, dict) and proxy_data:
        details.append(
            f"proxycheck: proxy={proxy_data.get('proxy', '?')} type={proxy_data.get('type', '?')} "
            f"risk={proxy_data.get('risk', '?')} provider={proxy_data.get('provider', '?')}"
        )
    else:
        details.append("proxycheck: unavailable")

    if isinstance(bgpview, dict) and bgpview.get("status") == "ok":
        data = bgpview.get("data", {})
        rir = data.get("rir_allocation", {})
        details.append(
            f"bgpview: prefix_count={len(data.get('prefixes', []) or [])} "
            f"rir={rir.get('rir_name', '?')}"
        )
    else:
        details.append("bgpview: unavailable")

    details.append(f"whois: country={whois_country or '?'}")

    # Classify — sub-finding granularity
    proxy_flag = str(proxy_data.get("proxy", "")).lower() == "yes" if isinstance(proxy_data, dict) else False
    ip_type = str(proxy_data.get("type", "")).lower() if isinstance(proxy_data, dict) else ""
    risk_score = int(proxy_data.get("risk", 0)) if isinstance(proxy_data, dict) else 0
    hosting = bool(ip_api.get("hosting")) if isinstance(ip_api, dict) and ip_api.get("status") == "success" else False
    api_proxy = bool(ip_api.get("proxy")) if isinstance(ip_api, dict) and ip_api.get("status") == "success" else False

    # Sub-finding 1: ip-not-proxy
    if proxy_flag or api_proxy:
        proxy_status = "fail"
        proxy_summary = f"IP is flagged as proxy/VPN (type={ip_type}, risk={risk_score})"
    else:
        proxy_status = "pass"
        proxy_summary = "IP not flagged as proxy/VPN"

    # Sub-finding 2: ip-not-hosting
    if hosting:
        hosting_status = "fail"
        hosting_summary = "IP is flagged as hosting/IDC"
    else:
        hosting_status = "pass"
        hosting_summary = "IP not flagged as hosting/IDC"

    # Sub-finding 3: ip-type-match
    if expected_ip_type == "residential":
        if ip_type in BAD_IP_TYPES:
            type_status = "fail"
            type_summary = f"IP type is '{ip_type}', not residential"
        elif ip_type in GOOD_IP_TYPES:
            type_status = "pass"
            type_summary = f"IP type '{ip_type}' matches residential"
        elif ip_type:
            type_status = "warn"
            type_summary = f"IP type '{ip_type}' not confidently residential"
        else:
            type_status = "warn"
            type_summary = "IP type could not be classified"
    else:
        type_status = "pass"
        type_summary = f"IP type check skipped (expected={expected_ip_type})"

    # Sub-finding 4: ip-risk-score
    if risk_score >= 66:
        risk_status = "warn"
        risk_summary = f"IP risk score is high ({risk_score}/100)"
    elif risk_score >= 33:
        risk_status = "warn"
        risk_summary = f"IP risk score is moderate ({risk_score}/100)"
    else:
        risk_status = "pass"
        risk_summary = f"IP risk score is low ({risk_score}/100)"

    # Sub-finding 5: ip-geo-consistent
    if country_code and whois_country and country_code != whois_country:
        geo_status = "warn"
        geo_summary = f"Geo mismatch: API country={country_code} vs whois country={whois_country}"
    else:
        geo_status = "pass"
        geo_summary = "Geo/whois country consistent"

    # ISP info (informational, appended to details)
    if isp_name and expected_ip_type == "residential":
        isp_lower = isp_name.lower()
        is_known_resi = any(resi in isp_lower for resi in US_RESIDENTIAL_ISPS)
        if not is_known_resi:
            details.append(f"isp-check: '{isp_name}' is not a known US residential ISP")

    # Combined status for backward compat
    all_statuses = [proxy_status, hosting_status, type_status, risk_status, geo_status]
    if "fail" in all_statuses:
        combined_status = "fail"
    elif "warn" in all_statuses:
        combined_status = "warn"
    else:
        combined_status = "pass"

    # Build recommendations
    recommendations: list[str] = []
    if proxy_status == "fail":
        recommendations.append(
            f"当前 IP 被标记为 {ip_type or 'proxy'}。"
            "请更换为真实住宅宽带 IP（如美国 Comcast/AT&T/Spectrum 家宽），"
            "伪住宅（IDC 隧道包装）同样会被高敏感 API 识别。"
        )
    if hosting_status == "fail":
        recommendations.append("IP 归属于 IDC/Hosting 机房，建议更换为住宅节点。")
    if type_status == "fail":
        recommendations.append("请更换为真实住宅宽带 IP，当前 IP 类型不符合要求。")
    if type_status == "warn":
        recommendations.append("建议用更多权威渠道复核 IP 类型。")
    if risk_status == "warn":
        recommendations.append(f"风险评分 {risk_score}/100 偏高，建议更换更纯净的家宽节点。")
    if geo_status == "warn":
        recommendations.append(f"geo country={country_code} vs whois country={whois_country}，建议人工复核。")

    # Build summary for combined
    if combined_status == "fail":
        combined_summary = f"IP is flagged (proxy={proxy_flag}, hosting={hosting}, type={ip_type})"
    elif combined_status == "warn":
        combined_summary = f"IP quality uncertain (type={ip_type}, risk={risk_score})"
    else:
        combined_summary = "IP quality looks acceptable"

    sub_findings = [
        {"key": "ip-not-proxy", "status": proxy_status, "summary": proxy_summary},
        {"key": "ip-not-hosting", "status": hosting_status, "summary": hosting_summary},
        {"key": "ip-type-match", "status": type_status, "summary": type_summary},
        {"key": "ip-risk-score", "status": risk_status, "summary": risk_summary},
        {"key": "ip-geo-consistent", "status": geo_status, "summary": geo_summary},
    ]

    return {
        "status": combined_status,
        "summary": combined_summary,
        "details": details + recommendations,
        "sub_findings": sub_findings,
        "target_timezone": timezone,
        "target_locale": target_locale,
        "target_language": target_language,
        "target_locale_candidates": locale_candidates,
        "target_language_candidates": language_candidates,
        "country": country,
        "country_code": country_code,
        "city": city,
        "ip_type": ip_type or None,
        "risk_score": risk_score,
        "isp": isp_name,
    }
