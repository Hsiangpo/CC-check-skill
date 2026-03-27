#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CC-check 单元测试 — scoring, ip_quality, platform_ops 核心逻辑。

运行: python3 -m pytest tests/ -v
或:   python3 -m unittest tests/test_cc_check.py -v
"""

from __future__ import annotations

import os
import sys
import unittest
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import patch, MagicMock

# Ensure scripts/ is importable
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from scoring import WEIGHTS, compute_score, format_score_report, _grade
from ip_quality import (
    GOOD_IP_TYPES, BAD_IP_TYPES, US_RESIDENTIAL_ISPS,
    IANA_TIMEZONE_TO_LOCALE, parse_whois_country,
)
import platform_ops as plat


# ---------------------------------------------------------------------------
# Helper: mock Finding
# ---------------------------------------------------------------------------

@dataclass
class MockFinding:
    group: str
    key: str
    status: str
    summary: str = ""
    details: list[str] = field(default_factory=list)


# ===========================================================================
# scoring.py tests
# ===========================================================================

class TestScoringWeights(unittest.TestCase):
    """Verify weight configuration integrity."""

    def test_total_weight_is_100(self):
        """All non-zero weights must sum to exactly 100."""
        total = sum(
            w for group in WEIGHTS.values() for w in group.values()
        )
        self.assertEqual(total, 100, f"Total weights = {total}, expected 100")

    def test_ip_quality_weight_is_30(self):
        """IP quality must be the heaviest group at 30."""
        ip_weight = sum(WEIGHTS["ip-quality"].values())
        self.assertEqual(ip_weight, 30)

    def test_vpn_group_has_zero_weight(self):
        """VPN group items should not contribute to scoring."""
        vpn_weights = WEIGHTS.get("vpn", {})
        self.assertTrue(all(v == 0 for v in vpn_weights.values()),
                        f"VPN weights should all be 0, got {vpn_weights}")

    def test_all_groups_present(self):
        """All expected groups must exist in WEIGHTS."""
        expected = {"ip-quality", "dns", "system", "network", "clash",
                    "packages", "privacy", "nodejs", "vpn", "identity", "claude"}
        self.assertEqual(set(WEIGHTS.keys()), expected)


class TestComputeScore(unittest.TestCase):
    """Verify scoring calculation logic."""

    def test_all_pass_yields_100(self):
        """All passing findings should yield 100/100."""
        findings = []
        for group, keys in WEIGHTS.items():
            for key, weight in keys.items():
                if weight > 0:
                    findings.append(MockFinding(group, key, "pass"))
        report = compute_score(findings)
        self.assertEqual(report.total_score, 100)
        self.assertEqual(report.max_score, 100)
        self.assertEqual(report.grade, "A+")

    def test_all_fail_yields_0(self):
        """All failing findings should yield 0/100."""
        findings = []
        for group, keys in WEIGHTS.items():
            for key, weight in keys.items():
                if weight > 0:
                    findings.append(MockFinding(group, key, "fail"))
        report = compute_score(findings)
        self.assertEqual(report.total_score, 0)
        self.assertEqual(report.grade, "F")

    def test_warn_gives_70_percent(self):
        """A single warn on a 30-point item should give 21 points."""
        findings = [MockFinding("ip-quality", "classification", "warn")]
        report = compute_score(findings)
        self.assertEqual(report.total_score, 21)

    def test_skip_gives_50_percent(self):
        """Two skipped 1-point items should give 1 point total (2*0.5=1)."""
        findings = [
            MockFinding("nodejs", "node-tz", "skip"),
            MockFinding("nodejs", "node-locale", "skip"),
        ]
        report = compute_score(findings)
        self.assertEqual(report.total_score, 1)

    def test_zero_weight_items_ignored(self):
        """VPN items (weight=0) should not affect score."""
        findings = [
            MockFinding("vpn", "project-root", "fail"),
            MockFinding("vpn", "unit-tests", "fail"),
        ]
        report = compute_score(findings)
        self.assertEqual(report.total_score, 0)
        self.assertEqual(len(report.groups), 0)  # No groups with non-zero weight

    def test_mixed_statuses(self):
        """Mixed pass/warn/fail should compute correctly."""
        findings = [
            MockFinding("ip-quality", "classification", "pass"),  # 30
            MockFinding("dns", "dns-google", "warn"),             # 7 * 0.7 = 4.9
            MockFinding("dns", "dns-cloudflare", "fail"),         # 0
        ]
        report = compute_score(findings)
        self.assertEqual(report.total_score, 35)  # 30 + 4.9 → round(34.9) = 35


class TestGrade(unittest.TestCase):
    """Verify grade boundaries."""

    def test_grade_boundaries(self):
        self.assertEqual(_grade(100), "A+")
        self.assertEqual(_grade(95), "A+")
        self.assertEqual(_grade(94.9), "A")
        self.assertEqual(_grade(90), "A")
        self.assertEqual(_grade(89.9), "B")
        self.assertEqual(_grade(80), "B")
        self.assertEqual(_grade(79.9), "C")
        self.assertEqual(_grade(70), "C")
        self.assertEqual(_grade(69.9), "D")
        self.assertEqual(_grade(60), "D")
        self.assertEqual(_grade(59.9), "F")
        self.assertEqual(_grade(0), "F")


class TestFormatScoreReport(unittest.TestCase):
    """Verify report formatting."""

    def test_report_contains_score(self):
        findings = [MockFinding("ip-quality", "classification", "pass")]
        report = compute_score(findings)
        text = format_score_report(report)
        self.assertIn("CC-Check Score:", text)
        self.assertIn("30", text)  # earned
        self.assertIn("100", text)  # max

    def test_report_contains_bars(self):
        findings = [MockFinding("dns", "dns-google", "pass")]
        report = compute_score(findings)
        text = format_score_report(report)
        self.assertIn("█", text)


# ===========================================================================
# ip_quality.py tests
# ===========================================================================

class TestIPQualityConstants(unittest.TestCase):
    """Verify IP quality classification constants."""

    def test_good_and_bad_types_do_not_overlap(self):
        overlap = GOOD_IP_TYPES & BAD_IP_TYPES
        self.assertEqual(overlap, set(), f"Overlap: {overlap}")

    def test_residential_in_good_types(self):
        self.assertIn("residential", GOOD_IP_TYPES)
        self.assertIn("mobile", GOOD_IP_TYPES)

    def test_hosting_vpn_in_bad_types(self):
        self.assertIn("hosting", BAD_IP_TYPES)
        self.assertIn("vpn", BAD_IP_TYPES)
        self.assertIn("proxy", BAD_IP_TYPES)

    def test_us_residential_isps_not_empty(self):
        self.assertGreater(len(US_RESIDENTIAL_ISPS), 10)
        self.assertIn("comcast", US_RESIDENTIAL_ISPS)
        self.assertIn("verizon", US_RESIDENTIAL_ISPS)


class TestWhoisParser(unittest.TestCase):
    """Verify whois country parsing."""

    def test_parse_whois_country_normal(self):
        text = "NetRange:  1.0.0.0\nCountry:  US\nOrgName: Example"
        self.assertEqual(parse_whois_country(text), "US")

    def test_parse_whois_country_lowercase(self):
        text = "country:        DE"
        self.assertEqual(parse_whois_country(text), "DE")

    def test_parse_whois_country_empty(self):
        self.assertIsNone(parse_whois_country(""))
        self.assertIsNone(parse_whois_country("OrgName: Test\nNetRange: 1.0.0.0"))

    def test_parse_whois_country_first_match(self):
        text = "Country:  US\nCountry:  EU"
        self.assertEqual(parse_whois_country(text), "US")


class TestIANAMapping(unittest.TestCase):
    """Verify timezone→locale mapping."""

    def test_us_mapping(self):
        locale, lang = IANA_TIMEZONE_TO_LOCALE["US"]
        self.assertEqual(locale, "en_US.UTF-8")
        self.assertEqual(lang, "en_US")

    def test_jp_mapping(self):
        locale, lang = IANA_TIMEZONE_TO_LOCALE["JP"]
        self.assertEqual(locale, "ja_JP.UTF-8")

    def test_unknown_country_returns_none(self):
        result = IANA_TIMEZONE_TO_LOCALE.get("XX", (None, None))
        self.assertEqual(result, (None, None))


# ===========================================================================
# platform_ops.py tests
# ===========================================================================

class TestPlatformConstants(unittest.TestCase):
    """Verify platform detection and constants."""

    def test_platform_is_known(self):
        self.assertIn(plat.PLATFORM, ("darwin", "linux", "win32"))

    def test_suspicious_dns_set(self):
        self.assertIn("114.114.114.114", plat.SUSPICIOUS_DNS)
        self.assertIn("223.5.5.5", plat.SUSPICIOUS_DNS)
        self.assertIn("223.6.6.6", plat.SUSPICIOUS_DNS)
        self.assertIn("119.29.29.29", plat.SUSPICIOUS_DNS)

    def test_china_mirror_keywords(self):
        self.assertIn("taobao", plat.CHINA_MIRROR_KEYWORDS)
        self.assertIn("npmmirror", plat.CHINA_MIRROR_KEYWORDS)
        self.assertIn("tencent", plat.CHINA_MIRROR_KEYWORDS)


class TestLocaleInfo(unittest.TestCase):
    """Verify locale info retrieval."""

    def test_locale_info_returns_dataclass(self):
        info = plat.get_locale_info()
        self.assertIsInstance(info, plat.LocaleInfo)
        # LANG should come from environment
        self.assertEqual(info.lang, os.environ.get("LANG", ""))


class TestHostnameInfo(unittest.TestCase):
    """Verify hostname retrieval."""

    def test_hostname_not_empty(self):
        info = plat.get_hostname_info()
        self.assertIn("hostname", info)
        self.assertTrue(len(info["hostname"]) > 0)


class TestUserInfo(unittest.TestCase):
    """Verify user info retrieval."""

    def test_username_present(self):
        info = plat.get_user_info()
        self.assertIn("username", info)
        self.assertTrue(len(info["username"]) > 0)


class TestHostsFile(unittest.TestCase):
    """Verify hosts file check."""

    def test_hosts_check_returns_list(self):
        result = plat.check_hosts_file()
        self.assertIsInstance(result, list)


class TestShellProfilePaths(unittest.TestCase):
    """Verify shell profile path detection."""

    def test_returns_list_of_paths(self):
        paths = plat.get_shell_profile_paths()
        self.assertIsInstance(paths, list)
        if plat.PLATFORM != "win32":
            self.assertGreater(len(paths), 0)
            for p in paths:
                self.assertIsInstance(p, Path)


class TestChinaDomainKeywords(unittest.TestCase):
    """Verify shell history scan keywords."""

    def test_scan_returns_dict(self):
        result = plat.scan_shell_history()
        self.assertIsInstance(result, dict)


class TestFingerprintBrowserDetection(unittest.TestCase):
    """Verify fingerprint browser detection."""

    def test_returns_list(self):
        result = plat.detect_fingerprint_browsers()
        self.assertIsInstance(result, list)


class TestBuildMacOSScript(unittest.TestCase):
    """Verify macOS cleanup script generation."""

    def test_script_contains_suspicious_dns(self):
        script = plat._build_macos_cleanup_script()
        self.assertIn("114.114.114.114", script)
        self.assertIn("223.5.5.5", script)
        self.assertIn("networksetup", script)


class TestBuildLinuxScript(unittest.TestCase):
    """Verify Linux cleanup script generation."""

    def test_script_contains_suspicious_dns(self):
        script = plat._build_linux_cleanup_script()
        self.assertIn("114.114.114.114", script)
        self.assertIn("resolvectl", script)
        self.assertIn("#!/bin/bash", script)


if __name__ == "__main__":
    unittest.main()
