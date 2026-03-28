#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CC-check 单元测试 — scoring, ip_quality, platform_ops 核心逻辑。

运行: python -m pytest tests/ -v
或:   python -m unittest discover -s tests -p test_cc_check.py -v
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
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
import cc_check
import browser_leaks as bleaks
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


class TestWindowsCommandCompatibility(unittest.TestCase):
    """验证 Windows 下的外部命令执行兼容性。"""

    @patch.object(plat, "PLATFORM", "win32")
    @patch("platform_ops.subprocess.run")
    def test_get_nodejs_env_uses_native_process_invocation(self, mock_run):
        """Windows 应直接调用 node，而不是包一层 PowerShell 字符串。"""

        def side_effect(args, **kwargs):
            joined = " ".join(str(part) for part in args).lower()
            if "node" in joined and "powershell" not in joined and "pwsh" not in joined:
                return subprocess.CompletedProcess(
                    args,
                    0,
                    '{"tz":"America/Los_Angeles","locale":"en-US","time":"ok","hostname":"pc","platform":"win32"}\n',
                    "",
                )
            return subprocess.CompletedProcess(args, 1, "", "unexpected wrapper")

        mock_run.side_effect = side_effect

        info = plat.get_nodejs_env()

        self.assertEqual(info["tz"], "America/Los_Angeles")
        self.assertEqual(info["locale"], "en-US")

    @patch.object(plat, "PLATFORM", "win32")
    @patch("platform_ops.subprocess.run")
    def test_check_package_mirrors_reads_real_windows_command_output(self, mock_run):
        """Windows 下 npm/pip 检测应该读到真实命令输出。"""

        def side_effect(args, **kwargs):
            joined = " ".join(str(part) for part in args).lower()
            if "npm" in joined and "powershell" not in joined and "pwsh" not in joined:
                return subprocess.CompletedProcess(args, 0, "https://registry.npmmirror.com/\n", "")
            if any(name in joined for name in ("pip3", "python", "python3")) and "powershell" not in joined and "pwsh" not in joined:
                return subprocess.CompletedProcess(
                    args,
                    0,
                    "https://pypi.tuna.tsinghua.edu.cn/simple\n",
                    "",
                )
            return subprocess.CompletedProcess(args, 1, "", "unexpected wrapper")

        mock_run.side_effect = side_effect

        with tempfile.TemporaryDirectory() as tmpdir, patch("platform_ops.Path.home", return_value=Path(tmpdir)):
            result = plat.check_package_mirrors()

        self.assertEqual(result["npm"]["registry"], "https://registry.npmmirror.com/")
        self.assertTrue(result["npm"]["is_china_mirror"])
        self.assertEqual(result["pip"]["index"], "https://pypi.tuna.tsinghua.edu.cn/simple")
        self.assertTrue(result["pip"]["is_china_mirror"])

    def test_find_china_mirror_residue_scans_files_without_shell_tools(self):
        """镜像残留扫描应由 Python 直接完成，而不是依赖 find/grep。"""

        with tempfile.TemporaryDirectory() as tmpdir, patch("platform_ops.Path.home", return_value=Path(tmpdir)):
            npm_dir = Path(tmpdir) / ".npm" / "cache"
            npm_dir.mkdir(parents=True)
            (npm_dir / "cache.json").write_text('{"registry":"https://registry.npmmirror.com/"}', encoding="utf-8")
            (Path(tmpdir) / ".npmrc").write_text("registry=https://registry.npmjs.org/\n", encoding="utf-8")

            result = plat.find_china_mirror_residue()

        self.assertEqual(len(result), 1)
        self.assertTrue(result[0].endswith("cache.json"))


class TestFixLocalWindowsSafety(unittest.TestCase):
    """验证 Windows 下 fix-local 的关键动作能真正生效。"""

    def test_fix_local_removes_telemetry_directory_without_rm(self):
        """删除 telemetry 不应依赖 rm -rf 这类 Unix 命令。"""

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            claude_dir = root / ".claude"
            telemetry = claude_dir / "telemetry"
            telemetry.mkdir(parents=True)
            (telemetry / "event.json").write_text("{}", encoding="utf-8")

            ctx = cc_check.Context(
                skill_root=root,
                home=root,
                claude_dir=claude_dir,
                clash_dir=None,
                vpn_root=None,
                public_subscription_url=None,
                target_timezone=None,
                target_locale=None,
                target_language=None,
                proxy_url=None,
                expected_ip_type="residential",
                dry_run=False,
            )
            findings = [cc_check.Finding("privacy", "telemetry", "fail", "Claude telemetry exists")]

            with patch("cc_check.fetch_public_ip", return_value=None), patch("cc_check.build_target_profile", return_value={}):
                actions = cc_check.fix_local(ctx, findings=findings)

            self.assertFalse(telemetry.exists())
            self.assertIn("Removed Claude telemetry", actions)


class TestClashVergeDnsToggleSafety(unittest.TestCase):
    """验证 Clash Verge DNS 设置修复不会误伤工作链路。"""

    def test_runtime_with_domain_proxies_is_detected(self):
        runtime = "proxies:\n- name: test\n  server: cc.proxy.example.com\n  port: 8388\n"
        self.assertTrue(cc_check.runtime_has_domain_proxies(runtime))

    def test_runtime_with_ip_proxies_is_not_detected(self):
        runtime = "proxies:\n- name: test\n  server: 104.254.211.203\n  port: 8388\n"
        self.assertFalse(cc_check.runtime_has_domain_proxies(runtime))

    @patch.object(cc_check.plat, "PLATFORM", "darwin")
    def test_skip_dns_toggle_on_macos_when_runtime_uses_domain_proxies(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            clash_dir = Path(tmpdir)
            (clash_dir / "verge.yaml").write_text("enable_dns_settings: true\n", encoding="utf-8")
            (clash_dir / "clash-verge.yaml").write_text(
                "proxies:\n- name: test\n  server: cc.proxy.example.com\n  port: 8388\n",
                encoding="utf-8",
            )

            changed = cc_check.ensure_verge_dns_toggle(clash_dir)

            self.assertFalse(changed)
            self.assertIn("enable_dns_settings: true", (clash_dir / "verge.yaml").read_text(encoding="utf-8"))

    @patch.object(cc_check.plat, "PLATFORM", "win32")
    def test_allow_dns_toggle_when_runtime_uses_ip_proxies(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            clash_dir = Path(tmpdir)
            (clash_dir / "verge.yaml").write_text("enable_dns_settings: true\n", encoding="utf-8")
            (clash_dir / "clash-verge.yaml").write_text(
                "proxies:\n- name: test\n  server: 104.254.211.203\n  port: 8388\n",
                encoding="utf-8",
            )

            changed = cc_check.ensure_verge_dns_toggle(clash_dir)

            self.assertTrue(changed)
            self.assertIn("enable_dns_settings: false", (clash_dir / "verge.yaml").read_text(encoding="utf-8"))


class TestFixLocalRiskGates(unittest.TestCase):
    """验证高风险修复默认不会自动执行。"""

    @patch.object(cc_check.plat, "PLATFORM", "darwin")
    def test_fix_local_skips_risky_repairs_without_allow_flags(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            clash_dir = root / "clash"
            clash_dir.mkdir()
            ctx = cc_check.Context(
                skill_root=root,
                home=root,
                claude_dir=root / ".claude",
                clash_dir=clash_dir,
                vpn_root=None,
                public_subscription_url=None,
                target_timezone=None,
                target_locale=None,
                target_language=None,
                proxy_url=None,
                expected_ip_type="residential",
                dry_run=False,
            )
            findings = [
                cc_check.Finding("dns", "system-dns-display", "fail", "Suspicious DNS display"),
                cc_check.Finding("privacy", "shell-history", "warn", "Shell history contains China domains"),
                cc_check.Finding("system", "input-method", "warn", "System Chinese IME enabled"),
                cc_check.Finding("clash", "dns-cleanup-watchdog", "warn", "DNS watchdog missing"),
            ]

            with (
                patch("cc_check.fetch_public_ip", return_value=None),
                patch("cc_check.build_target_profile", return_value={}),
                patch.object(cc_check.plat, "set_static_dns") as mock_static_dns,
                patch.object(cc_check.plat, "install_dns_watchdog") as mock_watchdog,
                patch.object(cc_check.plat, "clean_shell_history") as mock_history,
                patch.object(cc_check.plat, "install_rime") as mock_rime,
                patch.object(cc_check.plat, "remove_system_chinese_ime") as mock_remove_ime,
            ):
                actions = cc_check.fix_local(ctx, findings=findings)

            mock_static_dns.assert_not_called()
            mock_watchdog.assert_not_called()
            mock_history.assert_not_called()
            mock_rime.assert_not_called()
            mock_remove_ime.assert_not_called()
            self.assertTrue(any("--allow-static-dns" in action for action in actions))
            self.assertTrue(any("--allow-dns-watchdog" in action for action in actions))
            self.assertTrue(any("--allow-shell-history-cleanup" in action for action in actions))
            self.assertTrue(any("--allow-rime-install" in action for action in actions))
            self.assertTrue(any("--allow-ime-removal" in action for action in actions))

    @patch.object(cc_check.plat, "PLATFORM", "darwin")
    def test_fix_local_executes_allowed_risky_repairs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            clash_dir = root / "clash"
            clash_dir.mkdir()
            ctx = cc_check.Context(
                skill_root=root,
                home=root,
                claude_dir=root / ".claude",
                clash_dir=clash_dir,
                vpn_root=None,
                public_subscription_url=None,
                target_timezone=None,
                target_locale=None,
                target_language=None,
                proxy_url=None,
                expected_ip_type="residential",
                dry_run=False,
                allow_static_dns=True,
                allow_dns_watchdog=True,
                allow_shell_history_cleanup=True,
                allow_rime_install=True,
                allow_ime_removal=True,
            )
            findings = [
                cc_check.Finding("dns", "system-dns-display", "fail", "Suspicious DNS display"),
                cc_check.Finding("privacy", "shell-history", "warn", "Shell history contains China domains"),
                cc_check.Finding("system", "input-method", "warn", "System Chinese IME enabled"),
                cc_check.Finding("clash", "dns-cleanup-watchdog", "warn", "DNS watchdog missing"),
            ]

            with (
                patch("cc_check.fetch_public_ip", return_value=None),
                patch("cc_check.build_target_profile", return_value={}),
                patch.object(cc_check.plat, "set_static_dns", return_value=["Locked static DNS"]) as mock_static_dns,
                patch.object(cc_check.plat, "install_dns_watchdog", return_value=["Installed DNS watchdog"]) as mock_watchdog,
                patch.object(cc_check.plat, "clean_shell_history", return_value={"/tmp/.zsh_history": 2}) as mock_history,
                patch.object(cc_check.plat, "install_rime", return_value=["Installed RIME"]) as mock_rime,
                patch.object(cc_check.plat, "remove_system_chinese_ime", return_value=["Removed system Chinese IME"]) as mock_remove_ime,
            ):
                actions = cc_check.fix_local(ctx, findings=findings)

            mock_static_dns.assert_called_once_with()
            mock_watchdog.assert_called_once_with(clash_dir)
            mock_history.assert_called_once_with(dry_run=False)
            mock_rime.assert_called_once_with(dry_run=False)
            mock_remove_ime.assert_called_once_with(dry_run=False)
            self.assertIn("Locked static DNS", actions)
            self.assertIn("Installed DNS watchdog", actions)
            self.assertIn("Removed 2 China-domain lines from /tmp/.zsh_history (backup: /tmp/.zsh_history.bak)", actions)
            self.assertIn("Installed RIME", actions)
            self.assertIn("Removed system Chinese IME", actions)


class TestShellHistoryCleanupPrecision(unittest.TestCase):
    """验证 shell history 清理只删明确命中的高风险行。"""

    @patch.object(plat, "PLATFORM", "darwin")
    def test_clean_shell_history_keeps_generic_vendor_words(self):
        with tempfile.TemporaryDirectory() as tmpdir, patch("platform_ops.Path.home", return_value=Path(tmpdir)):
            history = Path(tmpdir) / ".bash_history"
            history.write_text(
                "open -a WeChat\n"
                "curl https://www.jd.com/\n"
                "npm config set registry https://registry.npmmirror.com/\n",
                encoding="utf-8",
            )

            removed = plat.clean_shell_history(dry_run=False)

            self.assertEqual(removed, {str(history): 1})
            cleaned = history.read_text(encoding="utf-8")
            self.assertIn("WeChat", cleaned)
            self.assertIn("jd.com", cleaned)
            self.assertNotIn("npmmirror.com", cleaned)
            self.assertTrue(Path(f"{history}.bak").exists())


class TestWindowsDnsWatchdog(unittest.TestCase):
    """验证 Windows DNS watchdog 任务按最高权限创建。"""

    @patch.object(plat, "PLATFORM", "win32")
    def test_install_dns_watchdog_uses_highest_privilege(self):
        commands: list[str] = []

        def fake_run_shell(cmd: str, **_: object) -> subprocess.CompletedProcess:
            commands.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with tempfile.TemporaryDirectory() as tmpdir, patch.object(plat, "run_shell", side_effect=fake_run_shell):
            actions = plat.install_dns_watchdog(Path(tmpdir))

        create_cmds = [cmd for cmd in commands if "schtasks /Create" in cmd]
        self.assertEqual(len(create_cmds), 2)
        self.assertTrue(all("/RL HIGHEST" in cmd for cmd in create_cmds))
        self.assertTrue(any("highest privilege" in action.lower() for action in actions))


class TestBrowserLeaksReporting(unittest.TestCase):
    """验证 browser-leaks 报告会同时带出自动项和手工清单。"""

    def test_build_report_payload_includes_manual_checklist(self):
        findings = [
            bleaks.BrowserFinding("ip", "multi-endpoint-consistency", "pass", "All endpoints match"),
        ]

        payload = bleaks.build_report_payload(findings)

        self.assertEqual(payload["mode"], "python-baseline-plus-manual-checklist")
        self.assertEqual(len(payload["automated"]), 1)
        self.assertEqual(payload["automated"][0]["key"], "multi-endpoint-consistency")
        self.assertEqual(len(payload["manual"]), len(bleaks.BROWSER_TESTS))
        self.assertTrue(payload["manual"][0]["url"].startswith("https://browserleaks.com/"))


class TestExtendedInspectHelpers(unittest.TestCase):
    """验证新增扩展检查的基础回归。"""

    def test_scan_git_remotes_finds_gitee(self):
        with tempfile.TemporaryDirectory() as tmpdir, patch("platform_ops.Path.home", return_value=Path(tmpdir)):
            repo = Path(tmpdir) / "Projects" / "demo" / ".git"
            repo.mkdir(parents=True)
            output = "origin\thttps://gitee.com/example/demo.git (fetch)\n"

            with patch.object(plat, "run_shell", return_value=subprocess.CompletedProcess("git", 0, output, "")):
                hits = plat.scan_git_remotes()

        self.assertEqual(hits, ["demo: https://gitee.com/example/demo.git"])

    @patch.object(plat, "PLATFORM", "linux")
    def test_check_vscode_locale_reads_jsonc(self):
        with tempfile.TemporaryDirectory() as tmpdir, patch("platform_ops.Path.home", return_value=Path(tmpdir)):
            config_dir = Path(tmpdir) / ".config" / "Code" / "User"
            config_dir.mkdir(parents=True)
            (config_dir / "settings.json").write_text(
                '// comment\n{"locale": "zh-CN"}\n',
                encoding="utf-8",
            )

            result = plat.check_vscode_locale()

        self.assertTrue(result["found"])
        self.assertEqual(result["locale"], "zh-CN")
        self.assertTrue(result["china"])

    def test_scan_ssh_known_hosts_flags_china_domain_only(self):
        with tempfile.TemporaryDirectory() as tmpdir, patch("platform_ops.Path.home", return_value=Path(tmpdir)):
            ssh_dir = Path(tmpdir) / ".ssh"
            ssh_dir.mkdir()
            (ssh_dir / "known_hosts").write_text(
                "git.aliyun.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n"
                "8.8.8.8 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIgoogle\n",
                encoding="utf-8",
            )

            hits = plat.scan_ssh_known_hosts()

        self.assertEqual(hits, ["git.aliyun.com"])


if __name__ == "__main__":
    unittest.main()
