#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Browser support tests for scoring and bootstrap diagnostics."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import browser_bootstrap as bboot
import browser_artifacts as barts
import browser_leaks as bleaks
import browser_scoring as bscore


class TestBrowserScoring(unittest.TestCase):
    """验证浏览器自动化评分行为。"""

    def test_browser_score_weights_sum_to_100(self):
        self.assertEqual(sum(bscore.WEIGHTS.values()), 100)

    def test_compute_browser_score_mixed_statuses(self):
        findings = [
            bleaks.BrowserFinding("webrtc", "webrtc-leak", "pass", "ok"),
            bleaks.BrowserFinding("javascript", "js-locale", "warn", "warn"),
            bleaks.BrowserFinding("webgl", "webgl-renderer", "fail", "bad"),
        ]

        report = bscore.compute_browser_score(findings)

        self.assertEqual(report.max_score, 32)
        self.assertEqual(report.total_score, 22)
        self.assertEqual(report.grade, "D")

    def test_compute_browser_score_marks_blockers(self):
        findings = [
            bleaks.BrowserFinding("webrtc", "webrtc-leak", "fail", "unexpected public candidate"),
            bleaks.BrowserFinding("ip", "browser-python-egress-alignment", "pass", "aligned"),
        ]

        report = bscore.compute_browser_score(findings)

        self.assertTrue(report.blocked)
        self.assertEqual(report.blocker_reasons, ["webrtc-leak: unexpected public candidate"])

    def test_payload_includes_browser_score_when_automation_used(self):
        findings = [
            bleaks.BrowserFinding("webrtc", "webrtc-leak", "pass", "ok"),
            bleaks.BrowserFinding("ip", "browser-python-egress-alignment", "pass", "aligned"),
        ]
        meta = {
            "mode": "playwright-automation-plus-python-baseline",
            "automation_supported": True,
            "automation_used": True,
            "provider": "playwright",
            "executed_tests": ["webrtc"],
            "browser_score": bscore.build_browser_score_payload(bscore.compute_browser_score(findings)),
        }

        payload = bleaks.build_report_payload(findings, meta)

        self.assertIsNotNone(payload["browser_score"])
        self.assertEqual(payload["browser_score"]["max_score"], 28)
        self.assertIn("blocked", payload["browser_score"])

    def test_build_browser_recommendations_from_findings(self):
        findings = [
            bleaks.BrowserFinding("webrtc", "webrtc-leak", "fail", "bad"),
            bleaks.BrowserFinding("fonts", "china-fonts", "warn", "fonts"),
            bleaks.BrowserFinding("ip", "browser-python-egress-alignment", "fail", "mismatch"),
        ]

        recommendations = bleaks.build_browser_recommendations(findings, {
            "automation_used": True,
            "reason": "",
        })

        keys = [item["key"] for item in recommendations]
        self.assertEqual(keys, ["webrtc-leak", "browser-python-egress-alignment", "china-fonts"])

    def test_build_browser_recommendations_bootstrap_hint_when_automation_unavailable(self):
        recommendations = bleaks.build_browser_recommendations([], {
            "automation_used": False,
            "reason": "playwright package not found in current Node environment; run browser_bootstrap.py install to prepare local Playwright",
        })

        self.assertEqual(recommendations[0]["key"], "automation-bootstrap")

    def test_refine_webrtc_findings_downgrades_proxy_only_candidate(self):
        findings = [
            bleaks.BrowserFinding("webrtc", "webrtc-leak", "fail", "raw"),
            bleaks.BrowserFinding("webrtc", "webrtc-local-ip", "pass", "ok"),
        ]

        refined = bleaks.refine_webrtc_findings(
            findings,
            {"publicCandidates": ["104.254.211.203"]},
            {"endpoints": {"ipify": "104.254.211.203"}},
        )

        self.assertEqual(refined[0].status, "warn")
        self.assertIn("proxy egress candidate", refined[0].summary)

    def test_refine_webrtc_findings_ignores_zero_placeholder(self):
        findings = [
            bleaks.BrowserFinding("webrtc", "webrtc-leak", "pass", "raw"),
            bleaks.BrowserFinding("webrtc", "webrtc-local-ip", "pass", "ok"),
        ]

        refined = bleaks.refine_webrtc_findings(
            findings,
            {"publicCandidates": ["0.0.0.0"]},
            {"endpoints": {"ipify": "104.247.120.78"}},
        )

        self.assertEqual(refined[0].status, "pass")


class TestBrowserBootstrapStatus(unittest.TestCase):
    """验证本地 Playwright 引导状态输出。"""

    def test_build_status_payload_reports_missing_tools(self):
        with tempfile.TemporaryDirectory() as tmpdir, patch("browser_bootstrap.collect_tool_status", return_value={"node": "", "npm": "", "npx": ""}):
            payload = bboot.build_status_payload(Path(tmpdir))

        self.assertFalse(payload["installed"])
        self.assertEqual(payload["missing_tools"], ["node", "npm", "npx"])
        self.assertTrue(any("missing tools" in item for item in payload["recommendations"]))

    def test_build_status_payload_exposes_proxy_env(self):
        with tempfile.TemporaryDirectory() as tmpdir, patch.dict(os.environ, {"HTTPS_PROXY": "http://127.0.0.1:7897"}, clear=False):
            payload = bboot.build_status_payload(Path(tmpdir))

        self.assertEqual(payload["proxy_env"]["HTTPS_PROXY"], "http://127.0.0.1:7897")
        self.assertEqual(len(payload["install_commands"]), 2)


class TestBrowserArtifacts(unittest.TestCase):
    """验证浏览器证据文件保存。"""

    def test_save_browser_artifact_writes_json_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = barts.save_browser_artifact(
                {"mode": "test"},
                {"ip": {"endpoints": {"ipify": "1.1.1.1"}}},
                Path(tmpdir),
            )

            saved = Path(path)
            self.assertTrue(saved.exists())
            payload = json.loads(saved.read_text(encoding="utf-8"))
            self.assertEqual(payload["payload"]["mode"], "test")
            self.assertEqual(payload["raw_results"]["ip"]["endpoints"]["ipify"], "1.1.1.1")


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

    def test_build_report_payload_with_playwright_metadata(self):
        findings = [
            bleaks.BrowserFinding("javascript", "js-locale", "pass", "Browser locale: en-US"),
        ]
        meta = {
            "mode": "playwright-automation-plus-python-baseline",
            "automation_supported": True,
            "automation_used": True,
            "provider": "playwright",
            "executed_tests": ["javascript", "webrtc"],
        }

        payload = bleaks.build_report_payload(findings, meta)

        self.assertEqual(payload["mode"], "playwright-automation-plus-python-baseline")
        self.assertTrue(payload["automation_supported"])
        self.assertTrue(payload["automation_used"])
        self.assertEqual(payload["provider"], "playwright")
        self.assertEqual(payload["executed_tests"], ["javascript", "webrtc"])
        self.assertEqual([item["test"] for item in payload["manual"]], ["ip", "fonts", "canvas", "webgl", "tls"])

    def test_build_report_payload_removes_canvas_and_tls_when_automated(self):
        findings = [
            bleaks.BrowserFinding("canvas", "canvas-fingerprint", "pass", "Canvas fingerprint collected"),
            bleaks.BrowserFinding("tls", "tls-browser-version", "pass", "Browser TLS page reports TLS 1.3"),
        ]
        meta = {
            "mode": "playwright-automation-plus-python-baseline",
            "automation_supported": True,
            "automation_used": True,
            "provider": "playwright",
            "executed_tests": ["javascript", "webrtc", "canvas", "tls"],
        }

        payload = bleaks.build_report_payload(findings, meta)

        self.assertEqual([item["test"] for item in payload["manual"]], ["ip", "fonts", "webgl"])

    def test_analyze_canvas_reports_fingerprint_and_stability(self):
        findings = bleaks.analyze_canvas({
            "fingerprintHash": "abc123",
            "secondaryHash": "abc123",
            "dataUrlsMatch": True,
        })

        self.assertEqual([item.key for item in findings], ["canvas-fingerprint", "canvas-fingerprint-stability"])
        self.assertTrue(all(item.status == "pass" for item in findings))

    def test_analyze_tls_page_flags_legacy_protocols(self):
        findings = bleaks.analyze_tls_page({
            "text": "TLS 1.3 Enabled\nTLS 1.0 Enabled\nTLS 1.1 Disabled",
        })

        self.assertEqual(findings[0].key, "tls-browser-version")
        self.assertEqual(findings[0].status, "pass")
        self.assertEqual(findings[1].key, "tls-browser-legacy")
        self.assertEqual(findings[1].status, "fail")

    def test_analyze_webgl_flags_software_renderer(self):
        findings = bleaks.analyze_webgl({
            "vendor": "Google Inc. (Google)",
            "renderer": "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero)))",
        })

        self.assertEqual(findings[0].key, "webgl-vendor")
        self.assertEqual(findings[0].status, "warn")
        self.assertEqual(findings[1].key, "webgl-renderer")
        self.assertEqual(findings[1].status, "fail")

    def test_compare_browser_and_python_egress_detects_mismatch(self):
        python_findings = [
            bleaks.BrowserFinding(
                "ip",
                "multi-endpoint-consistency",
                "pass",
                "All 4 endpoints return same IP: 1.1.1.1",
                ["ipify: 1.1.1.1"],
            ),
        ]

        finding = bleaks.compare_browser_and_python_egress(python_findings, {
            "endpoints": {"ipify": "2.2.2.2", "httpbin": "2.2.2.2"},
        })

        self.assertIsNotNone(finding)
        self.assertEqual(finding.key, "browser-python-egress-alignment")
        self.assertEqual(finding.status, "fail")

    def test_analyze_webrtc_ignores_zero_ip_placeholder(self):
        findings = bleaks.analyze_webrtc({
            "supported": True,
            "localCandidates": [],
            "publicCandidates": ["104.254.211.203", "0.0.0.0"],
        })

        self.assertEqual(findings[0].status, "fail")
        self.assertNotIn("0.0.0.0", findings[0].summary)
        self.assertNotIn("0.0.0.0", findings[0].details)

    @patch.object(bleaks, "run_python_checks")
    @patch.object(bleaks, "detect_playwright_automation")
    def test_run_browser_checks_falls_back_when_playwright_unavailable(self, mock_detect, mock_python):
        mock_detect.return_value = {
            "available": False,
            "provider": "playwright",
            "reason": "playwright package not found",
        }
        mock_python.return_value = [
            bleaks.BrowserFinding("ip", "multi-endpoint-consistency", "pass", "All endpoints match"),
        ]

        findings, meta = bleaks.run_browser_checks()

        self.assertEqual(len(findings), 1)
        self.assertEqual(meta["mode"], "python-baseline-plus-manual-checklist")
        self.assertFalse(meta["automation_supported"])
        self.assertFalse(meta["automation_used"])
        self.assertEqual(meta["provider"], "playwright")
        self.assertEqual(meta["executed_tests"], [])

    @patch.object(bleaks, "run_playwright_automation")
    @patch.object(bleaks, "run_python_checks")
    @patch.object(bleaks, "detect_playwright_automation")
    def test_run_browser_checks_uses_playwright_when_available(self, mock_detect, mock_python, mock_playwright):
        mock_detect.return_value = {
            "available": True,
            "provider": "playwright",
            "reason": "",
        }
        mock_python.return_value = [
            bleaks.BrowserFinding("ip", "multi-endpoint-consistency", "pass", "All endpoints match"),
        ]
        mock_playwright.return_value = {
            "findings": [
                bleaks.BrowserFinding("javascript", "js-locale", "pass", "Browser locale: en-US"),
            ],
            "executed_tests": ["javascript"],
            "errors": [],
            "results": {},
        }

        findings, meta = bleaks.run_browser_checks()

        self.assertEqual(len(findings), 2)
        self.assertEqual(meta["mode"], "playwright-automation-plus-python-baseline")
        self.assertTrue(meta["automation_supported"])
        self.assertTrue(meta["automation_used"])
        self.assertEqual(meta["executed_tests"], ["javascript"])


if __name__ == "__main__":
    unittest.main()
