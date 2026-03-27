#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VPN 项目适配层。"""

from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

try:
    import paramiko  # type: ignore[import-untyped]
except Exception:
    paramiko = None


GENERIC_PUBLIC_MARKERS = [
    "dns-hijack",
    "respect-rules: true",
    "proxy-server-nameserver",
]


def load_module(path: Path, name: str, extra: Path | None = None) -> Any | None:
    """动态加载模块。"""
    if not path.exists():
        return None
    if extra is not None:
        sys.path.insert(0, str(extra))
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception:
        return None
    finally:
        if extra is not None and sys.path and sys.path[0] == str(extra):
            sys.path.pop(0)


def detect_root(explicit: str | None) -> Path | None:
    """检测可能的 VPN 项目根目录。"""
    candidates: list[Path] = []
    if explicit:
        path = Path(explicit).expanduser()
        return path if path.exists() else None
    env_path = os.environ.get("CC_CHECK_VPN_PROJECT_ROOT")
    if env_path:
        path = Path(env_path).expanduser()
        if path.exists():
            candidates.append(path)
    home = Path.home()
    candidates.extend([home / "Develop", home / "Projects", home / "Code", home])
    for base in candidates:
        if base.is_file():
            continue
        for pattern in ("**/scripts/subscription_builder.py", "**/scripts/deploy_6node_subscription.py"):
            try:
                for match in base.glob(pattern):
                    if ".git" not in match.parts:
                        return match.parents[1]
            except Exception:
                continue
    return None


def adapter_name(vpn_root: Path | None) -> str | None:
    """返回匹配到的适配器名。"""
    if vpn_root is None:
        return None
    if (vpn_root / "scripts" / "subscription_builder.py").exists():
        return "subscription-builder"
    return None


def detect_public_subscription_url(vpn_root: Path | None, explicit: str | None) -> str | None:
    """检测公开订阅 URL。"""
    if explicit:
        return explicit
    if vpn_root is None:
        return None
    builder = load_module(vpn_root / "scripts" / "subscription_builder.py", "cc_check_builder", vpn_root / "scripts")
    if builder is not None:
        try:
            state = builder.build_state()
            url = state.get("subscription_url")
            if url:
                return str(url)
        except Exception:
            pass
    for candidate in (
        vpn_root / "docs/output/us_config.json",
        vpn_root / "docs/output/us_sub_url.txt",
        vpn_root / "README.MD",
        vpn_root / "README.md",
    ):
        if not candidate.exists():
            continue
        text = candidate.read_text(encoding="utf-8", errors="ignore")
        match = re.search(r"https?://[^\s\"']+/[^\s\"']*clash-meta\.ya?ml", text)
        if match:
            return match.group(0)
    return None


def inspect(
    vpn_root: Path | None,
    public_subscription_url: str | None,
    run_shell: Any,
    fetch_text_url: Any,
) -> list[dict[str, Any]]:
    """检查 VPN 项目和远端状态。"""
    findings: list[dict[str, Any]] = []

    if vpn_root is None:
        findings.append({"key": "project-root", "status": "skip", "summary": "VPN project root was not detected", "details": []})
    else:
        adapter = adapter_name(vpn_root)
        if adapter is None:
            findings.append({"key": "project-root", "status": "skip", "summary": f"VPN project found at {vpn_root.name} but no supported adapter matched", "details": []})
        else:
            findings.append({"key": "project-root", "status": "pass", "summary": f"VPN project root detected at {vpn_root.name}", "details": [f"adapter={adapter}"]})

    if vpn_root is not None and adapter_name(vpn_root) is not None:
        test_result = subprocess.run(
            [sys.executable, "-m", "unittest", "tests/test_subscription_builder.py"],
            capture_output=True, text=True, timeout=120, check=False, cwd=vpn_root,
        )
        findings.append(
            {
                "key": "unit-tests",
                "status": "pass" if test_result.returncode == 0 else "fail",
                "summary": "VPN project unit tests passed" if test_result.returncode == 0 else "VPN project unit tests failed",
                "details": [],
            }
        )

        generated_file = vpn_root / "docs/output/clash-meta.yaml"
        generated_text = generated_file.read_text(encoding="utf-8", errors="ignore") if generated_file.exists() else ""
        missing = [marker for marker in GENERIC_PUBLIC_MARKERS if marker not in generated_text]
        findings.append(
            {
                "key": "generated-subscription",
                "status": "pass" if generated_text and not missing else "fail",
                "summary": "Generated subscription contains hardened markers" if generated_text and not missing else f"Generated subscription is missing markers: {', '.join(missing) if missing else 'file missing'}",
                "details": [],
            }
        )
    else:
        findings.append({"key": "unit-tests", "status": "skip", "summary": "VPN project unit tests unavailable without a supported local adapter", "details": []})
        findings.append({"key": "generated-subscription", "status": "skip", "summary": "Generated subscription unavailable without a supported local adapter", "details": []})

    if public_subscription_url:
        public_text = fetch_text_url(public_subscription_url, timeout=12, retries=2)
        if public_text is None:
            findings.append({"key": "public-subscription", "status": "warn", "summary": "Cannot fetch public subscription right now; retry later", "details": []})
        else:
            public_missing = [marker for marker in GENERIC_PUBLIC_MARKERS if marker not in public_text]
            findings.append(
                {
                    "key": "public-subscription",
                    "status": "pass" if not public_missing else "fail",
                    "summary": "Public subscription contains hardened markers" if not public_missing else f"Public subscription is missing markers: {', '.join(public_missing)}",
                    "details": [],
                }
            )
    else:
        findings.append({"key": "public-subscription", "status": "skip", "summary": "Public subscription URL is not configured", "details": []})

    if vpn_root is not None and adapter_name(vpn_root) is not None:
        findings.extend(inspect_remote(vpn_root))
    else:
        findings.append({"key": "remote-service", "status": "skip", "summary": "Remote service checks unavailable without a supported local adapter", "details": []})
        findings.append({"key": "remote-listener", "status": "skip", "summary": "Remote listener checks unavailable without a supported local adapter", "details": []})
    return findings


def inspect_remote(vpn_root: Path) -> list[dict[str, Any]]:
    """检查远端服务状态。"""
    if paramiko is None:
        return [{"key": "remote-service", "status": "skip", "summary": "paramiko is unavailable", "details": []}]

    builder = load_module(vpn_root / "scripts" / "subscription_builder.py", "cc_check_builder_remote", vpn_root / "scripts")
    deployer = load_module(vpn_root / "scripts" / "deploy_6node_subscription.py", "cc_check_deployer_remote", vpn_root / "scripts")
    if builder is None or deployer is None or not hasattr(deployer, "REMOTE"):
        return [{"key": "remote-service", "status": "skip", "summary": "VPN remote adapter metadata is unavailable", "details": []}]

    remote = deployer.REMOTE
    host = remote.get("host")
    port = int(remote.get("ssh_port", 22))
    user = remote.get("ssh_user")
    password = remote.get("ssh_password")
    if not all([host, user, password]):
        return [{"key": "remote-service", "status": "warn", "summary": "Remote deployment credentials are incomplete", "details": []}]

    state = builder.build_state()
    service_name = state.get("runtime", {}).get("vpn_service", {}).get("name", "vpn-service")
    service_port = state.get("ss", {}).get("port", 8388)

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=host, port=port, username=user, password=password, timeout=20, banner_timeout=20)
    except Exception as error:
        return [{"key": "remote-service", "status": "warn", "summary": f"Cannot connect to VPN host: {error.__class__.__name__}", "details": []}]

    try:
        active = remote_exec(client, f"systemctl is-active {service_name}").strip()
        listeners = remote_exec(client, f"ss -lntup | grep {service_port} || true")
    finally:
        client.close()

    return [
        {
            "key": "remote-service",
            "status": "pass" if active == "active" else "fail",
            "summary": f"Remote {service_name} service is {'active' if active == 'active' else active or 'unknown'}",
            "details": [],
        },
        {
            "key": "remote-listener",
            "status": "pass" if "xray" in listeners.lower() else ("fail" if str(service_port) in listeners else "fail"),
            "summary": (
                f"Remote {service_port} listener belongs to Xray"
                if "xray" in listeners.lower()
                else f"Remote {service_port} listener is not owned by Xray"
                if str(service_port) in listeners
                else f"Remote {service_port} listener is missing"
            ),
            "details": [],
        },
    ]


def remote_exec(client: Any, command: str) -> str:
    """执行远端命令。"""
    _stdin, stdout, stderr = client.exec_command(command, timeout=120)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    return (out + ("\n" + err if err else "")).strip()


def redaction_tokens(vpn_root: Path) -> list[str]:
    """收集需要脱敏的敏感值。"""
    tokens: list[str] = []
    builder = load_module(vpn_root / "scripts" / "subscription_builder.py", "builder_redact", vpn_root / "scripts")
    deployer = load_module(vpn_root / "scripts" / "deploy_6node_subscription.py", "deployer_redact", vpn_root / "scripts")
    if builder is not None:
        tokens.extend([getattr(builder, "SS_PASSWORD", ""), getattr(builder, "SUBSCRIPTION_ID", "")])
    if deployer is not None and hasattr(deployer, "REMOTE"):
        remote = deployer.REMOTE
        tokens.extend([remote.get("ssh_password", ""), remote.get("panel_pass", "")])
    return [token for token in tokens if token]


def fix(
    vpn_root: Path | None,
    findings: list[Any],
    dry_run: bool,
    run_shell: Any,
    redact_text: Any,
) -> list[str]:
    """执行 VPN 修复。"""
    if vpn_root is None:
        return ["Skip VPN fixes: VPN project root not found"]
    if adapter_name(vpn_root) is None:
        return ["Skip VPN fixes: no supported VPN adapter matched"]

    def failed(keys: set[str]) -> bool:
        return any(getattr(item, "status", "") == "fail" and getattr(item, "key", "") in keys for item in findings)

    repair_keys = {"generated-subscription", "public-subscription", "remote-service", "remote-listener"}
    if not failed(repair_keys):
        return ["VPN deploy not needed"]
    if dry_run:
        return ["[DRY RUN] Would regenerate subscription and deploy"]

    actions: list[str] = []
    subprocess.run(
        [sys.executable, "scripts/subscription_builder.py"],
        capture_output=True, text=True, timeout=120, check=False, cwd=vpn_root,
    )
    actions.append("Regenerated VPN subscription outputs")

    if failed({"public-subscription", "remote-service", "remote-listener"}):
        result = subprocess.run(
            [sys.executable, "scripts/deploy_6node_subscription.py"],
            capture_output=True, text=True, timeout=1800, check=False, cwd=vpn_root,
        )
        if result.returncode != 0:
            output = redact_text(result.stdout + "\n" + result.stderr, redaction_tokens(vpn_root))
            raise RuntimeError(f"VPN deploy failed:\n{output[-4000:]}")
        actions.append("Ran VPN deploy script to sync public and remote state")
    else:
        actions.append("VPN deploy was not needed")
    return actions
