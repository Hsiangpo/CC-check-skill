#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Optional browser automation bootstrap helper for CC-Check."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path

LOCAL_BROWSER_ENV = ".cc-check-browser"


def get_browser_env_dir(project_root: Path) -> Path:
    """返回本地浏览器自动化依赖目录。"""
    return project_root / LOCAL_BROWSER_ENV


def build_package_json() -> dict[str, object]:
    """构建本地 Node 环境的 package.json。"""
    return {
        "name": "cc-check-browser-env",
        "private": True,
        "description": "Optional local browser automation environment for CC-Check",
        "license": "MIT",
    }


def build_install_commands(env_dir: Path) -> list[list[str]]:
    """返回安装 Playwright 所需命令。"""
    return [
        ["npm", "install", "playwright"],
        ["npx", "playwright", "install", "chromium"],
    ]


def ensure_package_json(env_dir: Path) -> Path:
    """写入最小 package.json。"""
    env_dir.mkdir(parents=True, exist_ok=True)
    package_path = env_dir / "package.json"
    package_path.write_text(json.dumps(build_package_json(), indent=2) + "\n", encoding="utf-8")
    return package_path


def collect_tool_status() -> dict[str, str]:
    """检测 Node 相关命令是否可用。"""
    return {
        "node": shutil.which("node") or "",
        "npm": shutil.which("npm") or "",
        "npx": shutil.which("npx") or "",
    }


def collect_proxy_env() -> dict[str, str]:
    """返回当前可见的代理环境变量。"""
    keys = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")
    return {key: os.environ.get(key, "") for key in keys if os.environ.get(key, "").strip()}


def build_status_payload(project_root: Path) -> dict[str, object]:
    """构建浏览器自动化环境状态摘要。"""
    env_dir = get_browser_env_dir(project_root)
    package_path = env_dir / "node_modules" / "playwright" / "index.js"
    tool_status = collect_tool_status()
    missing_tools = [name for name, path in tool_status.items() if not path]
    installed = package_path.exists()
    recommendations: list[str] = []
    if missing_tools:
        recommendations.append(f"missing tools: {', '.join(missing_tools)}")
    elif not installed:
        recommendations.append("run browser_bootstrap.py install to prepare local Playwright")
    else:
        recommendations.append("local Playwright environment is ready")

    return {
        "env_dir": str(env_dir),
        "installed": installed,
        "module": str(package_path),
        "package_json": str(env_dir / "package.json"),
        "tools": tool_status,
        "missing_tools": missing_tools,
        "proxy_env": collect_proxy_env(),
        "install_commands": [" ".join(command) for command in build_install_commands(env_dir)],
        "recommendations": recommendations,
    }


def run_install(env_dir: Path) -> None:
    """执行本地 Playwright 安装。"""
    ensure_package_json(env_dir)
    for command in build_install_commands(env_dir):
        subprocess.run(command, cwd=str(env_dir), check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Bootstrap optional local Playwright environment for CC-Check")
    parser.add_argument("command", choices=("status", "install"), nargs="?", default="status")
    parser.add_argument("--dry-run", action="store_true", help="Print commands without executing them")
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parents[1]
    env_dir = get_browser_env_dir(project_root)
    if args.command == "status":
        print(json.dumps(build_status_payload(project_root), ensure_ascii=False, indent=2))
        return 0

    if args.dry_run:
        print(f"mkdir -p {env_dir}")
        print(f"write {env_dir / 'package.json'}")
        for command in build_install_commands(env_dir):
            print(" ".join(command))
        return 0

    run_install(env_dir)
    print(f"Playwright installed under {env_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
