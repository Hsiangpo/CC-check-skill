#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""跨平台操作抽象层。

根据 sys.platform 自动分发到 macOS / Linux / Windows 对应实现。
所有函数返回统一结构，上层 cc_check.py 无需关心平台差异。
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PLATFORM = sys.platform  # darwin / linux / win32


# ---------------------------------------------------------------------------
# Shell execution
# ---------------------------------------------------------------------------

def _detect_shell() -> str:
    if PLATFORM == "win32":
        return _detect_windows_shell()
    shell = os.environ.get("SHELL", "")
    if "zsh" in shell:
        return "/bin/zsh"
    if "fish" in shell:
        return shell
    return "/bin/bash"


def _detect_windows_shell() -> str:
    """优先使用 pwsh，不存在时再退回 powershell。"""
    for shell_name in ("pwsh", "powershell"):
        shell_path = shutil.which(shell_name)
        if shell_path:
            return shell_path
    return "powershell"


def _prepare_command_args(args: list[str]) -> list[str]:
    """在 Windows 下兼容 .cmd/.bat 包装器。"""
    if PLATFORM != "win32" or not args:
        return args

    resolved = shutil.which(args[0]) or args[0]
    prepared = [resolved, *args[1:]]
    if str(resolved).lower().endswith((".cmd", ".bat")):
        comspec = os.environ.get("ComSpec", "cmd.exe")
        return [comspec, "/d", "/s", "/c", subprocess.list2cmdline(prepared)]
    return prepared


def run_command(args: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
    """直接调用外部程序，避免 shell 引号和重定向差异。"""
    prepared_args = _prepare_command_args(args)
    try:
        return subprocess.run(
            prepared_args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return subprocess.CompletedProcess(prepared_args, 127, "", f"Command not found: {args[0]}")


def run_shell(command: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    """执行当前平台的 shell 命令。"""
    if PLATFORM == "win32":
        return subprocess.run(
            [_detect_windows_shell(), "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    shell = _detect_shell()
    flag = "-lc" if "zsh" in shell else "-c"
    return subprocess.run(
        [shell, flag, command],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


# ---------------------------------------------------------------------------
# Locale & Language
# ---------------------------------------------------------------------------

@dataclass
class LocaleInfo:
    lang: str
    lc_all: str
    system_languages: list[str]
    measurement_units: str  # "Inches" / "Centimeters" / ""
    temperature_unit: str   # "Fahrenheit" / "Celsius" / ""
    time_format_24h: bool | None
    date_format: str        # "MDY" / "DMY" / ""


def get_locale_info() -> LocaleInfo:
    """获取系统 locale 信息。"""
    lang = os.environ.get("LANG", "")
    lc_all = os.environ.get("LC_ALL", "")

    languages: list[str] = []
    measurement = ""
    temperature = ""
    time_24h: bool | None = None
    date_fmt = ""

    if PLATFORM == "darwin":
        r = run_shell("defaults read NSGlobalDomain AppleLanguages 2>/dev/null")
        if r.returncode == 0:
            languages = re.findall(r'"([^"]+)"', r.stdout)
            if not languages:
                languages = [s.strip().strip(",").strip('"').strip("'")
                             for s in r.stdout.splitlines()
                             if s.strip() and s.strip() not in ("(", ")")]
        r = run_shell("defaults read NSGlobalDomain AppleMeasurementUnits 2>/dev/null")
        measurement = r.stdout.strip() if r.returncode == 0 else ""
        r = run_shell("defaults read NSGlobalDomain AppleTemperatureUnit 2>/dev/null")
        temperature = r.stdout.strip() if r.returncode == 0 else ""
        r = run_shell("defaults read NSGlobalDomain AppleICUForce24HourTime 2>/dev/null")
        if r.returncode == 0:
            time_24h = r.stdout.strip() == "1"

    elif PLATFORM == "linux":
        r = run_shell("localectl status 2>/dev/null")
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                if "LANG=" in line:
                    lang = lang or line.split("=", 1)[-1].strip()

    elif PLATFORM == "win32":
        r = run_shell("(Get-Culture).Name")
        if r.returncode == 0:
            languages = [r.stdout.strip()]
        r = run_shell("[System.Globalization.RegionInfo]::CurrentRegion.IsMetric")
        if r.returncode == 0:
            is_metric = r.stdout.strip().lower() == "true"
            measurement = "Centimeters" if is_metric else "Inches"
            temperature = "Celsius" if is_metric else "Fahrenheit"

    return LocaleInfo(lang=lang, lc_all=lc_all, system_languages=languages,
                      measurement_units=measurement, temperature_unit=temperature,
                      time_format_24h=time_24h, date_format=date_fmt)


# ---------------------------------------------------------------------------
# Timezone
# ---------------------------------------------------------------------------

def get_system_timezone() -> str:
    """获取系统时区。"""
    if PLATFORM == "darwin":
        link = Path("/etc/localtime")
        if link.is_symlink():
            target = str(link.resolve())
            idx = target.find("zoneinfo/")
            if idx != -1:
                return target[idx + 9:]
    elif PLATFORM == "linux":
        r = run_shell("timedatectl show --property=Timezone --value 2>/dev/null")
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
        tz_file = Path("/etc/timezone")
        if tz_file.exists():
            return tz_file.read_text().strip()
    elif PLATFORM == "win32":
        r = run_shell("(Get-TimeZone).Id")
        if r.returncode == 0:
            return r.stdout.strip()
    return os.environ.get("TZ", "")


# ---------------------------------------------------------------------------
# Hostname
# ---------------------------------------------------------------------------

def get_hostname_info() -> dict[str, str]:
    """获取主机名信息。"""
    import socket
    info: dict[str, str] = {"hostname": socket.gethostname()}
    if PLATFORM == "darwin":
        r = run_shell("scutil --get ComputerName 2>/dev/null")
        if r.returncode == 0:
            info["computer_name"] = r.stdout.strip()
        r = run_shell("scutil --get LocalHostName 2>/dev/null")
        if r.returncode == 0:
            info["local_hostname"] = r.stdout.strip()
    elif PLATFORM == "win32":
        r = run_shell("$env:COMPUTERNAME")
        if r.returncode == 0:
            info["computer_name"] = r.stdout.strip()
    return info


# ---------------------------------------------------------------------------
# User identity
# ---------------------------------------------------------------------------

def get_user_info() -> dict[str, str]:
    """获取当前用户信息。"""
    info: dict[str, str] = {"username": os.environ.get("USER") or os.environ.get("USERNAME", "")}
    if PLATFORM == "darwin":
        r = run_shell("id -F 2>/dev/null")
        if r.returncode == 0:
            info["real_name"] = r.stdout.strip()
    elif PLATFORM == "linux":
        r = run_shell("getent passwd $(whoami) | cut -d: -f5 | cut -d, -f1")
        if r.returncode == 0:
            info["real_name"] = r.stdout.strip()
    elif PLATFORM == "win32":
        r = run_shell("[System.Security.Principal.WindowsIdentity]::GetCurrent().Name")
        if r.returncode == 0:
            info["real_name"] = r.stdout.strip()
    return info


# ---------------------------------------------------------------------------
# Input method
# ---------------------------------------------------------------------------

def get_active_input_methods() -> list[str]:
    """获取当前活跃的输入法。"""
    methods: list[str] = []
    if PLATFORM == "darwin":
        try:
            import plistlib
            path = Path.home() / "Library/Preferences/com.apple.HIToolbox.plist"
            if path.exists():
                payload = plistlib.loads(path.read_bytes())
                for source in payload.get("AppleSelectedInputSources", []):
                    if isinstance(source, dict):
                        im = source.get("Input Mode") or source.get("Bundle ID")
                        if im:
                            methods.append(str(im))
                for source in payload.get("AppleEnabledInputSources", []):
                    if isinstance(source, dict):
                        im = source.get("Input Mode") or source.get("Bundle ID")
                        if im and im not in methods:
                            methods.append(str(im))
        except Exception:
            pass
        r = run_shell("defaults read com.apple.HIToolbox AppleCurrentKeyboardLayoutInputSourceID 2>/dev/null")
        if r.returncode == 0:
            kid = r.stdout.strip()
            if kid and kid not in methods:
                methods.insert(0, kid)
    elif PLATFORM == "linux":
        r = run_shell("gsettings get org.gnome.desktop.input-sources sources 2>/dev/null")
        if r.returncode == 0 and r.stdout.strip():
            methods.append(r.stdout.strip())
    return methods


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

def get_dns_servers() -> dict[str, list[str]]:
    """获取各网络接口的 DNS 服务器。返回 {service: [servers]}。"""
    result: dict[str, list[str]] = {}
    if PLATFORM == "darwin":
        r = run_shell("networksetup -listallnetworkservices")
        if r.returncode != 0:
            return result
        for line in r.stdout.splitlines()[1:]:
            service = line.lstrip("*").strip()
            if not service:
                continue
            dns_r = run_shell(f'networksetup -getdnsservers "{service}"')
            if dns_r.returncode != 0:
                continue
            if "There aren't any DNS Servers set" in dns_r.stdout:
                result[service] = []
            else:
                result[service] = [s.strip() for s in dns_r.stdout.splitlines() if s.strip()]
    elif PLATFORM == "linux":
        resolv = Path("/etc/resolv.conf")
        if resolv.exists():
            servers = [line.split()[1] for line in resolv.read_text().splitlines()
                       if line.startswith("nameserver")]
            result["system"] = servers
        r = run_shell("resolvectl status 2>/dev/null")
        if r.returncode == 0:
            current_iface = "resolved"
            for line in r.stdout.splitlines():
                if "Link" in line:
                    m = re.search(r'\((\S+)\)', line)
                    current_iface = m.group(1) if m else "resolved"
                if "DNS Servers:" in line or "Current DNS Server:" in line:
                    server = line.split(":")[-1].strip()
                    if server:
                        result.setdefault(current_iface, []).append(server)
    elif PLATFORM == "win32":
        r = run_shell("Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object InterfaceAlias, ServerAddresses | ConvertTo-Json")
        if r.returncode == 0:
            try:
                entries = json.loads(r.stdout)
                if isinstance(entries, dict):
                    entries = [entries]
                for entry in entries:
                    iface = entry.get("InterfaceAlias", "unknown")
                    servers = entry.get("ServerAddresses", [])
                    if servers:
                        result[iface] = servers
            except json.JSONDecodeError:
                pass
    return result


def clear_dns_for_service(service: str) -> None:
    """将指定网络接口的 DNS 替换为安全的公共 DNS。

    注意：不能使用 'Empty' 清空 DNS，否则 Clash Verge 等代理客户端
    无法解析节点服务器域名，导致所有节点 Timeout、网络完全中断。
    正确做法是替换为无风控风险的公共 DNS（Google / Cloudflare）。
    """
    safe_dns = ["8.8.8.8", "1.1.1.1"]
    if PLATFORM == "darwin":
        dns_str = " ".join(safe_dns)
        run_shell(f'networksetup -setdnsservers "{service}" {dns_str}')
    elif PLATFORM == "linux":
        run_shell("sudo resolvectl revert 2>/dev/null || true")
    elif PLATFORM == "win32":
        # Set safe DNS on the specified interface
        dns_csv = ",".join(f'"{d}"' for d in safe_dns)
        run_shell(
            f'Set-DnsClientServerAddress -InterfaceAlias "{service}" '
            f'-ServerAddresses ({dns_csv})'
        )


def flush_dns_cache() -> None:
    """刷新 DNS 缓存。"""
    if PLATFORM == "darwin":
        run_shell("sudo dscacheutil -flushcache 2>/dev/null; sudo killall -HUP mDNSResponder 2>/dev/null")
    elif PLATFORM == "linux":
        run_shell("sudo systemd-resolve --flush-caches 2>/dev/null || sudo resolvectl flush-caches 2>/dev/null")
    elif PLATFORM == "win32":
        run_shell("Clear-DnsClientCache")


# ---------------------------------------------------------------------------
# Network & Proxy
# ---------------------------------------------------------------------------

def get_tun_interfaces() -> list[str]:
    """获取 TUN 虚拟网卡列表。"""
    tuns: list[str] = []
    if PLATFORM == "darwin":
        r = run_shell("ifconfig 2>/dev/null | grep -E '^utun' | cut -d: -f1")
        tuns = [s.strip() for s in r.stdout.splitlines() if s.strip()]
    elif PLATFORM == "linux":
        r = run_shell("ip link show 2>/dev/null | grep -E 'tun|Meta' | awk -F: '{print $2}' | tr -d ' '")
        tuns = [s.strip() for s in r.stdout.splitlines() if s.strip()]
    elif PLATFORM == "win32":
        r = run_shell("Get-NetAdapter | Where-Object { $_.InterfaceDescription -like '*TAP*' -or $_.InterfaceDescription -like '*TUN*' -or $_.InterfaceDescription -like '*Wintun*' } | Select-Object -ExpandProperty Name")
        tuns = [s.strip() for s in r.stdout.splitlines() if s.strip()]
    return tuns


def get_system_proxy_state() -> dict[str, Any]:
    """获取系统代理设置。"""
    state: dict[str, Any] = {"enabled": False}
    if PLATFORM == "darwin":
        r = run_shell("networksetup -getwebproxy Wi-Fi 2>/dev/null")
        if r.returncode == 0 and "Enabled: Yes" in r.stdout:
            state["enabled"] = True
            for line in r.stdout.splitlines():
                if line.startswith("Server:"):
                    state["server"] = line.split(":", 1)[1].strip()
                if line.startswith("Port:"):
                    state["port"] = line.split(":", 1)[1].strip()
    elif PLATFORM == "linux":
        for key in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
            if os.environ.get(key):
                state["enabled"] = True
                state["proxy_env"] = os.environ.get(key)
                break
    elif PLATFORM == "win32":
        r = run_shell('Get-ItemProperty "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" | Select-Object ProxyEnable, ProxyServer | ConvertTo-Json')
        if r.returncode == 0:
            try:
                data = json.loads(r.stdout)
                state["enabled"] = bool(data.get("ProxyEnable"))
                state["server"] = data.get("ProxyServer", "")
            except json.JSONDecodeError:
                pass
    return state


# ---------------------------------------------------------------------------
# Clash Verge / proxy client
# ---------------------------------------------------------------------------

_CLASH_DIR_NAMES = [
    "io.github.clash-verge-rev.clash-verge-rev",
    "clash-verge",
    "io.github.clashverge.rev",
]


def detect_clash_dir(explicit: str | None = None) -> Path | None:
    """发现 Clash Verge 支持目录。"""
    if explicit:
        p = Path(explicit).expanduser()
        return p if p.exists() else None

    env_path = os.environ.get("CC_CHECK_CLASH_DIR")
    if env_path:
        p = Path(env_path).expanduser()
        return p if p.exists() else None

    if PLATFORM == "darwin":
        base = Path.home() / "Library" / "Application Support"
    elif PLATFORM == "linux":
        base = Path.home() / ".config"
    elif PLATFORM == "win32":
        base = Path(os.environ.get("APPDATA", "")) if os.environ.get("APPDATA") else Path.home() / "AppData" / "Roaming"
    else:
        return None

    for name in _CLASH_DIR_NAMES:
        candidate = base / name
        if candidate.exists():
            return candidate
    return None


_CLASH_PROCESS_PATTERNS = {
    "darwin": "Clash Verge.app/Contents/MacOS/clash-verge",
    "linux": "clash-verge",
    "win32": "clash-verge",
}


def is_clash_running() -> bool:
    """检测 Clash Verge 进程是否在运行。"""
    pattern = _CLASH_PROCESS_PATTERNS.get(PLATFORM, "clash-verge")
    if PLATFORM == "win32":
        r = run_shell(f'Get-Process -Name "clash-verge" -ErrorAction SilentlyContinue')
        return r.returncode == 0 and "clash-verge" in r.stdout.lower()
    r = run_shell(f'pgrep -f "{pattern}" 2>/dev/null')
    return r.returncode == 0


def get_clash_api_json(path: str) -> dict[str, Any] | None:
    """通过 mihomo unix socket / HTTP 读取 Clash API。"""
    sock = "/tmp/verge/verge-mihomo.sock"
    if PLATFORM != "win32" and Path(sock).exists():
        cmd = f"curl --silent --show-error --unix-socket {sock} http://localhost/{path}"
    else:
        cmd = f"curl --silent --show-error http://127.0.0.1:9097/{path}"
    r = run_shell(cmd, timeout=8)
    if r.returncode != 0 or not r.stdout.strip():
        return None
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return None


# ---------------------------------------------------------------------------
# Package manager mirrors
# ---------------------------------------------------------------------------

CHINA_MIRROR_KEYWORDS = [
    "taobao", "npmmirror", "cnpm", "tencent", "aliyun", "tuna.tsinghua",
    "ustc.edu.cn", "huaweicloud", "163.com", "douban", "bfsu.edu.cn",
]


def _first_successful_stdout(commands: list[list[str]], timeout: int = 30) -> str:
    """依次尝试多个命令，返回第一个有效输出。"""
    for args in commands:
        result = run_command(args, timeout=timeout)
        output = result.stdout.strip()
        if result.returncode == 0 and output and output.lower() not in {"null", "undefined"}:
            return output
    return ""


def get_npm_registry() -> str:
    """读取 npm registry。"""
    return _first_successful_stdout([["npm", "config", "get", "registry"]])


def set_npm_registry(registry: str) -> bool:
    """设置 npm registry。"""
    result = run_command(["npm", "config", "set", "registry", registry])
    return result.returncode == 0


def get_pip_index_url() -> str:
    """读取 pip 全局 index-url。"""
    return _first_successful_stdout(
        [
            ["pip3", "config", "get", "global.index-url"],
            [sys.executable, "-m", "pip", "config", "get", "global.index-url"],
        ]
    )


def unset_pip_global_index() -> bool:
    """移除 pip 全局 index-url。"""
    for args in (
        ["pip3", "config", "unset", "global.index-url"],
        [sys.executable, "-m", "pip", "config", "unset", "global.index-url"],
    ):
        result = run_command(args)
        if result.returncode == 0:
            return True
    return False


def get_git_global_value(key: str) -> str:
    """读取 git 全局配置项。"""
    result = run_command(["git", "config", "--global", key])
    return result.stdout.strip() if result.returncode == 0 else ""


def unset_git_global_value(key: str) -> bool:
    """移除 git 全局配置项。"""
    result = run_command(["git", "config", "--global", "--unset", key])
    return result.returncode == 0


def remove_tree(path: Path) -> bool:
    """递归删除目录。"""
    if not path.exists():
        return True
    try:
        shutil.rmtree(path)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return not path.exists()


def find_china_mirror_residue() -> list[str]:
    """用 Python 直接扫描 npm 相关残留文件。"""
    candidates: list[Path] = []
    npm_root = Path.home() / ".npm"
    if npm_root.exists():
        for pattern in ("*.json", "*.npmrc", "*npmrc*"):
            candidates.extend(npm_root.rglob(pattern))
    npmrc = Path.home() / ".npmrc"
    if npmrc.exists():
        candidates.append(npmrc)

    hits: list[str] = []
    seen: set[Path] = set()
    for path in sorted(candidates):
        if path in seen or not path.is_file():
            continue
        seen.add(path)
        try:
            text = path.read_text(errors="ignore").lower()
        except OSError:
            continue
        if any(keyword in text for keyword in CHINA_MIRROR_KEYWORDS):
            hits.append(str(path))
    return hits


def check_package_mirrors() -> dict[str, dict[str, Any]]:
    """检测 npm/pip/brew 是否使用了中国镜像。"""
    results: dict[str, dict[str, Any]] = {}

    # npm
    npm_reg = get_npm_registry()
    is_china = any(kw in npm_reg.lower() for kw in CHINA_MIRROR_KEYWORDS)
    results["npm"] = {"registry": npm_reg, "is_china_mirror": is_china}

    # pip
    pip_index = ""
    for path in [Path.home() / ".pip" / "pip.conf", Path.home() / ".config" / "pip" / "pip.conf"]:
        if path.exists():
            text = path.read_text(errors="ignore")
            m = re.search(r'index-url\s*=\s*(\S+)', text)
            if m:
                pip_index = m.group(1)
                break
    pip_output = get_pip_index_url()
    if pip_output:
        pip_index = pip_index or pip_output
    is_china = any(kw in pip_index.lower() for kw in CHINA_MIRROR_KEYWORDS) if pip_index else False
    results["pip"] = {"index": pip_index or "(default pypi)", "is_china_mirror": is_china}

    # brew (macOS / Linux)
    if PLATFORM != "win32":
        brew_vars = {}
        for key in ["HOMEBREW_API_DOMAIN", "HOMEBREW_BOTTLE_DOMAIN", "HOMEBREW_BREW_GIT_REMOTE"]:
            val = os.environ.get(key, "")
            brew_vars[key] = val
        is_china = any(any(kw in v.lower() for kw in CHINA_MIRROR_KEYWORDS) for v in brew_vars.values() if v)
        results["brew"] = {"vars": brew_vars, "is_china_mirror": is_china}

    return results


# ---------------------------------------------------------------------------
# Node.js runtime
# ---------------------------------------------------------------------------

def get_nodejs_env() -> dict[str, str]:
    """获取 Node.js 运行时环境信息。"""
    script = """
    const os = require('os');
    console.log(JSON.stringify({
        tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
        locale: Intl.DateTimeFormat().resolvedOptions().locale,
        time: new Date().toString(),
        hostname: os.hostname(),
        platform: os.platform(),
    }));
    """
    r = run_command(["node", "-e", script.strip()])
    if r.returncode != 0:
        return {}
    try:
        return json.loads(r.stdout.strip())
    except json.JSONDecodeError:
        return {}


# ---------------------------------------------------------------------------
# /etc/hosts
# ---------------------------------------------------------------------------

def check_hosts_file() -> list[str]:
    """检查 hosts 文件中的非标准条目。"""
    suspicious: list[str] = []
    if PLATFORM == "win32":
        hosts_path = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
    else:
        hosts_path = Path("/etc/hosts")
    if not hosts_path.exists():
        return suspicious
    for line in hosts_path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line in ("127.0.0.1\tlocalhost", "127.0.0.1       localhost",
                    "255.255.255.255\tbroadcasthost", "255.255.255.255 broadcasthost",
                    "::1\tlocalhost", "::1             localhost", "::1 localhost"):
            continue
        suspicious.append(line)
    return suspicious


# ---------------------------------------------------------------------------
# Shell history
# ---------------------------------------------------------------------------

CHINA_DOMAIN_KEYWORDS = [
    "taobao", "aliyun", "tencent", "baidu", "163.com", "qq.com",
    "weixin", "wechat", "zhihu", "bilibili", "cnpm", "npmmirror",
    "douyin", "bytedance", "jd.com", "alibaba",
]


def scan_shell_history() -> dict[str, int]:
    """扫描 shell 历史中的中国域名/IP 引用。"""
    hits: dict[str, int] = {}
    history_files = []
    if PLATFORM != "win32":
        for name in [".zsh_history", ".bash_history", ".local/share/fish/fish_history"]:
            path = Path.home() / name
            if path.exists():
                history_files.append(path)
    for path in history_files:
        try:
            text = path.read_text(errors="ignore")
        except Exception:
            continue
        for keyword in CHINA_DOMAIN_KEYWORDS:
            count = text.lower().count(keyword)
            if count > 0:
                hits[keyword] = hits.get(keyword, 0) + count
    return hits


def clean_shell_history(dry_run: bool = False) -> dict[str, int]:
    """精准删除 shell 历史中含中国域名的行，保留其他所有历史。

    Returns:
        dict: {history_file: removed_count}
    """
    removed: dict[str, int] = {}
    if PLATFORM == "win32":
        return removed

    history_files = []
    for name in [".zsh_history", ".bash_history", ".local/share/fish/fish_history"]:
        path = Path.home() / name
        if path.exists():
            history_files.append(path)

    keywords_lower = [k.lower() for k in CHINA_DOMAIN_KEYWORDS]

    for path in history_files:
        try:
            lines = path.read_text(errors="ignore").splitlines(keepends=True)
        except Exception:
            continue

        clean_lines = []
        removed_count = 0
        for line in lines:
            lower = line.lower()
            if any(kw in lower for kw in keywords_lower):
                removed_count += 1
            else:
                clean_lines.append(line)

        if removed_count > 0:
            removed[str(path)] = removed_count
            if not dry_run:
                # Backup before modifying
                backup = path.with_suffix(path.suffix + ".bak")
                try:
                    import shutil
                    shutil.copy2(path, backup)
                    path.write_text("".join(clean_lines), errors="ignore")
                except Exception:
                    pass

    return removed


# ---------------------------------------------------------------------------
# Shell profiles
# ---------------------------------------------------------------------------

def get_shell_profile_paths() -> list[Path]:
    """获取当前平台的 shell profile 文件路径。"""
    home = Path.home()
    if PLATFORM == "win32":
        r = run_shell("echo $PROFILE")
        if r.returncode == 0 and r.stdout.strip():
            return [Path(r.stdout.strip())]
        return []

    shell = _detect_shell()
    if "zsh" in shell:
        return [home / ".zprofile", home / ".zshrc"]
    if "fish" in shell:
        return [home / ".config" / "fish" / "config.fish"]
    return [home / ".bash_profile", home / ".bashrc"]


# ---------------------------------------------------------------------------
# Browser fingerprint detection (basic)
# ---------------------------------------------------------------------------

_BROWSER_APPS = {
    "AdsPower": {
        "darwin": "~/Library/Application Support/AdsEditor",
        "win32": "%LOCALAPPDATA%/AdsEditor",
    },
    "BitBrowser": {
        "darwin": "~/Library/Application Support/BitBrowser",
        "win32": "%LOCALAPPDATA%/BitBrowser",
    },
    "VMLogin": {
        "darwin": "~/Library/Application Support/VMLogin",
        "win32": "%APPDATA%/VMLogin",
    },
    "Multilogin": {
        "darwin": "~/Library/Application Support/Multilogin",
        "win32": "%APPDATA%/Multilogin",
    },
    "GoLogin": {
        "darwin": "~/Library/Application Support/GoLogin",
        "win32": "%APPDATA%/GoLogin",
    },
}


def detect_fingerprint_browsers() -> list[str]:
    """检测已安装的指纹浏览器。"""
    found: list[str] = []
    for name, paths in _BROWSER_APPS.items():
        raw = paths.get(PLATFORM, "")
        if not raw:
            continue
        expanded = Path(os.path.expandvars(os.path.expanduser(raw)))
        if expanded.exists():
            found.append(name)
    return found


# ---------------------------------------------------------------------------
# LaunchAgent / systemd user service (DNS watchdog)
# ---------------------------------------------------------------------------

LAUNCH_AGENT_LABEL = "io.github.clash-verge-rev.dns-cleanup"
SUSPICIOUS_DNS = {"114.114.114.114", "223.5.5.5", "223.6.6.6", "119.29.29.29"}


def install_dns_watchdog(clash_dir: Path) -> list[str]:
    """安装 DNS 展示值清理守护。"""
    actions: list[str] = []
    if PLATFORM == "darwin":
        script = _build_macos_cleanup_script()
        helper = clash_dir / "cleanup_system_dns.sh"
        helper.write_text(script, encoding="utf-8")
        helper.chmod(0o755)

        agent_dir = Path.home() / "Library" / "LaunchAgents"
        agent_dir.mkdir(parents=True, exist_ok=True)
        plist_path = agent_dir / f"{LAUNCH_AGENT_LABEL}.plist"
        plist_path.write_text(_build_launchagent_plist(helper), encoding="utf-8")

        uid = os.getuid()
        run_shell(f'launchctl bootout gui/{uid} "{plist_path}" >/dev/null 2>&1 || true')
        run_shell(f'launchctl bootstrap gui/{uid} "{plist_path}"')
        run_shell(f'launchctl kickstart -k gui/{uid}/{LAUNCH_AGENT_LABEL}')
        actions.append("Installed macOS DNS cleanup watchdog LaunchAgent")

    elif PLATFORM == "linux":
        # Install systemd user timer for DNS cleanup
        config_dir = Path.home() / ".config" / "systemd" / "user"
        config_dir.mkdir(parents=True, exist_ok=True)

        cleanup_script = clash_dir / "cleanup_system_dns.sh"
        cleanup_script.write_text(_build_linux_cleanup_script(), encoding="utf-8")
        cleanup_script.chmod(0o755)

        service_unit = config_dir / "cc-check-dns-cleanup.service"
        service_unit.write_text(
            "[Unit]\n"
            "Description=CC-check DNS cleanup\n\n"
            "[Service]\n"
            "Type=oneshot\n"
            f"ExecStart={cleanup_script}\n",
            encoding="utf-8",
        )

        timer_unit = config_dir / "cc-check-dns-cleanup.timer"
        timer_unit.write_text(
            "[Unit]\n"
            "Description=CC-check DNS cleanup timer\n\n"
            "[Timer]\n"
            "OnBootSec=30s\n"
            "OnUnitActiveSec=15s\n\n"
            "[Install]\n"
            "WantedBy=timers.target\n",
            encoding="utf-8",
        )

        run_shell("systemctl --user daemon-reload")
        run_shell("systemctl --user enable --now cc-check-dns-cleanup.timer")
        actions.append("Installed Linux DNS cleanup systemd user timer")

    elif PLATFORM == "win32":
        actions.append("Windows DNS watchdog: not implemented (DNS usually managed by proxy client)")
    return actions


def _build_macos_cleanup_script() -> str:
    return """#!/bin/zsh
set -euo pipefail
if ! pgrep -f "/Applications/Clash Verge.app/Contents/MacOS/clash-verge" >/dev/null 2>&1; then exit 0; fi
while IFS= read -r service; do
  service=${service#\\*}; service=${service## }
  [[ -z "$service" ]] && continue
  current=$(/usr/sbin/networksetup -getdnsservers "$service" 2>/dev/null || true)
  if [[ "$current" == *"114.114.114.114"* ]] || [[ "$current" == *"223.5.5.5"* ]] || [[ "$current" == *"223.6.6.6"* ]] || [[ "$current" == *"119.29.29.29"* ]]; then
    /usr/sbin/networksetup -setdnsservers "$service" 8.8.8.8 1.1.1.1 >/dev/null 2>&1 || true
  fi
done < <(/usr/sbin/networksetup -listallnetworkservices | tail -n +2)
"""


def _build_linux_cleanup_script() -> str:
    """生成 Linux DNS 清理 bash 脚本。"""
    suspicious_list = " ".join(SUSPICIOUS_DNS)
    return f"""#!/bin/bash
set -euo pipefail
# CC-check DNS cleanup for Linux
# Checks resolv.conf and resolvectl for suspicious China DNS servers

SUSPICIOUS=({suspicious_list})

cleanup_resolv() {{
    if [ ! -f /etc/resolv.conf ]; then return; fi
    for dns in "${{SUSPICIOUS[@]}}"; do
        if grep -q "$dns" /etc/resolv.conf 2>/dev/null; then
            sudo resolvectl revert 2>/dev/null || true
            echo "Reverted DNS via resolvectl"
            return
        fi
    done
}}

cleanup_resolv
"""


def _build_launchagent_plist(script_path: Path) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key><string>{LAUNCH_AGENT_LABEL}</string>
    <key>ProgramArguments</key><array><string>/bin/zsh</string><string>{script_path}</string></array>
    <key>RunAtLoad</key><true/>
    <key>StartInterval</key><integer>15</integer>
    <key>StandardOutPath</key><string>/tmp/{LAUNCH_AGENT_LABEL}.out</string>
    <key>StandardErrorPath</key><string>/tmp/{LAUNCH_AGENT_LABEL}.err</string>
  </dict>
</plist>
"""
