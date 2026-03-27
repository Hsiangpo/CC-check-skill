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


def install_rime(dry_run: bool = False) -> list[str]:
    """跨平台安装 RIME 输入法（隐蔽中文输入方案）。

    macOS: Squirrel (鼠须管) — bundle ID: im.rime.inputmethod.Squirrel
    Linux: ibus-rime 或 fcitx5-rime
    Windows: Weasel (小狼毫)

    Returns:
        list[str]: 操作日志
    """
    actions: list[str] = []

    if PLATFORM == "darwin":
        # Check if already installed
        if Path("/Library/Input Methods/Squirrel.app").exists():
            actions.append("RIME/Squirrel already installed")
            return actions

        if dry_run:
            actions.append("[DRY RUN] Would download and install Squirrel.pkg from GitHub")
            return actions

        # Download latest release
        import json as _json
        try:
            from urllib.request import urlopen
            resp = urlopen("https://api.github.com/repos/rime/squirrel/releases/latest", timeout=15)
            release = _json.loads(resp.read())
            pkg_url = None
            for asset in release.get("assets", []):
                if asset["name"].endswith(".pkg"):
                    pkg_url = asset["browser_download_url"]
                    break
            if not pkg_url:
                actions.append("Failed: no .pkg found in latest Squirrel release")
                return actions

            pkg_path = Path("/tmp/Squirrel.pkg")
            r = run_shell(f'curl -sL -o {pkg_path} "{pkg_url}"')
            if r.returncode != 0 or not pkg_path.exists():
                actions.append("Failed to download Squirrel.pkg")
                return actions
            actions.append(f"Downloaded Squirrel.pkg ({pkg_path.stat().st_size // 1024 // 1024}MB)")

            # Install (requires sudo - will prompt)
            r = run_shell(f"sudo installer -pkg {pkg_path} -target /")
            if r.returncode == 0:
                actions.append("Installed Squirrel successfully")
            else:
                actions.append(f"Install failed (may need manual: open {pkg_path})")
                actions.append("Manual install: double-click /tmp/Squirrel.pkg")
        except Exception as e:
            actions.append(f"Failed to install Squirrel: {e}")
            actions.append("Manual: download from https://github.com/rime/squirrel/releases")

    elif PLATFORM == "linux":
        if dry_run:
            actions.append("[DRY RUN] Would install ibus-rime or fcitx5-rime")
            return actions

        # Detect package manager and input framework
        has_fcitx5 = run_shell("which fcitx5 2>/dev/null").returncode == 0
        has_ibus = run_shell("which ibus 2>/dev/null").returncode == 0
        has_apt = run_shell("which apt-get 2>/dev/null").returncode == 0
        has_dnf = run_shell("which dnf 2>/dev/null").returncode == 0
        has_pacman = run_shell("which pacman 2>/dev/null").returncode == 0

        pkg = "fcitx5-rime" if has_fcitx5 else "ibus-rime"

        if has_apt:
            r = run_shell(f"sudo apt-get install -y {pkg}")
        elif has_dnf:
            r = run_shell(f"sudo dnf install -y {pkg}")
        elif has_pacman:
            r = run_shell(f"sudo pacman -S --noconfirm {pkg}")
        else:
            actions.append(f"Please install {pkg} manually with your package manager")
            return actions

        if r.returncode == 0:
            actions.append(f"Installed {pkg} successfully")
        else:
            actions.append(f"Failed to install {pkg}: {r.stderr}")

    elif PLATFORM == "win32":
        if dry_run:
            actions.append("[DRY RUN] Would download Weasel (小狼毫) installer")
            return actions

        actions.append("Windows RIME (Weasel/小狼毫) requires manual installation:")
        actions.append("  Download: https://github.com/rime/weasel/releases")
        actions.append("  After install, remove Chinese IME from Settings → Time & Language → Language")

    return actions


def remove_system_chinese_ime(dry_run: bool = False) -> list[str]:
    """移除系统内置的中文输入法（保留 RIME）。

    Returns:
        list[str]: 操作日志
    """
    actions: list[str] = []

    if PLATFORM == "darwin":
        try:
            import plistlib
            plist_path = Path.home() / "Library/Preferences/com.apple.HIToolbox.plist"
            if not plist_path.exists():
                return ["HIToolbox plist not found"]

            payload = plistlib.loads(plist_path.read_bytes())
            china_keywords = ("pinyin", "chinese", "wubi", "shuangpin", "zhuyin",
                              "cangjie", "changjie", "scim", "itabc")

            for key in ("AppleEnabledInputSources", "AppleSelectedInputSources"):
                sources = payload.get(key, [])
                cleaned = []
                for src in sources:
                    if not isinstance(src, dict):
                        cleaned.append(src)
                        continue
                    # Combine all identifying fields for matching
                    all_ids = " ".join(str(v) for v in [
                        src.get("Input Mode", ""),
                        src.get("Bundle ID", ""),
                        src.get("KeyboardLayout Name", ""),
                    ]).lower()
                    # Keep RIME, remove system Chinese
                    if "rime" in all_ids:
                        cleaned.append(src)
                    elif any(kw in all_ids for kw in china_keywords):
                        label = src.get("Input Mode") or src.get("Bundle ID") or "unknown"
                        actions.append(f"{'[DRY RUN] Would remove' if dry_run else 'Removed'}: {label}")
                    else:
                        cleaned.append(src)
                payload[key] = cleaned

            if not dry_run and actions:
                plist_path.write_bytes(plistlib.dumps(payload))
                actions.append("Updated HIToolbox.plist — changes take effect after logout/restart")

        except Exception as e:
            actions.append(f"Failed to modify input sources: {e}")

    elif PLATFORM == "linux":
        if dry_run:
            actions.append("[DRY RUN] Would remove system Chinese IME from input sources")
        else:
            actions.append("Linux: Remove Chinese IME via Settings → Region & Language → Input Sources")
            actions.append("Keep only RIME after installing ibus-rime or fcitx5-rime")

    elif PLATFORM == "win32":
        if dry_run:
            actions.append("[DRY RUN] Would remove Microsoft Pinyin from language settings")
        else:
            # Try PowerShell removal
            r = run_shell('powershell -Command "Get-WinUserLanguageList"')
            actions.append("Windows: Remove Chinese IME from Settings → Time & Language → Language & Region")
            actions.append("Keep only Weasel after installing RIME")

    return actions or ["No system Chinese IME to remove"]


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


SAFE_DNS_SERVERS = ["8.8.8.8", "1.1.1.1"]


def set_static_dns() -> list[str]:
    """跨平台设置 DHCP 不可覆盖的静态 DNS。

    macOS:  networksetup 手动 DNS + scutil 覆盖 DHCP resolver
    Linux:  nmcli connection 锁定 DNS + ignore-auto-dns
    Windows: netsh 设置静态 DNS（不受 DHCP 影响）

    Returns:
        操作日志列表。
    """
    actions: list[str] = []

    if PLATFORM == "darwin":
        actions.extend(_set_static_dns_darwin())
    elif PLATFORM == "linux":
        actions.extend(_set_static_dns_linux())
    elif PLATFORM == "win32":
        actions.extend(_set_static_dns_windows())

    flush_dns_cache()
    actions.append("Flushed DNS cache")
    return actions


def _set_static_dns_darwin() -> list[str]:
    """macOS: 三层静态 DNS 防护。"""
    actions: list[str] = []

    # Layer 1: networksetup 手动 DNS（优先于 DHCP）
    r = run_shell("networksetup -listallnetworkservices")
    services = [
        s.strip().lstrip("*").strip()
        for s in r.stdout.splitlines()[1:]
        if s.strip() and not s.strip().startswith("*")
    ]

    for svc in services:
        dns_str = " ".join(SAFE_DNS_SERVERS)
        run_shell(f'networksetup -setdnsservers "{svc}" {dns_str}')
        actions.append(f"Set manual DNS on {svc}: {dns_str}")

    # Layer 2: scutil 直接覆盖 resolver（最强，DHCP 无法覆盖）
    resolver_dir = Path("/etc/resolver")
    if not resolver_dir.exists():
        run_shell("sudo mkdir -p /etc/resolver")
    # 默认 resolver 文件 - 所有未匹配的域名都走安全 DNS
    resolver_content = "\n".join(
        [f"nameserver {dns}" for dns in SAFE_DNS_SERVERS]
    ) + "\n"
    # 写入 /etc/resolver/default 需要 sudo
    # 改用 scutil 设置 DNS 配置（不需要写 /etc/resolver）
    scutil_script = (
        "d.init\n"
        "d.add ServerAddresses * " + " ".join(SAFE_DNS_SERVERS) + "\n"
        "d.add SearchDomains * local\n"
        "set State:/Network/Service/StaticDNS/DNS\n"
        "quit\n"
    )
    tmp_scutil = Path("/tmp/cc-check-scutil-dns.txt")
    tmp_scutil.write_text(scutil_script, encoding="utf-8")
    run_shell(f"sudo scutil < {tmp_scutil}")
    tmp_scutil.unlink(missing_ok=True)
    actions.append("Set scutil State:/Network/Service/StaticDNS/DNS")

    return actions


def _set_static_dns_linux() -> list[str]:
    """Linux: nmcli 锁定 DNS + ignore-auto-dns。"""
    actions: list[str] = []

    # 检测活跃的 NetworkManager 连接
    r = run_shell("nmcli -t -f NAME,TYPE,DEVICE connection show --active 2>/dev/null")
    if r.returncode != 0:
        # Fallback: 直接写 resolved.conf
        resolved_conf = Path("/etc/systemd/resolved.conf")
        if resolved_conf.exists():
            text = resolved_conf.read_text(errors="ignore")
            dns_line = f"DNS={' '.join(SAFE_DNS_SERVERS)}"
            if "[Resolve]" in text:
                # Replace or add DNS line
                import re as _re
                if _re.search(r"^DNS=", text, _re.MULTILINE):
                    text = _re.sub(r"^DNS=.*$", dns_line, text, flags=_re.MULTILINE)
                else:
                    text = text.replace("[Resolve]", f"[Resolve]\n{dns_line}")
            else:
                text += f"\n[Resolve]\n{dns_line}\n"
            run_shell(f"echo '{text}' | sudo tee /etc/systemd/resolved.conf > /dev/null")
            run_shell("sudo systemctl restart systemd-resolved 2>/dev/null || true")
            actions.append(f"Set resolved.conf DNS: {dns_line}")
        return actions

    connections = []
    for line in r.stdout.strip().splitlines():
        parts = line.split(":")
        if len(parts) >= 3 and parts[2]:  # has active device
            connections.append(parts[0])

    dns_str = " ".join(SAFE_DNS_SERVERS)
    for conn in connections:
        # 设置静态 DNS
        run_shell(f'nmcli connection modify "{conn}" ipv4.dns "{dns_str}"')
        # 关键：ignore-auto-dns 阻止 DHCP 覆盖
        run_shell(f'nmcli connection modify "{conn}" ipv4.ignore-auto-dns yes')
        # 应用修改
        run_shell(f'nmcli connection up "{conn}" 2>/dev/null || true')
        actions.append(f"Locked DNS on {conn}: {dns_str} (ignore-auto-dns=yes)")

    return actions


def _set_static_dns_windows() -> list[str]:
    """Windows: netsh 设置静态 DNS（不受 DHCP 影响）。"""
    actions: list[str] = []

    # 获取活跃的网络适配器
    r = run_shell(
        'Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | '
        'Select-Object -ExpandProperty Name'
    )
    if r.returncode != 0:
        return ["Failed to enumerate network adapters"]

    adapters = [a.strip() for a in r.stdout.strip().splitlines() if a.strip()]
    for adapter in adapters:
        # netsh 设置静态 DNS（优先级高于 DHCP）
        primary = SAFE_DNS_SERVERS[0]
        secondary = SAFE_DNS_SERVERS[1] if len(SAFE_DNS_SERVERS) > 1 else ""
        run_shell(
            f'netsh interface ip set dns name="{adapter}" static {primary} primary'
        )
        if secondary:
            run_shell(
                f'netsh interface ip add dns name="{adapter}" {secondary} index=2'
            )
        actions.append(f"Set static DNS on {adapter}: {', '.join(SAFE_DNS_SERVERS)}")

    return actions


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


# ---------------------------------------------------------------------------
# Extended checks: GOPROXY, Docker, Git remotes, VS Code, SSH, Fonts
# ---------------------------------------------------------------------------

CHINA_MIRROR_PATTERNS = [
    "goproxy.cn", "goproxy.io", "mirrors.aliyun", "mirrors.tencent",
    "mirrors.ustc", "mirrors.tuna", "npmmirror", "cnpm",
    "douban", "huaweicloud",
]

CHINA_GIT_HOSTS = [
    "gitee.com", "coding.net", "gitcode.net", "jihulab.com",
    "codechina.csdn.net",
]

# Chinese-specific fonts that are NOT bundled in standard US macOS/Linux/Windows
CHINA_FONTS_FINGERPRINT = [
    "STHeiti", "STSong", "STFangsong", "STKaiti",
    "SimSun", "SimHei", "FangSong", "KaiTi",
    "Microsoft YaHei", "Microsoft JhengHei",
    "WenQuanYi", "Noto Sans CJK SC", "Noto Serif CJK SC",
    "Source Han Sans SC", "Source Han Serif SC",
]

# macOS-bundled CJK fonts (these come with every macOS regardless of language)
MACOS_BUNDLED_CJK = {
    "PingFang SC", "PingFang TC", "PingFang HK",
    "STHeiti", "Heiti SC", "Heiti TC",
    "Hiragino Sans GB", "Apple SD Gothic Neo",
    "Apple LiGothic", "Apple LiSung",
}


def check_goproxy() -> dict[str, Any]:
    """检查 Go 代理是否指向中国镜像。"""
    r = run_shell("go env GOPROXY 2>/dev/null")
    if r.returncode != 0:
        return {"installed": False, "proxy": None, "china": False}
    proxy = r.stdout.strip()
    china = any(p in proxy.lower() for p in CHINA_MIRROR_PATTERNS)
    return {"installed": True, "proxy": proxy, "china": china}


def check_docker_mirrors() -> dict[str, Any]:
    """检查 Docker daemon.json 是否配置了中国镜像。"""
    result: dict[str, Any] = {"found": False, "mirrors": [], "china": False}
    daemon_paths = []

    if PLATFORM == "darwin":
        daemon_paths.append(Path.home() / ".docker" / "daemon.json")
    elif PLATFORM == "linux":
        daemon_paths.extend([
            Path("/etc/docker/daemon.json"),
            Path.home() / ".docker" / "daemon.json",
        ])
    elif PLATFORM == "win32":
        daemon_paths.append(Path.home() / ".docker" / "daemon.json")

    for dp in daemon_paths:
        if not dp.exists():
            continue
        try:
            data = json.loads(dp.read_text(errors="ignore"))
            mirrors = data.get("registry-mirrors", [])
            if mirrors:
                result["found"] = True
                result["mirrors"] = mirrors
                result["china"] = any(
                    any(p in m.lower() for p in CHINA_MIRROR_PATTERNS)
                    for m in mirrors
                )
                result["path"] = str(dp)
                break
        except Exception:
            continue
    return result


def scan_git_remotes() -> list[str]:
    """扫描常见项目目录中的 git remote，查找中国 Git 托管服务。"""
    china_remotes: list[str] = []
    home = Path.home()
    search_dirs = [home]

    # Also check common dev directories
    for d in ["Projects", "Developer", "Code", "repos", "workspace", "src"]:
        p = home / d
        if p.is_dir():
            search_dirs.append(p)

    seen: set[str] = set()
    for base in search_dirs:
        try:
            # Only scan 2 levels deep to avoid slowness
            git_dirs = list(base.glob("*/.git")) + list(base.glob("*/*/.git"))
        except (PermissionError, OSError):
            continue
        for git_dir in git_dirs:
            repo = git_dir.parent
            repo_str = str(repo)
            if repo_str in seen:
                continue
            seen.add(repo_str)
            r = run_shell(f'git -C "{repo}" remote -v 2>/dev/null')
            if r.returncode != 0:
                continue
            for line in r.stdout.splitlines():
                lower = line.lower()
                for host in CHINA_GIT_HOSTS:
                    if host in lower:
                        china_remotes.append(f"{repo.name}: {line.split()[1]}")
                        break
    return china_remotes


def check_vscode_locale() -> dict[str, Any]:
    """检查 VS Code 的 locale 设置。"""
    result: dict[str, Any] = {"found": False, "locale": None, "china": False}
    settings_paths = []

    if PLATFORM == "darwin":
        settings_paths.append(
            Path.home() / "Library/Application Support/Code/User/settings.json"
        )
    elif PLATFORM == "linux":
        settings_paths.append(
            Path.home() / ".config/Code/User/settings.json"
        )
    elif PLATFORM == "win32":
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            settings_paths.append(Path(appdata) / "Code/User/settings.json")

    # Also check locale.json (VS Code's language override)
    for sp in list(settings_paths):
        locale_json = sp.parent / "locale.json"
        if locale_json not in settings_paths:
            settings_paths.append(locale_json)

    for sp in settings_paths:
        if not sp.exists():
            continue
        try:
            text = sp.read_text(errors="ignore")
            # Handle JSONC (with comments)
            text_clean = re.sub(r'//.*$', '', text, flags=re.MULTILINE)
            data = json.loads(text_clean)
            locale = data.get("locale") or data.get("vscode.locale")
            if locale:
                result["found"] = True
                result["locale"] = locale
                result["china"] = locale.lower().startswith("zh")
                result["path"] = str(sp)
                break
        except Exception:
            continue
    return result


def scan_ssh_known_hosts() -> list[str]:
    """扫描 SSH known_hosts 中的中国 IP/域名。"""
    hits: list[str] = []
    kh = Path.home() / ".ssh" / "known_hosts"
    if not kh.exists():
        return hits

    # China IP ranges (major blocks)
    china_ip_prefixes = [
        "1.0.", "1.1.", "1.2.", "1.4.", "1.8.",
        "14.", "27.", "36.", "39.", "42.",
        "49.", "58.", "59.", "60.", "61.",
        "101.", "106.", "110.", "111.", "112.",
        "113.", "114.", "115.", "116.", "117.",
        "118.", "119.", "120.", "121.", "122.",
        "123.", "124.", "125.", "139.", "140.",
        "150.", "153.", "157.", "163.", "171.",
        "175.", "180.", "182.", "183.", "202.",
        "210.", "211.", "218.", "219.", "220.",
        "221.", "222.", "223.",
    ]
    china_domains = [".cn", ".com.cn", "aliyun", "tencent", "huawei"]

    try:
        text = kh.read_text(errors="ignore")
        for line in text.splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            host_part = line.split()[0] if line.split() else ""
            lower_host = host_part.lower()

            # Check domains
            if any(d in lower_host for d in china_domains):
                hits.append(host_part)
                continue

            # Check IP prefixes (only first host field)
            for prefix in china_ip_prefixes:
                if host_part.startswith(prefix) or host_part.startswith(f"[{prefix}"):
                    hits.append(host_part)
                    break
    except Exception:
        pass
    return hits


def check_system_fonts() -> dict[str, Any]:
    """检查系统是否安装了暴露中文环境的字体。"""
    result: dict[str, Any] = {"china_fonts": [], "total_cjk": 0}

    if PLATFORM == "darwin":
        r = run_shell("system_profiler SPFontsDataType 2>/dev/null | grep 'Full Name:'")
        if r.returncode == 0:
            fonts = [line.split(":", 1)[1].strip() for line in r.stdout.splitlines() if ":" in line]
        else:
            # Fallback: check font directories
            fonts = []
            for font_dir in [Path("/Library/Fonts"), Path.home() / "Library/Fonts"]:
                if font_dir.exists():
                    fonts.extend(f.stem for f in font_dir.iterdir() if f.suffix in (".ttf", ".otf", ".ttc"))

    elif PLATFORM == "linux":
        r = run_shell("fc-list :lang=zh family 2>/dev/null")
        if r.returncode == 0:
            fonts = [line.strip() for line in r.stdout.splitlines() if line.strip()]
        else:
            fonts = []

    elif PLATFORM == "win32":
        fonts_dir = Path(os.environ.get("WINDIR", "C:\\Windows")) / "Fonts"
        fonts = []
        if fonts_dir.exists():
            fonts = [f.stem for f in fonts_dir.iterdir() if f.suffix in (".ttf", ".otf", ".ttc")]
    else:
        fonts = []

    for font_name in CHINA_FONTS_FINGERPRINT:
        matches = [f for f in fonts if font_name.lower() in f.lower()]
        if matches:
            # On macOS, skip bundled CJK fonts
            if PLATFORM == "darwin" and font_name in MACOS_BUNDLED_CJK:
                continue
            result["china_fonts"].append(font_name)

    result["total_cjk"] = len(result["china_fonts"])
    return result

