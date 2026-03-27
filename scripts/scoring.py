#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CC-check v1.3.0 评分系统。

将每个 Finding 映射到分值，汇总生成百分制报告。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# ---------------------------------------------------------------------------
# 权重定义（总分 100）
# ---------------------------------------------------------------------------

# 权重定义 — 各组权重之和 = 100
# IP质量 30 > DNS 15 > System 21 > Network 10 > Clash 8 > Packages 6 > Privacy 6 > Node.js 2 > VPN 0 > Identity 1 > Claude 1
WEIGHTS: dict[str, dict[str, int]] = {
    "ip-quality": {
        "classification": 30,             # 最高优先级：IP 类型/风险/ISP 直接决定 API 风控结果
    },
    "dns": {
        "dns-google": 7,                  # Google DNS whoami 泄露中国 ISP 是最高风险
        "dns-cloudflare": 4,              # Cloudflare DNS 一致性
        "system-dns-display": 4,          # 系统 DNS 展示清洁度
    },
    "system": {
        "timezone": 5,                    # TZ 对齐
        "locale": 5,                      # Locale 对齐
        "proxy-env": 3,                   # 代理环境变量
        "system-languages": 2,            # 系统语言
        "measurement-units": 1,           # 度量单位
        "time-format": 1,                 # 时间格式
        "hostname": 1,                    # 主机名
        "input-method": 1,               # 输入法
        "hosts-file": 1,                  # hosts 文件
        "user-identity": 1,               # 用户名
        "vscode-locale": 0,               # VS Code 语言（信息性）
        "font-fingerprint": 0,            # 字体指纹（信息性）
    },
    "network": {
        "public-ip": 5,                   # 公网 IP 可达
        "multi-source-ip": 3,             # 多源 IP 一致
        "ipv6-leak": 2,                   # IPv6 泄露
    },
    "clash": {
        "process": 2,                     # 进程运行
        "mode": 1,                        # 模式非 direct
        "tun-enabled": 2,                 # TUN 开启
        "runtime-markers": 2,             # 配置标记
        "dns-cleanup-watchdog": 1,        # DNS 清理守护
    },
    "packages": {
        "npm-registry": 2,                # npm 镜像
        "pip-index": 1,                   # pip 镜像
        "brew-mirrors": 1,                # brew 镜像
        "china-mirror-residue": 2,        # 中国镜像残留
        "goproxy": 0,                     # GOPROXY（信息性）
        "docker-mirror": 0,               # Docker 镜像源（信息性）
    },
    "privacy": {
        "telemetry": 2,                   # 遥测目录
        "privacy-env": 2,                 # 隐私环境变量
        "session-residue": 1,             # 会话残留
        "shell-history": 1,               # 历史记录
        "ssh-known-hosts": 0,             # SSH 已知主机（信息性）
    },
    "nodejs": {
        "node-tz": 1,                     # Node.js 时区
        "node-locale": 1,                 # Node.js locale
    },
    "vpn": {
        "project-root": 0,                # 检测到即可，不计分
        "unit-tests": 0,                  # 不影响环境评分
        "generated-subscription": 0,      # VPN 项目状态不影响本地环境分
        "public-subscription": 0,
        "remote-service": 0,
        "remote-listener": 0,
    },
    "identity": {
        "git-identity": 1,                # 低风险
        "git-remotes": 0,                 # Git 远程仓库（信息性）
    },
    "claude": {
        "language": 1,                    # 设置文件
    },
}
# 总分验证:
# ip(30) + dns(7+4+4=15) + sys(5+5+3+2+1+1+1+1+1+1=21) + net(5+3+2=10) + clash(2+1+2+2+1=8)
# + pkg(2+1+1+2=6) + priv(2+2+1+1=6) + node(1+1=2) + vpn(0) + id(1) + claude(1) = 100 ✓


@dataclass
class GroupScore:
    group: str
    earned: float
    max_points: int
    percentage: float


@dataclass
class ScoreReport:
    total_score: int
    max_score: int
    percentage: float
    grade: str
    groups: list[GroupScore]


def _get_weight(group: str, key: str) -> int:
    return WEIGHTS.get(group, {}).get(key, 0)


def compute_score(findings: list[Any]) -> ScoreReport:
    """根据 findings 计算评分。"""
    group_earned: dict[str, float] = {}
    group_max: dict[str, int] = {}

    for f in findings:
        w = _get_weight(f.group, f.key)
        if w == 0:
            continue
        group_max[f.group] = group_max.get(f.group, 0) + w
        if f.status == "pass":
            group_earned[f.group] = group_earned.get(f.group, 0) + w
        elif f.status == "warn":
            group_earned[f.group] = group_earned.get(f.group, 0) + w * 0.7
        elif f.status == "skip":
            group_earned[f.group] = group_earned.get(f.group, 0) + w * 0.5

    # 满分始终为 100
    total_max = 100
    total_earned = sum(group_earned.values())
    percentage = round(total_earned / total_max * 100, 1) if total_max > 0 else 0

    groups = []
    for g in sorted(group_max.keys()):
        mx = group_max[g]
        earned = group_earned.get(g, 0)
        pct = round(earned / mx * 100, 1) if mx > 0 else 0
        groups.append(GroupScore(group=g, earned=earned, max_points=mx, percentage=pct))

    grade = _grade(percentage)
    return ScoreReport(
        total_score=round(total_earned),
        max_score=total_max,
        percentage=percentage,
        grade=grade,
        groups=groups,
    )


def _grade(pct: float) -> str:
    if pct >= 95:
        return "A+"
    if pct >= 90:
        return "A"
    if pct >= 80:
        return "B"
    if pct >= 70:
        return "C"
    if pct >= 60:
        return "D"
    return "F"


def format_score_report(report: ScoreReport) -> str:
    """生成可视化评分报告。"""
    lines: list[str] = []
    lines.append("")
    lines.append("╔════════════════════════════════════════════╗")
    lines.append(f"║  CC-Check Score: {report.total_score:>3} / {report.max_score:<3}  Grade: {report.grade:<3}  ({report.percentage}%)  ║")
    lines.append("╠════════════════════════════════════════════╣")
    for g in report.groups:
        bar_len = 10
        filled = round(g.percentage / 100 * bar_len)
        bar = "█" * filled + "░" * (bar_len - filled)
        label = f"{g.group:<12}"
        score = f"{g.earned:>4.0f}/{g.max_points:<3}"
        pct = f"{g.percentage:>5.1f}%"
        lines.append(f"║  {label} {score}  {bar}  {pct}  ║")
    lines.append("╚════════════════════════════════════════════╝")
    lines.append("")
    return "\n".join(lines)
