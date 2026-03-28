#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Browser leak automation scoring for CC-Check."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

WEIGHTS: dict[str, int] = {
    "webrtc-leak": 16,
    "webrtc-local-ip": 10,
    "js-locale": 8,
    "js-timezone": 8,
    "js-languages": 4,
    "browser-multi-endpoint-consistency": 8,
    "browser-python-egress-alignment": 12,
    "china-fonts": 5,
    "canvas-fingerprint": 4,
    "canvas-fingerprint-stability": 5,
    "webgl-vendor": 4,
    "webgl-renderer": 8,
    "tls-browser-version": 4,
    "tls-browser-legacy": 4,
}


@dataclass
class BrowserGroupScore:
    group: str
    earned: float
    max_points: int
    percentage: float


@dataclass
class BrowserScoreReport:
    total_score: int
    max_score: int
    percentage: float
    grade: str
    groups: list[BrowserGroupScore]


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


def _earned_points(status: str, weight: int) -> float:
    if status == "pass":
        return float(weight)
    if status == "warn":
        return weight * 0.7
    if status == "skip":
        return weight * 0.5
    return 0.0


def compute_browser_score(findings: list[Any]) -> BrowserScoreReport:
    """根据浏览器自动化 findings 计算百分制得分。"""
    group_earned: dict[str, float] = {}
    group_max: dict[str, int] = {}

    for finding in findings:
        weight = WEIGHTS.get(finding.key, 0)
        if weight == 0:
            continue
        group = getattr(finding, "test", "other")
        group_max[group] = group_max.get(group, 0) + weight
        group_earned[group] = group_earned.get(group, 0.0) + _earned_points(getattr(finding, "status", "fail"), weight)

    total_max = sum(group_max.values())
    total_earned = sum(group_earned.values())
    percentage = round(total_earned / total_max * 100, 1) if total_max else 0.0

    groups = []
    for group in sorted(group_max.keys()):
        earned = group_earned.get(group, 0.0)
        max_points = group_max[group]
        pct = round(earned / max_points * 100, 1) if max_points else 0.0
        groups.append(BrowserGroupScore(group=group, earned=earned, max_points=max_points, percentage=pct))

    return BrowserScoreReport(
        total_score=round(total_earned),
        max_score=total_max,
        percentage=percentage,
        grade=_grade(percentage),
        groups=groups,
    )


def build_browser_score_payload(report: BrowserScoreReport) -> dict[str, Any]:
    """把浏览器评分报告转成 JSON 友好的结构。"""
    return {
        "total_score": report.total_score,
        "max_score": report.max_score,
        "percentage": report.percentage,
        "grade": report.grade,
        "groups": [
            {
                "group": group.group,
                "earned": round(group.earned, 1),
                "max_points": group.max_points,
                "percentage": group.percentage,
            }
            for group in report.groups
        ],
    }
