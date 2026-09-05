"""출력 전 안정 정렬(spec §7.1) — 모든 projection 이 같은 순서를 본다(결정성)."""
from __future__ import annotations

from ..models import REACHABLE, UNKNOWN, UNREACHABLE, Finding, severity_rank

_REACH_RANK = {REACHABLE: 2, UNKNOWN: 1, UNREACHABLE: 0}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (f.category, -severity_rank(f.severity),
                                           -_REACH_RANK.get(f.reachability.status, 1), f.dedup_key))
