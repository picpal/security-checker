"""경로 기반 finding 제외 — 모든 스캐너에 공통 적용되는 사후 필터.

스캐너마다 exclude 플래그가 제각각(osv 는 빈약)이라, 정규화된 finding 의 경로로
한 번에 거른다. 매칭은 절대/상대 경로 모두에 직관적으로 동작하도록:
- fnmatch 전체 경로 / '*/<pat>' / 경로 세그먼트 일치 / 세그먼트별 fnmatch
"""

from __future__ import annotations

from fnmatch import fnmatch
from pathlib import PurePath


def _finding_path(f) -> str:
    if f.location and f.location.file:
        return f.location.file
    return f.source or ""


def path_excluded(path: str, patterns) -> bool:
    if not path or not patterns:
        return False
    parts = PurePath(path).parts
    for pat in patterns:
        if fnmatch(path, pat):
            return True
        if fnmatch(path, f"*/{pat}"):
            return True
        if pat in parts:  # 'fixtures' 같은 맨이름
            return True
        if any(fnmatch(part, pat) for part in parts):
            return True
    return False


def exclude_findings(findings, patterns):
    if not patterns:
        return findings
    return [f for f in findings if not path_excluded(_finding_path(f), patterns)]
