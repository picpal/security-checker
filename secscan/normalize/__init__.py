"""정규화 레이어 — 원시 스캐너 출력을 typed Finding 으로 (이 프로젝트의 심장).

결정적: 같은 입력이면 같은 출력. 단위 테스트(골든) 1순위.
"""

from __future__ import annotations

from ..adapters.base import OK, RawResult
from .merge import merge_consensus
from .osv import parse_osv
from .trivy import parse_trivy

# 도구명 → 파서. 새 스캐너 = 여기 한 줄 + 파서 모듈 추가.
_PARSERS = {
    "trivy": parse_trivy,
    "osv-scanner": parse_osv,
}


def to_findings(raw_results: list[RawResult]):
    """성공한 RawResult 만 정규화·병합. 실패/타임아웃은 건너뛴다(부분 실패는 별도 보고)."""
    findings = []
    for r in raw_results:
        if r.status != OK:
            continue
        parser = _PARSERS.get(r.tool)
        if parser:
            findings.extend(parser(r.payload, tool_version=r.version))
    return merge_consensus(findings)

