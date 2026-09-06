"""ScannerStatus 직렬화 dict 읽기 헬퍼(I2, 최종 리뷰).

정본 직렬화는 `asdict(ScannerStatus)` → `tool/status/tool_version/duration_s/message` 5키다
(spec 원칙 5, secscan/models.py). 이 브랜치 개발 중 `tools/verify/evidence.py` 가 한동안 손으로
`tool`/`error` 2키만(V1 초기 meta.json, tool_version/duration_s 없음)로 썼던 흔적이 옛 증거에
남을 수 있다 — 이 모듈이 그 옛 표기(그리고 아주 초기의 `name`/`error`)를 5키로 정규화하는
유일한 경로다. 소비자는 `meta["scanner_status"]` 를 직접 읽지 않고 이 함수만 쓴다.
"""

from __future__ import annotations


def status_rows(meta: dict) -> list[dict]:
    """`meta["scanner_status"]` 를 canonical 5키(tool/status/tool_version/duration_s/message)로."""
    out: list[dict] = []
    for s in meta.get("scanner_status", []) or []:
        out.append({
            "tool": s.get("tool") or s.get("name", ""),
            "status": s.get("status", ""),
            "tool_version": s.get("tool_version"),
            "duration_s": s.get("duration_s"),
            "message": s.get("message") or s.get("error", ""),
        })
    return out
