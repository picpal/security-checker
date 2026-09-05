"""facts*.json 직렬화 — 4곳에 복제된 포맷을 한 곳에 고정한다(spec §4.5, 리뷰 M2)."""

from __future__ import annotations

import json


def facts_text(d: dict) -> str:
    """정본 facts dict → 파일에 쓸 텍스트. 모든 facts*.json 생성기가 이 함수 하나만 쓴다."""
    return json.dumps(d, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
