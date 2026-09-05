"""trivy JSON 순회 단일화(최종 리뷰 M1). 제품 코드(secscan/normalize/trivy.py)는 건드리지 않는다."""
from __future__ import annotations

import json
from typing import Iterator


def iter_vulns(payload) -> Iterator[tuple[str, dict]]:
    data = json.loads(payload) if isinstance(payload, str) else (payload or {})
    for res in data.get("Results", []) or []:
        for v in res.get("Vulnerabilities") or []:
            yield res.get("Target", ""), v
