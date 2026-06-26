"""억제·baseline 영속화 — git 추적·감사 가능한 JSON (OpenVEX 영감).

baseline: 기존 finding 키 집합을 저장해 재스캔 시 신규만 표면화한다.
suppression: 사람이 확정한 억제 엔트리 목록.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from ..models import Finding, Suppression


def save_suppressions(path, suppressions: list[Suppression]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    data = {"@context": "secscan-suppressions/v1", "suppressions": [asdict(s) for s in suppressions]}
    p.write_text(json.dumps(data, indent=2, ensure_ascii=False))


def load_suppressions(path) -> list[Suppression]:
    p = Path(path)
    if not p.exists():
        return []
    data = json.loads(p.read_text())
    return [Suppression(**entry) for entry in data.get("suppressions", [])]


def save_baseline(path, findings: list[Finding]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    keys = sorted({f.dedup_key for f in findings})
    p.write_text(json.dumps({"keys": keys}, indent=2, ensure_ascii=False))


def load_baseline(path) -> set[str]:
    p = Path(path)
    if not p.exists():
        return set()
    return set(json.loads(p.read_text()).get("keys", []))


def apply_baseline(findings: list[Finding], baseline_keys: set[str]) -> list[Finding]:
    from dataclasses import replace

    out = []
    for f in findings:
        if f.dedup_key in baseline_keys and f.suppression is None:
            out.append(replace(f, suppression=Suppression(
                state="baseline", reason="baseline 등록된 기존 이슈",
                provenance="baseline file", evidence="이전 스캔에서 확인됨",
                expiry=None, scope=f.dedup_key, basis="baseline",
            )))
        else:
            out.append(f)
    return out
