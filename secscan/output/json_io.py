"""findings.json — typed Finding 의 lossless canonical 직렬화 (spec §7.2).

SARIF/markdown/xlsx 는 projection(손실 있음)이고, 이 파일만 내부 모델을 그대로 담는다.
dataclasses.fields 기반이라 모델에 필드가 추가되면 자동으로 따라온다(단, 중첩 타입은
_NESTED 표에 등록해야 복원된다).
"""

from __future__ import annotations

import json
from dataclasses import fields, is_dataclass

from ..models import (
    Advisory, Compliance, Component, Consensus, Cvss, Finding, KisaWeakness, Location,
    Occurrence, Reachability, Suppression,
)

CONTEXT = "secscan-findings/v1"

# Finding 필드명 → 중첩 dataclass. tuple[dataclass] 은 (cls, "seq") 로 표기.
_NESTED: dict[str, object] = {
    "component": Component, "advisory": Advisory, "location": Location,
    "reachability": Reachability, "consensus": Consensus, "suppression": Suppression,
    "compliance": Compliance, "occurrences": (Occurrence, "seq"),
}
# (부모 dataclass, 필드명) → 원소 dataclass. 중첩 안의 tuple[dataclass] 복원용.
_SEQ: dict[tuple[type, str], type] = {(Compliance, "kisa"): KisaWeakness, (Advisory, "cvss"): Cvss}


def _plain(obj):
    if is_dataclass(obj):
        return {f.name: _plain(getattr(obj, f.name)) for f in fields(obj)}
    if isinstance(obj, (list, tuple)):
        return [_plain(x) for x in obj]
    return obj


def _build(cls, data):
    if data is None:
        return None
    kwargs = {}
    for f in fields(cls):
        if f.name not in data:
            continue
        v = data[f.name]
        seq_cls = _SEQ.get((cls, f.name))
        if seq_cls is not None:
            v = tuple(_build(seq_cls, x) for x in (v or []))
        elif isinstance(v, list):
            v = tuple(v)
        kwargs[f.name] = v
    return cls(**kwargs)


def _build_field(spec, v):
    if isinstance(spec, tuple):  # (cls, "seq")
        return tuple(_build(spec[0], x) for x in (v or []))
    return _build(spec, v)


def finding_to_dict(f: Finding) -> dict:
    d = _plain(f)
    d["id"] = f.id
    d["dedup_key"] = f.dedup_key
    return d


def finding_from_dict(d: dict) -> Finding:
    known = {f.name for f in fields(Finding)}
    kwargs = {}
    for name, v in d.items():
        if name not in known:
            continue  # id/dedup_key(파생)·미래 필드 무시
        if name in _NESTED:
            v = _build_field(_NESTED[name], v)
        elif isinstance(v, list):
            v = tuple(v)
        kwargs[name] = v
    return Finding(**kwargs)


def to_json(findings: list[Finding], *, meta: dict | None = None) -> str:
    doc = {"@context": CONTEXT, "meta": meta or {},
           "findings": [finding_to_dict(f) for f in findings]}
    return json.dumps(doc, indent=2, ensure_ascii=False, sort_keys=False)


def from_json(text: str) -> list[Finding]:
    doc = json.loads(text)
    if doc.get("@context") != CONTEXT:
        raise ValueError(f"findings.json 컨텍스트 불일치: {doc.get('@context')}")
    return [finding_from_dict(d) for d in doc.get("findings", [])]
