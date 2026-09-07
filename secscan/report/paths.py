"""경로 상대화 — `cli.py`·`result_check.py` 공유(순환 import 방지, spec §12(f))."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from ..models import Finding


def _rel(p: str, target: str | None) -> str:
    if not p or not target:
        return p
    prefix = str(Path(target)) .rstrip("/") + "/"
    return p[len(prefix):] if p.startswith(prefix) else p


def relativize(findings: list[Finding], target: str | None) -> list[Finding]:
    out = []
    for f in findings:
        loc = replace(f.location, file=_rel(f.location.file, target)) if f.location else None
        out.append(replace(f, location=loc, source=_rel(f.source, target)))
    return out
