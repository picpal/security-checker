"""`secscan report` — findings.json(+bom, +interpretations) → 5 시트 워크북. LLM 없이 완성된다."""
from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from ..models import Finding, Location
from ..output.json_io import from_json
from ..output.xlsx import Sheet
from .derive import derive_all
from .kb import entry_for
from .models import Interpretation
from .workbook import build_report_sheets, write_report


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


def build_report(findings: list[Finding], meta: dict, *, target: str | None = None, deppaths: dict[str, str] | None = None,
                 interps: dict[str, Interpretation] | None = None, interp_meta: dict | None = None) -> dict[str, Sheet]:
    target = target or meta.get("target")
    fs = relativize(findings, target)
    kbs = {f.id: entry_for(f) for f in fs}
    # relativize 로 id 가 바뀔 수 있다(dedup_key 에 경로 포함) — deppaths/interps 는 새 id 기준으로 넘겨야 한다.
    derived = derive_all(fs, kbs, deppaths)
    meta = {**meta, "target": target or meta.get("target", "")}
    return build_report_sheets(fs, meta, kbs, derived, interps, interp_meta)


def write_report_bundle(findings: list[Finding], meta: dict, out_dir, *, target: str | None = None,
                        deppaths: dict[str, str] | None = None, interps: dict[str, Interpretation] | None = None,
                        interp_meta: dict | None = None, prefer_xlsx: bool | None = None) -> tuple[list[Path], str | None]:
    sheets = build_report(findings, meta, target=target, deppaths=deppaths, interps=interps, interp_meta=interp_meta)
    return write_report(sheets, out_dir, created=str(meta.get("run_date", "")), prefer_xlsx=prefer_xlsx)


def add_report_parser(sub) -> None:
    rp = sub.add_parser("report", help="사람·LLM 겸용 보고서 워크북 생성")
    rp.add_argument("--findings", help="scan 이 낸 findings.json 경로")
    rp.add_argument("--target", help="경로 상대화 기준(기본: findings.json meta.target)")
    rp.add_argument("--out", default="out", help="출력 디렉토리")


def cmd_report(args) -> int:
    if not args.findings:
        print("secscan report: --findings 가 필요합니다")
        return 2
    text = Path(args.findings).read_text(encoding="utf-8")
    findings, meta = from_json(text), json.loads(text).get("meta", {})
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    paths, warn = write_report_bundle(findings, meta, out, target=args.target)
    if warn:
        print(f"⚠️ {warn}")
    print("출력: " + " · ".join(str(p) for p in paths))
    return 0
