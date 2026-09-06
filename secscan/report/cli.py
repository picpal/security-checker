"""`secscan report` — findings.json(+bom, +interpretations) → 5 시트 워크북. LLM 없이 완성된다."""
from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from ..models import Finding, Location
from ..output.json_io import from_json
from ..output.xlsx import Sheet
from .deppath import DepGraph, deppaths_for
from .derive import derive_all
from .interpret import build_request, load_interpretations
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


def build_report_with_request(findings: list[Finding], meta: dict, *, target: str | None = None,
                              bom: str | Path | None = None, interpretations: str | Path | None = None,
                              findings_path: str = "findings.json") -> tuple[dict[str, Sheet], dict, dict]:
    target = target or meta.get("target")
    fs = relativize(findings, target)
    kbs = {f.id: entry_for(f) for f in fs}
    deppaths = deppaths_for(fs, DepGraph.from_path(bom)) if bom is not None else None
    derived = derive_all(fs, kbs, deppaths)
    request = build_request(fs, derived, kbs, target=str(target or ""), findings_path=findings_path)
    interps, interp_meta = ({}, {"status": "absent", "rejected": []}) if interpretations is None \
        else load_interpretations(interpretations, request)
    meta = {**meta, "target": target or meta.get("target", "")}
    return build_report_sheets(fs, meta, kbs, derived, interps, interp_meta), request, interp_meta


def build_report(findings: list[Finding], meta: dict, *, target: str | None = None, deppaths: dict[str, str] | None = None,
                 bom: str | Path | None = None, interpretations: str | Path | None = None,
                 interps: dict[str, Interpretation] | None = None,
                 interp_meta: dict | None = None) -> dict[str, Sheet]:
    """호환 래퍼 — Task 5·7 테스트가 쓰는 시그니처. deppaths/interps 를 직접 주면 bom/interpretations 보다 우선."""
    if deppaths is None and interps is None and interp_meta is None:
        return build_report_with_request(findings, meta, target=target, bom=bom, interpretations=interpretations)[0]
    target = target or meta.get("target")
    fs = relativize(findings, target)
    kbs = {f.id: entry_for(f) for f in fs}
    # relativize 로 id 가 바뀔 수 있다(dedup_key 에 경로 포함) — deppaths/interps 는 새 id 기준으로 넘겨야 한다.
    derived = derive_all(fs, kbs, deppaths)
    meta = {**meta, "target": target or meta.get("target", "")}
    return build_report_sheets(fs, meta, kbs, derived, interps, interp_meta)


def write_report_bundle(findings: list[Finding], meta: dict, out_dir, *, target: str | None = None,
                        bom: str | Path | None = None, interpretations: str | Path | None = None,
                        findings_path: str = "findings.json", prefer_xlsx: bool | None = None) -> tuple[list[Path], str | None]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    sheets, request, _ = build_report_with_request(findings, meta, target=target, bom=bom, interpretations=interpretations,
                                                   findings_path=findings_path)
    paths, warn = write_report(sheets, out, created=str(meta.get("run_date", "")), prefer_xlsx=prefer_xlsx)
    rq = out / "report-request.json"
    rq.write_text(json.dumps(request, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return paths + [rq], warn


def add_report_parser(sub) -> None:
    rp = sub.add_parser("report", help="사람·LLM 겸용 보고서 워크북 생성")
    rp.add_argument("--findings", help="scan 이 낸 findings.json 경로")
    rp.add_argument("--target", help="경로 상대화 기준(기본: findings.json meta.target)")
    rp.add_argument("--bom", help="cdxgen BOM(bom.cdx.json). 없으면 의존 경로 열은 'BOM 없음'")
    rp.add_argument("--interpretations", help="Claude 가 쓴 interpretations.json. 검증 통과분만 병합")
    rp.add_argument("--out", default="out", help="출력 디렉토리")


def cmd_report(args) -> int:
    if not args.findings:
        print("secscan report: --findings 가 필요합니다")
        return 2
    text = Path(args.findings).read_text(encoding="utf-8")
    findings, meta = from_json(text), json.loads(text).get("meta", {})
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    paths, warn = write_report_bundle(findings, meta, out, target=args.target, bom=args.bom,
                                      interpretations=args.interpretations, findings_path=args.findings)
    if warn:
        print(f"⚠️ {warn}")
    print("출력: " + " · ".join(str(p) for p in paths))
    return 0
