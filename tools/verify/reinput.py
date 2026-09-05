"""V1 증거(옛 바이너리) raw 출력을 새 파이프라인에 재입력한다(spec §4.4 2단계 — baseline 이동 방지).

스캐너를 다시 돌리지 않는다. raw/*.json|sarif → normalize_each → merge → 기본 경로 제외 →
도달성은 V1 findings.json 의 판정을 dedup_key 로 carry-over(대상 트리·슬라이스가 없으므로) → 판정 H → 정렬.
`.gitignore` 기반 제외는 대상 트리가 없어 적용하지 않는다(meta.reinput_note 에 명시).
"""
from __future__ import annotations

import json
from dataclasses import asdict, replace
from pathlib import Path

from secscan.adapters.base import OK, RawResult
from secscan.disposition import decide
from secscan.exclude import DEFAULT_EXCLUDES, exclude_findings
from secscan.normalize import normalize_each
from secscan.normalize.merge import merge_consensus
from secscan.output.json_io import from_json, to_json
from secscan.output.markdown import to_markdown
from secscan.output.order import sort_findings
from secscan.output.sarif import to_sarif
from secscan.scan import TraceSink

_SKIP_RAW = {"bom.cdx.json"}  # SBOM 은 스캐너 출력이 아니다


def load_raws(evidence_dir: Path) -> list[RawResult]:
    ev = Path(evidence_dir)
    meta = json.loads((ev / "meta.json").read_text(encoding="utf-8")) if (ev / "meta.json").exists() else {}
    versions = meta.get("tool_versions", {})
    raws = []
    for p in sorted((ev / "raw").iterdir()):
        if p.name in _SKIP_RAW:
            continue
        fmt = "sarif" if p.suffix == ".sarif" else "json"
        raws.append(RawResult(p.stem, OK, fmt, p.read_text(encoding="utf-8"), version=versions.get(p.stem)))
    return raws


def reinput(evidence_dir: Path, out_dir: Path) -> list[Path]:
    ev, out = Path(evidence_dir), Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    old = from_json((ev / "findings.json").read_text(encoding="utf-8"))
    meta = json.loads((ev / "meta.json").read_text(encoding="utf-8")) if (ev / "meta.json").exists() else {}
    sink = TraceSink()
    raws = load_raws(ev)
    for r in raws:
        sink.record_raw(r.tool, r.status, len(r.payload))
    per_tool = normalize_each(raws)
    for tool in sorted(per_tool):
        sink.record(f"normalize:{tool}", per_tool[tool])
    findings = merge_consensus([f for fs in per_tool.values() for f in fs]); sink.record("merge", findings)
    findings = exclude_findings(findings, set(DEFAULT_EXCLUDES)); sink.record("exclude", findings)
    carry = {f.dedup_key: f.reachability for f in old}
    findings = [replace(f, reachability=carry.get(f.dedup_key, f.reachability)) for f in findings]
    sink.record("reachability", findings)
    findings = sort_findings(decide(findings)); sink.record("disposition", findings); sink.record("final", findings)
    new_meta = {**meta, "reinput_from": str(ev), "reinput_note": "raw 재입력 — 스캐너 미재실행, .gitignore 제외 미적용, 도달성은 V1 판정 carry-over"}
    written = []
    p = out / "findings.json"; p.write_text(to_json(findings, meta=new_meta), encoding="utf-8"); written.append(p)
    p = out / "findings.sarif"; p.write_text(json.dumps(to_sarif(findings), indent=2, ensure_ascii=False), encoding="utf-8"); written.append(p)
    p = out / "report.md"; p.write_text(to_markdown(findings, target=meta.get("snapshot"),
                                                     meta={"scanner_status": meta.get("scanner_status", [])}), encoding="utf-8"); written.append(p)
    p = out / "trace.json"; p.write_text(json.dumps(sink.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8"); written.append(p)
    p = out / "meta.json"; p.write_text(json.dumps(new_meta, indent=2, ensure_ascii=False), encoding="utf-8"); written.append(p)
    return written


def main(argv: list[str] | None = None) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="tools.verify.reinput")
    p.add_argument("--evidence", required=True); p.add_argument("--out", required=True)
    a = p.parse_args(argv)
    for w in reinput(Path(a.evidence), Path(a.out)):
        print(w)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
