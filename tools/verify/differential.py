"""GT-A differential(spec §5 축 7): 취약 스냅샷에서 기대 룰 출현 ∧ 수정 커밋에서 소멸.

탐지 recall(출현)과 actionable recall(tier)을 분리해 기록한다. 증거 디렉토리의 findings.json 을 읽는다.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from secscan.measure import load_gt_manifest
from secscan.models import Finding, sast_tier
from secscan.output.json_io import from_json


def find_expected(findings: list[Finding], entry: dict) -> list[Finding]:
    suf, fsuf = entry.get("expected_rule_suffix"), entry.get("file_suffix")
    return [f for f in findings if f.category == "sast" and f.location
            and (suf is None or f.rule_id.endswith(suf))
            and (fsuf is None or f.location.file.endswith(fsuf))]


def evaluate_pair(entry: dict, vuln_findings: list[Finding], fixed_findings: list[Finding]) -> dict:
    cls = entry.get("class")
    row = {"cwe": entry.get("cwe"), "class": cls, "file": entry.get("file_suffix"),
           "rule": entry.get("expected_rule_suffix")}
    if cls == "measure-then-classify":
        hits = find_expected(vuln_findings, entry)
        row.update({"observed": sorted({f.rule_id for f in hits}), "passed": None})
        return row
    if cls != "in-category":
        row.update({"passed": None, "observed": []})
        return row
    v, x = find_expected(vuln_findings, entry), find_expected(fixed_findings, entry)
    tier = sast_tier(v[0]) if v else None
    row.update({
        "present_in_vulnerable": bool(v), "absent_in_fixed": not x, "fixed_residual": len(x),
        "tier_vulnerable": tier, "tier_ok": (tier == entry.get("expected_tier")) if v else False,
        "passed": bool(v) and not x,
    })
    return row


def render(rows: list[dict]) -> str:
    L = ["| CWE | 분류 | 파일 | 룰 | 취약에서 출현 | 수정에서 소멸 | tier(기대) | 판정 |", "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        if r["class"] == "in-category":
            L.append(f"| {r['cwe']} | {r['class']} | {r['file']} | {r['rule']} | {r['present_in_vulnerable']} | {r['absent_in_fixed']} | "
                     f"{r['tier_vulnerable']} ({'ok' if r['tier_ok'] else 'mismatch'}) | {'PASS' if r['passed'] else 'FAIL'} |")
        else:
            L.append(f"| {r['cwe']} | {r['class']} | {r['file'] or '-'} | - | 관측: {', '.join(r.get('observed', [])) or '없음'} | - | - | 기록 |")
    return "\n".join(L)


def _load(evidence_root: Path, sha: str) -> list[Finding]:
    p = evidence_root / f"{sha}-standard" / "findings.json"
    return from_json(p.read_text(encoding="utf-8")) if p.exists() else []


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="tools.verify.differential")
    p.add_argument("--evidence-root", required=True)
    p.add_argument("--gt", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--facts", default=None, help="정본 수치 JSON(spec §4.5)")
    a = p.parse_args(argv)
    root = Path(a.evidence_root)
    rows = []
    for e in load_gt_manifest(a.gt).raw_entries:
        if not e.get("vulnerable"):
            rows.append({"cwe": e.get("cwe"), "class": e.get("class"), "file": None, "rule": None, "passed": None, "observed": []})
            continue
        rows.append(evaluate_pair(e, _load(root, e["vulnerable"]), _load(root, e["fixed"]) if e.get("fixed") else []))
    in_cat = [r for r in rows if r["class"] == "in-category"]
    md = (f"# GT-A differential — 범주 내 {sum(1 for r in in_cat if r['passed'])}/{len(in_cat)} PASS\n\n" + render(rows))
    Path(a.out).write_text(md, encoding="utf-8")
    if a.facts:
        Path(a.facts).write_text(json.dumps(collect_facts(rows), ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(a.out)
    return 0


def collect_facts(rows: list[dict]) -> dict:
    """정본 수치(spec §4.5). 판정은 evaluate_pair 의 기계적 결과를 그대로 옮긴다."""
    in_cat = [r for r in rows if r["class"] == "in-category"]
    facts: dict = {"gta.in_category_pass": f"{sum(1 for r in in_cat if r['passed'])}/{len(in_cat)}"}
    for i, r in enumerate(rows):
        if r["class"] == "in-category":
            facts[f"gta.row{i}.{r['cwe']}.passed"] = str(r["passed"])
            facts[f"gta.row{i}.{r['cwe']}.fixed_residual"] = r.get("fixed_residual", 0)
        elif r["class"] == "measure-then-classify":
            facts[f"gta.row{i}.{r['cwe']}.observed"] = ", ".join(r.get("observed", [])) or "없음"
    return facts


if __name__ == "__main__":
    raise SystemExit(main())
