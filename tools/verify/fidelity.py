"""축 8 보고서 충실성(spec §5) — findings.json 왕복·projection id 집합·판정(disposition) 일치·결정성·Meta 시트.

측정만 한다. 게이트 판정은 gate.py 가 facts 로 내린다.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from secscan.models import ACTIONABLE
from secscan.output.json_io import from_json, to_json
from secscan.output.markdown import to_markdown
from secscan.output.sarif import to_sarif
from secscan.output.xlsx import build_sheets

from ._facts import facts_text

_MD_ID = re.compile(r"· id `([0-9a-f]{12})`")


def _md_ids(md: str) -> set[str]:
    return set(_MD_ID.findall(md))


def _md_actionable(md: str) -> set[str]:
    sec = md.split("## 우선 조치", 1)
    if len(sec) < 2:
        return set()
    body = sec[1].split("\n## ", 1)[0]
    return set(_MD_ID.findall(body))


def _sarif_ids(doc: dict, only_actionable: bool = False) -> set[str]:
    out = set()
    for r in doc["runs"][0]["results"]:
        p = r.get("properties", {})
        if "id" in p and (not only_actionable or p.get("disposition") == ACTIONABLE):
            out.add(p["id"])
    return out


def _xlsx_ids(sheets: dict, only_actionable: bool = False) -> set[str]:
    header, rows = sheets["Findings"]
    i_id, i_d = header.index("Finding ID"), header.index("Disposition")
    return {r[i_id] for r in rows if not only_actionable or r[i_d] == ACTIONABLE}


def check(evidence_dir) -> dict:
    ev = Path(evidence_dir)
    text = (ev / "findings.json").read_text(encoding="utf-8")
    meta = json.loads((ev / "meta.json").read_text(encoding="utf-8")) if (ev / "meta.json").exists() else {}
    findings = from_json(text)
    roundtrip = from_json(to_json(findings)) == findings
    md1, md2 = to_markdown(findings, meta={"scanner_status": meta.get("scanner_status", [])}), to_markdown(findings, meta={"scanner_status": meta.get("scanner_status", [])})
    sa1, sa2 = to_sarif(findings), to_sarif(findings)
    sh1, sh2 = build_sheets(findings, meta), build_sheets(findings, meta)
    ids = {"findings": {f.id for f in findings}, "markdown": _md_ids(md1), "sarif": _sarif_ids(sa1), "xlsx": _xlsx_ids(sh1)}
    act = {"findings": {f.id for f in findings if f.disposition == ACTIONABLE}, "markdown": _md_actionable(md1),
           "sarif": _sarif_ids(sa1, True), "xlsx": _xlsx_ids(sh1, True)}
    return {
        "roundtrip_identical": roundtrip,
        "ids": ids, "actionable": act,
        "id_set_mismatch": sum(1 for k in ("markdown", "sarif", "xlsx") if ids[k] != ids["findings"]),
        "disposition_mismatch": sum(1 for k in ("markdown", "sarif", "xlsx") if act[k] != act["findings"]),
        "deterministic": md1 == md2 and sa1 == sa2 and sh1 == sh2,
        "meta_scanner_status_rows": len(meta.get("scanner_status", [])),
        "undecided": sum(1 for f in findings if f.disposition is None),
        "exit_code_would_be": 1 if act["findings"] else 0,
    }


def collect_facts(r: dict) -> dict:
    return {
        "fidelity.roundtrip_identical": str(r["roundtrip_identical"]),
        "fidelity.id_set_mismatch": r["id_set_mismatch"],
        "fidelity.disposition_mismatch": r["disposition_mismatch"],
        "fidelity.deterministic": str(r["deterministic"]),
        "fidelity.meta_scanner_status_rows": r["meta_scanner_status_rows"],
        "fidelity.undecided": r["undecided"],
        "fidelity.exit_code": r["exit_code_would_be"],
        **{f"fidelity.ids.{k}": len(v) for k, v in sorted(r["ids"].items())},
        **{f"fidelity.actionable.{k}": len(v) for k, v in sorted(r["actionable"].items())},
    }


def render(r: dict) -> str:
    L = ["# 보고서 충실성 (축 8 — 생성 문서)", "",
         "| 검사 | 값 |", "|---|---|",
         f"| findings.json 왕복 동일 | {r['roundtrip_identical']} |",
         f"| 결정성(md/SARIF/xlsx 2회 동일) | {r['deterministic']} |",
         f"| 미판정(disposition None) | {r['undecided']} |",
         f"| Meta 스캐너 status 행 | {r['meta_scanner_status_rows']} |",
         f"| exit code(판정 기준) | {r['exit_code_would_be']} |", "",
         "## id 집합", "| 포맷 | id 수 | findings.json 과 동일 |", "|---|---|---|"]
    for k in ("findings", "markdown", "sarif", "xlsx"):
        L.append(f"| {k} | {len(r['ids'][k])} | {r['ids'][k] == r['ids']['findings']} |")
    L += ["", "## actionable 집합(판정 일치)", "| 포맷 | actionable 수 | findings.json 과 동일 |", "|---|---|---|"]
    for k in ("findings", "markdown", "sarif", "xlsx"):
        L.append(f"| {k} | {len(r['actionable'][k])} | {r['actionable'][k] == r['actionable']['findings']} |")
    return "\n".join(L) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="tools.verify.fidelity")
    p.add_argument("--evidence", required=True); p.add_argument("--out", required=True); p.add_argument("--facts", default=None)
    a = p.parse_args(argv)
    r = check(a.evidence)
    Path(a.out).write_text(render(r), encoding="utf-8")
    if a.facts:
        Path(a.facts).write_text(facts_text(collect_facts(r)), encoding="utf-8")
    print(a.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
