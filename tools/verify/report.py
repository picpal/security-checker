"""측정 리포트 렌더 — attrition·정답지 대조·사람 도달성 판정 비교(spec §4.2·§4.3·§5 축 6a)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from secscan.measure import GtManifest, MatchReport, classify_extras, load_gt_manifest, match_ground_truth
from secscan.models import Finding
from secscan.output.json_io import from_json

OUR_METHOD = "패키지 prefix 존재(atom usage 슬라이스에 해당 타입 호출 유무)"


def render_attrition(trace: dict) -> str:
    """단계별 attrition 표(merge → exclude → final)."""
    L = ["| 단계 | 건수 | 증감 |", "|---|---|---|"]
    prev = None
    for s in trace.get("stages", []):
        delta = "" if prev is None else f"{s['count'] - prev:+d}"
        L.append(f"| {s['stage']} | {s['count']} | {delta} |")
        prev = s["count"]
    raw = ", ".join(f"{r['tool']}={r['status']}({r['bytes']}B)" for r in trace.get("raw", []))
    return f"raw: {raw}\n\n" + "\n".join(L)


def render_match(report: MatchReport, classes: dict[str, str]) -> str:
    """정답지 대조: recall·미탐·known-FP·version-mismatch·초과 탐지."""
    c_hit, c_tot = report.recall_cve()
    e_hit, e_tot = report.recall_entry(strict=True)
    e_len, _ = report.recall_entry(strict=False)
    by_o = " · ".join(f"{o} {h}/{t}" for o, (h, t) in sorted(recall_by_origin(report).items()))
    L = [f"- CVE 단위 recall(GT-B 합산): {c_hit}/{c_tot}",
         f"- origin 별 CVE recall: {by_o} (team = 보안팀 trivy 결과 재현율 성격, dev-found = 독립 증거 — spec §5 축 2)",
         f"- 항목 단위 recall: strict {e_hit}/{e_tot} · version-mismatch 포함 {e_len}/{e_tot}",
         f"- 종류별: {report.by_kind()}", ""]
    if report.missed():
        L += ["### 미탐", "| advisory | 패키지 | 설치 | 심각도(보안팀) | origin |", "|---|---|---|---|---|"]
        for m in report.missed():
            e = m.entry
            L.append(f"| {e.advisory} | {e.package} | {e.installed} | {e.severity_team or '-'} | {e.origin} |")
        L.append("")
    if report.false_positives():
        L += ["### known-FP 재현(치명)", *(f"- {m.entry.advisory} {m.entry.package} → 보고됨(버전 {m.got_version})"
                                          for m in report.false_positives()), ""]
    vm = [m for m in report.matches if m.kind == "version-mismatch"]
    if vm:
        L += ["### 버전 표기 불일치", *(f"- {m.entry.advisory} {m.entry.package}: 기대 {m.entry.installed} / 실제 {m.got_version}" for m in vm), ""]
    if report.extras:
        L += ["### 초과 탐지", "| advisory | 패키지 | 설치 | 분류 |", "|---|---|---|---|"]
        for f in sorted(report.extras, key=lambda x: x.dedup_key):
            L.append(f"| {f.advisory.id} | {f.component.package} | {f.component.version} | {classes.get(f.dedup_key, '미분류')} |")
    return "\n".join(L)


def render_human_verdicts(manifest: GtManifest, findings: list[Finding]) -> str:
    """사람 도달성 판정 비교(판정 방법이 다름 — 일치율 산출 안 함)."""
    by = {}
    for f in findings:
        if f.component and f.advisory:
            for i in (f.advisory.id, *f.advisory.aliases):
                by[(i, f.component.package)] = f
    L = ["| advisory | 패키지 | 사람 판정 | 사람 근거 분류 | 우리 판정 | 우리 근거 | 판정 방법 차이 |",
         "|---|---|---|---|---|---|---|"]
    for e in manifest.entries:
        if not e.human_verdict:
            continue
        f = by.get((e.advisory, e.package))
        ours = f.reachability.status if f else "미탐"
        ev = (f.reachability.evidence or "-") if f else "-"
        L.append(f"| {e.advisory} | {e.package} | {e.human_verdict} | {e.reason_class} ({e.reason}) | {ours} | {ev} | 사람=CVE 전제조건 / 우리={OUR_METHOD} |")
    return "\n".join(L)


def published_dates(trivy_payload: str) -> dict[str, str]:
    """Trivy JSON 에서 CVE별 공개 일자 추출."""
    out: dict[str, str] = {}
    for res in json.loads(trivy_payload or "{}").get("Results", []) or []:
        for v in res.get("Vulnerabilities") or []:
            if v.get("VulnerabilityID") and v.get("PublishedDate"):
                out[v["VulnerabilityID"]] = v["PublishedDate"][:10]
    return out


def recall_by_origin(report: MatchReport) -> dict[str, tuple[int, int]]:
    """origin(team/dev-found) 별 CVE 단위 recall — team 은 보안팀 trivy 재현율 성격(spec §5 축 2)."""
    hit_kinds = {"exact", "alias", "version-mismatch"}
    acc: dict[str, tuple[set, set]] = {}
    for m in report.matches:
        if m.entry.expected != "present":
            continue
        tot, hit = acc.setdefault(m.entry.origin, (set(), set()))
        tot.add(m.entry.advisory)
        if m.kind in hit_kinds:
            hit.add(m.entry.advisory)
    return {o: (len(h), len(t)) for o, (t, h) in acc.items()}


def collect_facts(report: MatchReport, classes: dict[str, str], findings: list[Finding],
                  trace: dict, meta: dict) -> dict:
    """정본 수치(spec §4.5). 문서는 이 값을 `<!-- fact:id -->` 마커와 함께 인용만 한다."""
    from collections import Counter
    c_hit, c_tot = report.recall_cve()
    s_hit, e_tot = report.recall_entry(strict=True)
    l_hit, _ = report.recall_entry(strict=False)
    facts: dict = {
        "sca.recall_cve": f"{c_hit}/{c_tot}",
        "sca.recall_entry_strict": f"{s_hit}/{e_tot}",
        "sca.recall_entry_loose": f"{l_hit}/{e_tot}",
        "sca.missed": len(report.missed()),
        "sca.missed_high_important": sum(1 for m in report.missed()
                                          if (m.entry.severity_team or "").upper() in ("HIGH", "IMPORTANT")),
        "sca.false_positive": len(report.false_positives()),
        "sca.extras": len(report.extras),
        "findings.total": len(findings),
    }
    for cls, n in sorted(Counter(classes.get(f.dedup_key, "미분류") for f in report.extras).items()):
        facts[f"sca.extras.{cls}"] = n
    for origin, (hit, tot) in sorted(recall_by_origin(report).items()):
        facts[f"sca.recall_cve.{origin}"] = f"{hit}/{tot}"
    for cat, n in sorted(Counter(f.category for f in findings).items()):
        facts[f"findings.{cat}"] = n
    for s in trace.get("stages", []):
        facts[f"attrition.{s['stage']}"] = s["count"]
    for s in meta.get("scanner_status", []):
        facts[f"scanner.{s['tool']}"] = s["status"]
    for st, n in sorted(Counter((f.reachability.status if f.reachability else "none")
                                for f in findings if f.category == "sca").items()):
        facts[f"reach.{st}"] = n
    return facts


def main(argv: list[str] | None = None) -> int:
    """CLI: --evidence <dir> --gt <gt-b-sca.json> --out <md> [--facts <json>]"""
    p = argparse.ArgumentParser(prog="tools.verify.report")
    p.add_argument("--evidence", required=True)
    p.add_argument("--gt", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--facts", default=None, help="정본 수치 JSON 출력 경로(spec §4.5)")
    a = p.parse_args(argv)
    ev = Path(a.evidence)
    findings = from_json((ev / "findings.json").read_text(encoding="utf-8"))
    trace = json.loads((ev / "trace.json").read_text(encoding="utf-8"))
    meta = json.loads((ev / "meta.json").read_text(encoding="utf-8")) if (ev / "meta.json").exists() else {}
    manifest = load_gt_manifest(a.gt)
    report = match_ground_truth(findings, manifest)
    raw_trivy = ev / "raw" / "trivy.json"
    dates = published_dates(raw_trivy.read_text(encoding="utf-8")) if raw_trivy.exists() else {}
    classes = classify_extras(report.extras, manifest, dates)
    md = "\n\n".join([
        f"# 대조 — {ev.name} vs {Path(a.gt).name}",
        "## 단계별 attrition", render_attrition(trace),
        "## 정답지 대조", render_match(report, classes),
        "## 사람 도달성 판정 비교(일치율 산출 안 함 — 방법이 다름)", render_human_verdicts(manifest, findings),
    ])
    Path(a.out).write_text(md, encoding="utf-8")
    if a.facts:
        Path(a.facts).write_text(json.dumps(collect_facts(report, classes, findings, trace, meta),
                                            ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(a.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
