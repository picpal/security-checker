"""측정 리포트 렌더 — attrition·정답지 대조·사람 도달성 판정 비교(spec §4.2·§4.3·§5 축 6a)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from secscan.measure import GtManifest, MatchReport, _ids, classify_extras, load_gt_manifest, match_ground_truth
from secscan.models import Finding
from secscan.output.json_io import from_json

from ._facts import facts_text

OUR_METHOD = "패키지 prefix 존재(atom usage 슬라이스에 해당 타입 호출 유무)"


def render_attrition(trace: dict) -> str:
    """단계별 attrition 표(normalize:<tool> 개별 → normalize(합계) → merge → exclude → final).

    `normalize:<tool>` 행은 도구별 **독립** 건수지 파이프라인 누적이 아니다 — 증감 칸을 비운다.
    증감은 `normalize(합계)`(도구별 합) 이후의 파이프라인 단계에서만 계산한다(리뷰 I1, N3 — trace
    의 `stages` 순서를 그대로 보존한다: partition 정렬 없이 normalize:* 행을 원래 순서대로 두고
    그 뒤에 normalize(합계)를 끼운 다음, 이후 파이프라인 행의 증감을 그 합계부터 계산한다). 예전에는
    도구 행 사이를 알파벳순으로 이어 증감을 찍어 merge 의 실제 감소(76→73, -3)가 +25 로
    부호가 뒤집혀 보였다. 증감은 0 이면 "0", 아니면 부호를 붙인다(N3 — 통일된 표기)."""
    stages = trace.get("stages", [])
    norm = [s for s in stages if s["stage"].startswith("normalize:")]
    pipeline = [s for s in stages if not s["stage"].startswith("normalize:")]
    L = ["| 단계 | 건수 | 증감 |", "| --- | --- | --- |"]
    for s in norm:
        L.append(f"| {s['stage']} | {s['count']} |  |")
    prev = None
    if norm:
        total = sum(s["count"] for s in norm)
        L.append(f"| normalize(합계) | {total} |  |")
        prev = total
    for s in pipeline:
        if prev is None:
            delta = ""
        else:
            d = s["count"] - prev
            delta = "0" if d == 0 else f"{d:+d}"
        L.append(f"| {s['stage']} | {s['count']} | {delta} |")
        prev = s["count"]
    raw = ", ".join(f"{r['tool']}={r['status']}({r['bytes']}B)" for r in trace.get("raw", []))
    return f"raw: {raw}\n\n" + "\n".join(L)


def _missed_key(advisory: str, package: str) -> str:
    return f"{advisory}|{package}"


def missed_stage(entry, trace: dict, raw_vulns: list[dict]) -> str:
    """GT-B 미탐 항목이 마지막으로 관측된 단계 → 그 다음 단계에서 빠졌다고 귀속한다(리뷰 I2).

    `trace.stages[*].keys` 를 기계적으로 훑는다 — 각 키를 `|` 로 나눠 `sca|<ecosystem>|<package>|
    <version>|<advisory>` 형태(≥5 필드)인지 보고, package·advisory(또는 alias)가 일치하는 단계를
    "포함한다"고 본다. 어느 단계에도 없으면 raw trivy 출력에서 같은 패키지·advisory 를 찾아
    normalize(정규화가 버림) vs scanner(애초에 미생산)를 가른다. 포함하는 단계가 있으면 그 중
    마지막 단계의 **다음** 단계가 빠뜨린 지점이다. final 까지 살아남았다면(정상적으로는 발생하지
    않아야 함 — 미탐인데 final 에 있다는 뜻) "matcher"(대조기 자체를 봐야 함)로 표시한다."""
    ids = {entry.advisory, *entry.aliases}
    stages = trace.get("stages", [])
    contained_idx = []
    for i, s in enumerate(stages):
        for k in s.get("keys", []) or []:
            parts = k.split("|")
            if len(parts) >= 5 and parts[0] == "sca" and parts[2] == entry.package and parts[4] in ids:
                contained_idx.append(i)
                break
    if not contained_idx:
        for v in raw_vulns:
            if v.get("PkgName") == entry.package and v.get("VulnerabilityID") in ids:
                return "normalize"
        return "scanner"
    last = max(contained_idx)
    if last == len(stages) - 1:
        return "matcher"
    return stages[last + 1]["stage"]


def missed_stages(report: MatchReport, trace: dict, raw_vulns: list[dict]) -> dict[str, str]:
    """미탐 각 항목(advisory|package 키)의 귀속 단계."""
    return {_missed_key(m.entry.advisory, m.entry.package): missed_stage(m.entry, trace, raw_vulns)
            for m in report.missed()}


def render_match(report: MatchReport, classes: dict[str, str], stages: dict[str, str] | None = None) -> str:
    """정답지 대조: recall·미탐·known-FP·version-mismatch·초과 탐지."""
    stages = stages or {}
    c_hit, c_tot = report.recall_cve()
    e_hit, e_tot = report.recall_entry(strict=True)
    e_len, _ = report.recall_entry(strict=False)
    by_o = " · ".join(f"{o} {h}/{t}" for o, (h, t) in sorted(recall_by_origin(report).items()))
    L = [f"- CVE 단위 recall(GT-B 합산): {c_hit}/{c_tot}",
         f"- origin 별 CVE recall: {by_o} (team = 보안팀 trivy 결과 재현율 성격, dev-found = 독립 증거 — spec §5 축 2)",
         f"- 항목 단위 recall: strict {e_hit}/{e_tot} · version-mismatch 포함 {e_len}/{e_tot}",
         f"- 종류별: {report.by_kind()}", ""]
    if report.missed():
        L += ["### 미탐", "| advisory | 패키지 | 설치 | 심각도(보안팀) | origin | 단계 |", "|---|---|---|---|---|---|"]
        for m in report.missed():
            e = m.entry
            stage = stages.get(_missed_key(e.advisory, e.package), "-")
            L.append(f"| {e.advisory} | {e.package} | {e.installed} | {e.severity_team or '-'} | {e.origin} | {stage} |")
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
            for i in _ids(f):
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


def raw_vulns(trivy_payload: str) -> list[dict]:
    """Trivy JSON 의 `Vulnerabilities` 배열 전체(원본 필드 그대로) — 미탐 단계 귀속(리뷰 I2)에 쓴다."""
    out: list[dict] = []
    for res in json.loads(trivy_payload or "{}").get("Results", []) or []:
        out.extend(res.get("Vulnerabilities") or [])
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
                  trace: dict, meta: dict, raw_vulns_: list[dict]) -> dict:
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
    facts["sca.extras.unclassified"] = sum(1 for f in report.extras if f.dedup_key not in classes)
    for origin, (hit, tot) in sorted(recall_by_origin(report).items()):
        facts[f"sca.recall_cve.{origin}"] = f"{hit}/{tot}"
    # 미탐 전건 단계 귀속(리뷰 I2) — scanner/normalize 는 미탐이 0 건이어도 항상 찍는다.
    stage_counts = Counter(missed_stage(m.entry, trace, raw_vulns_) for m in report.missed())
    for stage in sorted(set(stage_counts) | {"scanner", "normalize"}):
        facts[f"sca.missed_by_stage.{stage}"] = stage_counts.get(stage, 0)
    hv = [m.entry for m in report.matches if m.entry.human_verdict]
    facts["human.verdict_rows"] = len(hv)
    facts["human.verdict_advisories"] = len({e.advisory for e in hv})
    for cat, n in sorted(Counter(f.category for f in findings).items()):
        facts[f"findings.{cat}"] = n
    for s in trace.get("stages", []):
        facts[f"attrition.{s['stage']}"] = s["count"]
    for s in meta.get("scanner_status", []):
        facts[f"scanner.{s['tool']}"] = s["status"]
    reach = Counter((f.reachability.status if f.reachability else "none")
                    for f in findings if f.category == "sca")
    for st in ("reachable", "unreachable", "unknown"):
        facts[f"reach.{st}"] = reach.pop(st, 0)
    for st, n in sorted(reach.items()):
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
    raw_trivy_text = raw_trivy.read_text(encoding="utf-8") if raw_trivy.exists() else "{}"
    dates = published_dates(raw_trivy_text)
    vulns = raw_vulns(raw_trivy_text)
    classes = classify_extras(report.extras, manifest, dates)
    stages = missed_stages(report, trace, vulns)
    md = "\n\n".join([
        f"# 대조 — {ev.name} vs {Path(a.gt).name}",
        "## 단계별 attrition", render_attrition(trace),
        "## 정답지 대조", render_match(report, classes, stages),
        "## 사람 도달성 판정 비교(일치율 산출 안 함 — 방법이 다름)", render_human_verdicts(manifest, findings),
    ])
    Path(a.out).write_text(md, encoding="utf-8")
    if a.facts:
        Path(a.facts).write_text(facts_text(collect_facts(report, classes, findings, trace, meta, vulns)), encoding="utf-8")
    print(a.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
