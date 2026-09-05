"""정본 검증기 — 결과 문서의 수치가 증거에서 재계산한 정본과 같은지 기계적으로 검사(spec §4.5, 축 9).

AI(컨트롤러·서브에이전트)가 쓴 수치·분류·판정이 섞였는지 잡는다. 위반이면 문서를 고친다 — 정본은 불변.
"""

from __future__ import annotations

import argparse
import json
import re
import tempfile
from pathlib import Path

from secscan.measure import load_gt_manifest
from secscan.output.json_io import from_json

from . import differential, report
from .jar_surface import collect_facts as surface_facts, render_doc as render_surface
from .known_fp import check_known_fp, render as render_fp
from .profile_contract import render_doc as render_profiles

_MARK = re.compile(r"(\S+)\s*<!--\s*fact:([A-Za-z0-9_.\-/가-힣]+)\s*-->")
# 수치 토큰: 앞뒤가 영숫자·'.'·'/'·'-'·'§' 가 아닌 정수 또는 N/M ("9건"·"0(" 은 잡고, 날짜·버전·SHA·CVE id·§5 는 제외)
_NUM = re.compile(r"(?<![0-9A-Za-z./§-])(\d+(?:/\d+)?)(?![0-9A-Za-z./-])")
_MARK_TOKEN = re.compile(r"\S*\d\S*\s*<!--\s*fact:[^>]*-->")
_KNOWN_FP = dict(package="com.microsoft.sqlserver:mssql-jdbc", advisory="CVE-2025-59250", expected_version="13.2.1.jre11")


def parse_markers(md: str) -> list[tuple[str, str]]:
    """`<값> <!-- fact:<id> -->` 쌍 → (id, 값).

    마커 앞 토큰이 "8건"처럼 수치에 단위가 바로 붙은 경우, 토큰 전체가 아니라
    그 안의 마지막 수치 토큰만 값으로 취급한다(단위는 정본 값의 일부가 아니다).
    수치가 없는 토큰(예: "True")은 토큰 전체를 그대로 값으로 쓴다.
    """
    out: list[tuple[str, str]] = []
    for m in _MARK.finditer(md):
        token = m.group(1)
        nums = _NUM.findall(token)
        out.append((m.group(2), nums[-1] if nums else token))
    return out


def check_markers(md: str, facts: dict) -> list[dict]:
    rows = []
    for fid, val in parse_markers(md):
        fact = facts.get(fid)
        rows.append({"id": fid, "doc": val, "fact": None if fact is None else str(fact),
                     "ok": fact is not None and str(fact) == val})
    return rows


_VALUE_HEADERS = ("측정값", "값")


def unmarked_numbers(md: str, section: str | None) -> list[str]:
    """`## <section>` 절(None=문서 전체)의 표에서 **측정값/값 열**의 셀 중 수치 토큰(`N`·`N/M`)인데 마커가 없는 것 = 출처 불명.
    행 라벨("2 SCA")·기준 열("≥ 44/46")은 대상이 아니다. "9건"·"0(…)" 처럼 붙은 표기도 잡는다.
    날짜·버전·SHA·CVE id·`§5` 는 수치로 보지 않는다. 헤더에 측정값/값 열이 없는 표는 검사하지 않는다."""
    out: list[str] = []
    inside = section is None
    cols: list[int] | None = None  # 현재 표에서 검사할 열 인덱스
    for ln in md.splitlines():
        if ln.startswith("## "):
            if section is not None:
                inside = ln[3:].strip().startswith(section)
            cols = None
            continue
        s = ln.strip()
        if not s.startswith("|"):
            cols = None
            continue
        if not inside or set(s) <= set("|-: "):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if cols is None:  # 표의 첫 줄 = 헤더
            cols = [i for i, c in enumerate(cells) if c in _VALUE_HEADERS]
            continue
        for i in cols:
            if i < len(cells):
                bare = _MARK_TOKEN.sub(" ", cells[i])  # 마커 붙은 값은 제거하고 남은 수치만 본다
                out.extend(m.group(1) for m in _NUM.finditer(bare))
    return out


def check_provenance(triage: dict) -> list[dict]:
    """override 는 사람 확정(`human:<이름>`)만 유효 — AI 분류 덮어쓰기 금지."""
    rows = []
    for o in triage.get("overrides", []) or []:
        prov = str(o.get("provenance", "") or "")
        rows.append({"dedup_key": o.get("dedup_key"), "provenance": prov or "(없음)", "ok": prov.startswith("human:")})
    return rows


def raw_vs_typed(trivy_json: str, findings) -> dict:
    """raw trivy 고유 VulnerabilityID vs typed SCA 고유 advisory — 정규화 손실 검출(차이는 사실로 기록)."""
    raw: set[str] = set()
    for res in json.loads(trivy_json or "{}").get("Results", []) or []:
        for v in res.get("Vulnerabilities") or []:
            if v.get("VulnerabilityID"):
                raw.add(v["VulnerabilityID"])
    typed = {f.advisory.id for f in findings if f.category == "sca" and f.advisory}
    return {"raw_count": len(raw), "typed_count": len(typed),
            "only_raw": sorted(raw - typed), "only_typed": sorted(typed - raw)}


def regenerate(results_dir, evidence_root, gt_b, gt_a) -> list[dict]:
    """생성 문서를 같은 증거로 다시 만들어 바이트 비교."""
    res, ev = Path(results_dir), Path(evidence_root)
    std = ev / "a483b3b1-standard"
    rows: list[dict] = []

    def cmp(name: str, text: str) -> None:
        p = res / name
        if not p.exists():
            rows.append({"doc": name, "ok": False, "note": "결과 파일 없음"})
            return
        same = p.read_text(encoding="utf-8") == text
        rows.append({"doc": name, "ok": same, "note": "" if same else "재생성 결과와 다름"})

    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        report.main(["--evidence", str(std), "--gt", str(gt_b), "--out", str(t / "m.md"), "--facts", str(t / "f.json")])
        cmp("gt-b-match.md", (t / "m.md").read_text(encoding="utf-8"))
        cmp("facts.json", (t / "f.json").read_text(encoding="utf-8"))
        differential.main(["--evidence-root", str(ev), "--gt", str(gt_a), "--out", str(t / "d.md"), "--facts", str(t / "g.json")])
        cmp("gt-a-differential.md", (t / "d.md").read_text(encoding="utf-8"))
        cmp("facts-gta.json", (t / "g.json").read_text(encoding="utf-8"))
    bom, trivy = std / "raw" / "bom.cdx.json", std / "raw" / "trivy.json"
    if bom.exists() and trivy.exists():
        cmp("known-fp.md", render_fp(check_known_fp(bom.read_text(encoding="utf-8"), trivy.read_text(encoding="utf-8"), **_KNOWN_FP)))
    else:
        rows.append({"doc": "known-fp.md", "ok": False, "note": "raw/bom.cdx.json 또는 raw/trivy.json 없음"})
    deep = ev / "a483b3b1-deep" / "meta.json"
    if deep.exists():
        statuses = {s["tool"]: s["status"] for s in json.loads(deep.read_text(encoding="utf-8"))["scanner_status"]}
        cmp("profile-contract.md", render_profiles(statuses))
    jar, status = res / "input-surface.trivy-fs.json", res / "input-surface.status.json"
    if jar.exists() and status.exists() and bom.exists():
        ok = bool(json.loads(status.read_text(encoding="utf-8")).get("jar_build_scan_ok", False))
        m_b = load_gt_manifest(gt_b)
        cmp("input-surface.md", render_surface(ok, bom.read_text(encoding="utf-8"), jar.read_text(encoding="utf-8"), m_b))
        cmp("facts-surface.json", json.dumps(surface_facts(ok, bom.read_text(encoding="utf-8"), jar.read_text(encoding="utf-8"), m_b),
                                             ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    else:
        rows.append({"doc": "input-surface.md", "ok": False, "note": "trivy-fs.json / status.json / bom 없음"})
    return rows


def load_facts(results_dir) -> dict:
    facts: dict = {}
    for p in sorted(Path(results_dir).glob("facts*.json")):
        facts.update(json.loads(p.read_text(encoding="utf-8")))
    return facts


def render_report(regen: list[dict], markers: dict[str, list[dict]], unmarked: dict[str, list[str]],
                  prov: list[dict], rvt: dict) -> str:
    L = ["# 정본 검증 (spec §4.5 · 축 9)", "", "## 생성 문서 재생성 비교", "| 문서 | 일치 | 비고 |", "|---|---|---|"]
    L += [f"| {r['doc']} | {'✓' if r['ok'] else '✗'} | {r['note']} |" for r in regen]
    L += ["", "## fact 마커 대조", "| 문서 | id | 문서값 | 정본값 | 일치 |", "|---|---|---|---|---|"]
    L += [f"| {doc} | {r['id']} | {r['doc']} | {r['fact']} | {'✓' if r['ok'] else '✗'} |"
          for doc, rows in markers.items() for r in rows]
    un = [f"- {doc}: {', '.join(v)}" for doc, v in unmarked.items() if v]
    L += ["", "## 출처 불명 수치(마커 없음)", *(un or ["- 없음"])]
    pv = [f"- {r['dedup_key']}: {r['provenance']} {'✓' if r['ok'] else '✗'}" for r in prov]
    L += ["", "## override provenance", *(pv or ["- override 없음"])]
    L += ["", "## raw↔typed 카디널리티 (a483b3b1-standard)",
          f"- raw trivy 고유 VulnerabilityID: {rvt['raw_count']}", f"- typed SCA 고유 advisory: {rvt['typed_count']}",
          f"- raw 에만: {', '.join(rvt['only_raw']) or '없음'}", f"- typed 에만: {', '.join(rvt['only_typed']) or '없음'}"]
    fails = (sum(not r["ok"] for r in regen) + sum(not r["ok"] for rows in markers.values() for r in rows)
             + sum(len(v) for v in unmarked.values()) + sum(not r["ok"] for r in prov))
    L += ["", f"## 판정: {'✓ 통과' if fails == 0 else f'✗ 위반 {fails}건 — 문서를 고친다(정본 불변)'}"]
    return "\n".join(L) + "\n"


def collect_facts(regen: list[dict], markers: dict[str, list[dict]], unmarked: dict[str, list[str]],
                  prov: list[dict], rvt: dict) -> dict:
    """정본 검증 자체의 결과 수치(spec §4.5, 축 9). 다음 실행에서 `facts*.json` 글롭에 합류한다."""
    regen_mismatch = sum(not r["ok"] for r in regen)
    marker_mismatch = sum(not r["ok"] for rows in markers.values() for r in rows)
    unmarked_n = sum(len(v) for v in unmarked.values())
    prov_violations = sum(not r["ok"] for r in prov)
    raw_typed_mismatch = len(rvt["only_raw"]) + len(rvt["only_typed"])  # raw/typed 각각의 고유분 합 — 둘 다 비면 0
    total = regen_mismatch + marker_mismatch + unmarked_n + prov_violations
    return {
        "reconcile.regen_mismatch": regen_mismatch,
        "reconcile.marker_mismatch": marker_mismatch,
        "reconcile.unmarked": unmarked_n,
        "reconcile.provenance_violations": prov_violations,
        "reconcile.raw_typed_mismatch": raw_typed_mismatch,
        "reconcile.verdict": "통과" if total == 0 else "위반",
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="tools.verify.reconcile")
    p.add_argument("--results", required=True)
    p.add_argument("--evidence-root", required=True)
    p.add_argument("--gt-b", required=True)
    p.add_argument("--gt-a", required=True)
    p.add_argument("--measurement", default=None, help="측정 문서(md) — `## 요약` 절 마커 검사")
    p.add_argument("--out", default=None)
    a = p.parse_args(argv)
    res = Path(a.results)
    facts = load_facts(res)
    regen = regenerate(res, a.evidence_root, a.gt_b, a.gt_a)
    docs: dict[str, tuple[Path, str | None]] = {"gate-v2.md": (res / "gate-v2.md", None), "gate-v3.md": (res / "gate-v3.md", None)}
    if a.measurement:
        docs["measurement"] = (Path(a.measurement), "요약")
    markers: dict[str, list[dict]] = {}
    unmarked: dict[str, list[str]] = {}
    for name, (path, section) in docs.items():
        if not path.exists():
            continue
        md = path.read_text(encoding="utf-8")
        markers[name] = check_markers(md, facts)
        unmarked[name] = unmarked_numbers(md, section)
    triage = res / "extras-triage.json"
    prov = check_provenance(json.loads(triage.read_text(encoding="utf-8"))) if triage.exists() else []
    std = Path(a.evidence_root) / "a483b3b1-standard"
    rvt = raw_vs_typed((std / "raw" / "trivy.json").read_text(encoding="utf-8"),
                       from_json((std / "findings.json").read_text(encoding="utf-8")))
    text = render_report(regen, markers, unmarked, prov, rvt)
    Path(a.out or res / "reconcile-report.md").write_text(text, encoding="utf-8")
    (res / "facts-reconcile.json").write_text(
        json.dumps(collect_facts(regen, markers, unmarked, prov, rvt), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    print(text.splitlines()[-1])
    return 0 if text.rstrip().endswith("✓ 통과") else 1


if __name__ == "__main__":
    raise SystemExit(main())
