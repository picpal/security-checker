"""정본 검증기 — 결과 문서의 수치가 증거에서 재계산한 정본과 같은지 기계적으로 검사(spec §4.5, 축 9).

AI(컨트롤러·서브에이전트)가 쓴 수치·분류·판정이 섞였는지 잡는다. 위반이면 문서를 고친다 — 정본은 불변.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from secscan.output.json_io import from_json

from ._facts import facts_text
from ._trivy import iter_vulns

_MARK = re.compile(r"(\S+)\s*<!--\s*fact:([A-Za-z0-9_.\-/가-힣]+)\s*-->")
# 수치 토큰: 앞뒤가 영숫자·'.'·'/'·'-'·'§' 가 아닌 정수 또는 N/M ("9건"·"0(" 은 잡고, 날짜·버전·SHA·CVE id·§5 는 제외)
_NUM = re.compile(r"(?<![0-9A-Za-z./§-])(\d+(?:/\d+)?)(?![0-9A-Za-z./-])")
_MARK_TOKEN = re.compile(r"\S*\d\S*\s*<!--\s*fact:[^>]*-->")
_FACT_COMMENT = re.compile(r"\s*<!--\s*fact:[^>]*-->")
_KNOWN_FP = dict(package="com.microsoft.sqlserver:mssql-jdbc", advisory="CVE-2025-59250", expected_version="13.2.1.jre11")
# 측정 문서의 "표 전체 인용" 선언 — 줄 단위로 찾는다(N1, 리뷰 이후 20자 창 방식에서 전환).
# "전체 인용"을 포함하는 줄이면 그 줄에서 첫 백틱 파일명을 선언으로 취급해 그 표를 대상 파일의
# 같은 헤더 표와 바이트 대조한다(spec §4.5 (f), 리뷰 I8). "전체 인용 아님"(부정)은 제외한다 —
# 예: "reconcile-report.md(전체 인용 아님 — 요약만) 참조".
_FULL_QUOTE = re.compile(r"전체 인용(?!\s*아님)")
_QUOTE_FILE = re.compile(r"`([^`\n]+\.md)`")  # 경로 포함 허용(basename 은 호출부에서 Path(...).name 로 추출)


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


def _blank_fences(md: str) -> str:
    """펜스 코드블록(```) 내부 줄을 빈 줄로 치환한다 — 줄 수·오프셋은 그대로 유지하면서
    표·수치 스캐너가 코드블록 안의 `|` 로 시작하는 줄(pytest 표 등)을 표로 오인하지 않게 한다(리뷰 M5)."""
    out = []
    in_fence = False
    for ln in md.splitlines():
        if ln.strip().startswith("```"):
            in_fence = not in_fence
            out.append("")
            continue
        out.append("" if in_fence else ln)
    return "\n".join(out)


def _iter_tables(md: str, section: str | None):
    """섹션(None=문서 전체) 안의 마크다운 표를 (헤더 셀, [행 셀...]) 로 순회. 펜스 코드블록은 건너뛴다."""
    inside = section is None
    header: list[str] | None = None
    rows: list[list[str]] = []
    for ln in _blank_fences(md).splitlines():
        if ln.startswith("## "):
            if header is not None:
                yield header, rows
                header, rows = None, []
            if section is not None:
                inside = ln[3:].strip().startswith(section)
            continue
        s = ln.strip()
        if not s.startswith("|"):
            if header is not None:
                yield header, rows
                header, rows = None, []
            continue
        if not inside or set(s) <= set("|-: "):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if header is None:  # 표의 첫 줄 = 헤더
            header = cells
        else:
            rows.append(cells)
    if header is not None:
        yield header, rows


def unmarked_numbers(md: str, section: str | None) -> list[str]:
    """`## <section>` 절(None=문서 전체)의 표에서 **측정값/값 열**의 셀 중 수치 토큰(`N`·`N/M`)인데 마커가 없는 것 = 출처 불명.
    행 라벨("2 SCA")·기준 열("≥ 44/46")은 대상이 아니다. "9건"·"0(…)" 처럼 붙은 표기도 잡는다.
    날짜·버전·SHA·CVE id·`§5` 는 수치로 보지 않는다. 헤더에 측정값/값 열이 없는 표는 검사하지 않는다.
    펜스 코드블록 안의 `|` 로 시작하는 줄은 표로 보지 않는다(M5)."""
    out: list[str] = []
    for header, rows in _iter_tables(md, section):
        cols = [i for i, c in enumerate(header) if c in _VALUE_HEADERS]
        if not cols:
            continue
        for cells in rows:
            for i in cols:
                if i < len(cells):
                    bare = _MARK_TOKEN.sub(" ", cells[i])  # 마커 붙은 값은 제거하고 남은 수치만 본다
                    out.extend(m.group(1) for m in _NUM.finditer(bare))
    return out


def table_stats(md: str, section: str | None) -> tuple[int, int]:
    """(검사 대상 표 개수, 값 열이 없어 검사에서 빠진 표 개수) — 사각지대를 보이게 한다(리뷰 M6)."""
    total = 0
    no_value_col = 0
    for header, _rows in _iter_tables(md, section):
        total += 1
        if not any(c in _VALUE_HEADERS for c in header):
            no_value_col += 1
    return total, no_value_col


def _strip_markers(line: str) -> str:
    return _FACT_COMMENT.sub("", line)


def _read_table_lines(lines: list[str], start: int) -> list[str]:
    """`lines[start]`(헤더)부터 이어지는 `|` 표 블록을 (구분선 제외) 원문 그대로 수집."""
    out = []
    i = start
    while i < len(lines):
        s = lines[i].strip()
        if not s.startswith("|"):
            break
        if not (set(s) <= set("|-: ")):
            out.append(s)
        i += 1
    return out


def _table_near_lines(lines: list[str], line_no: int) -> list[str] | None:
    """`lines`(이미 펜스 처리된 줄 목록)에서 `line_no` 다음 표를 우선 찾고, 다음 헤딩 전까지
    없으면 `line_no` 이전(같은 절)의 가장 가까운 표를 찾는다 — "위 표는 …의 전체 인용이며"
    처럼 표를 먼저 보여준 뒤 인용을 선언하는 문장도 대응한다."""
    # 매치가 있는 줄 자체는 헤딩(`### …`)일 수 있으므로 앞뒤 탐색 모두 그 다음/이전 줄부터 본다.
    i = line_no + 1
    while i < len(lines):
        s = lines[i].strip()
        if s.startswith("#"):
            break
        if s.startswith("|") and not set(s) <= set("|-: "):
            return _read_table_lines(lines, i)
        i += 1
    i = line_no - 1
    while i >= 0:
        s = lines[i].strip()
        if s.startswith("#"):
            break
        if s.startswith("|") and not set(s) <= set("|-: "):
            start = i
            while start > 0 and lines[start - 1].strip().startswith("|"):
                start -= 1
            return _read_table_lines(lines, start)
        i -= 1
    return None


def _tables(md_text: str) -> list[list[str]]:
    """문서 전체의 표 블록들(구분선 제외, 펜스 코드블록 제외)."""
    lines = _blank_fences(md_text).splitlines()
    out: list[list[str]] = []
    i = 0
    while i < len(lines):
        s = lines[i].strip()
        if s.startswith("|") and not set(s) <= set("|-: "):
            block = _read_table_lines(lines, i)
            out.append(block)
            i += len(block)
            # 구분선 등 건너뛴 줄이 있을 수 있어 표가 끝나는 지점까지 다시 스캔
            while i < len(lines) and lines[i].strip().startswith("|"):
                i += 1
        else:
            i += 1
    return out


def check_quoted_tables(measurement_md: str, results_dir) -> list[dict]:
    """측정 문서의 "`<file>.md` … 전체 인용" 선언마다, 인용된 표를 원본 문서의 같은 헤더 표와
    (마커 제거 후) 행 단위로 대조한다(spec §4.5 (f), 리뷰 I8). "전체 인용이다"라는 주장 자체를 검증한다.

    N1: 탐지는 줄 단위다 — "전체 인용"을 포함하는 줄에서 첫 백틱 파일명(경로 포함 가능, `.md` 로
    끝나는 첫 `` `...` ``)을 선언으로 취급한다. 그런 줄에 파일명이 없으면(예: 손으로 쓴 문장이
    규칙을 어긴 경우) 검증 불능 행으로 남긴다 — 조용히 건너뛰지 않는다."""
    res = Path(results_dir)
    out: list[dict] = []
    blanked_lines = _blank_fences(measurement_md).splitlines()
    for i, line in enumerate(measurement_md.splitlines()):
        if not _FULL_QUOTE.search(line):
            continue
        m = _QUOTE_FILE.search(line)
        if not m:
            out.append({"quote": line, "header": "", "ok": False, "note": "선언 줄에 파일명 없음"})
            continue
        fname = Path(m.group(1)).name
        quoted = _table_near_lines(blanked_lines, i)
        if quoted is None:
            out.append({"quote": fname, "header": "", "ok": False, "note": "인용 위치 근처에 표 없음"})
            continue
        src_path = res / fname
        if not src_path.exists():
            out.append({"quote": fname, "header": quoted[0], "ok": False, "note": f"원본 파일 없음({fname})"})
            continue
        header = _strip_markers(quoted[0])
        src_tables = _tables(src_path.read_text(encoding="utf-8"))
        src = next((t for t in src_tables if _strip_markers(t[0]) == header), None)
        if src is None:
            out.append({"quote": fname, "header": header, "ok": False, "note": "원본에 동일 헤더 표 없음"})
            continue
        q_stripped = [_strip_markers(r) for r in quoted]
        s_stripped = [_strip_markers(r) for r in src]
        ok = q_stripped == s_stripped
        out.append({"quote": fname, "header": header, "ok": ok, "note": "" if ok else "행 불일치"})
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
    raw: set[str] = {v["VulnerabilityID"] for _, v in iter_vulns(trivy_json) if v.get("VulnerabilityID")}
    typed = {f.advisory.id for f in findings if f.category == "sca" and f.advisory}
    return {"raw_count": len(raw), "typed_count": len(typed),
            "only_raw": sorted(raw - typed), "only_typed": sorted(typed - raw)}


# 옛 결과 디렉토리(플랜 1, 2026-09-05)에는 이 태스크에서 새로 생긴 생성 문서가 없다 — legacy
# 디렉토리에서만 있으면 비교하고 없으면 건너뛴다(플랜 1 결과 디렉토리 호환). README.md 는 옛
# 증거 디렉토리의 손기입 운영 로그를 덮어써서 비교하지 않는다(Rec 5, 생성기는 새 증거에만 쓴다).
_OPTIONAL = {"fidelity.md", "reach-app.md", "gate.md", "facts-fidelity.json", "facts-reachapp.json", "README.md"}


def is_legacy_results_dir(results_dir) -> bool:
    """M5(최종 리뷰) — `_OPTIONAL` 스킵은 플랜 1 옛 결과 디렉토리에만 적용한다: `gate-v2.md` 가
    있고 `gate.md` 가 없으면(Task 13 이전, 새 생성 문서가 아직 없던 시절) legacy 로 본다. 그 외
    디렉토리는 생성 문서·facts 가 없으면 검사를 약화하지 않고 ✗ 행("결과 파일 없음")으로 잡는다.

    공개 함수(밑줄 없음) — I1(최종 리뷰): `generators.write_all` 도 같은 판정을 재사용해
    legacy 증거 디렉토리의 손기입 README 를 덮어쓰지 않는다."""
    res = Path(results_dir)
    return (res / "gate-v2.md").exists() and not (res / "gate.md").exists()


def regenerate(results_dir, evidence_root, gt_b, gt_a, *, std_name: str = "a483b3b1-standard") -> list[dict]:
    """생성 문서·facts 를 레지스트리(generators.GENERATORS)로 다시 만들어 바이트 비교.

    생성기 예외는 죽지 않고 ✗ 행으로 격리한다(M4/N6 — 부분 실패는 정상, spec §4.5)."""
    from .generators import GENERATORS, Ctx
    res = Path(results_dir)
    ctx = Ctx(res, Path(evidence_root), Path(gt_b), Path(gt_a), std_name)
    legacy = is_legacy_results_dir(res)
    rows: list[dict] = []

    def cmp(name: str, text: str, path: Path, optional: bool) -> None:
        if not path.exists():
            if not optional:
                rows.append({"doc": name, "ok": False, "note": "결과 파일 없음"})
            return
        same = path.read_text(encoding="utf-8") == text
        rows.append({"doc": name, "ok": same, "note": "" if same else "재생성 결과와 다름"})

    for g in GENERATORS:
        if legacy and g.doc == "README.md":
            # Rec 5 — 옛 증거 디렉토리의 README.md 는 손기입 운영 로그다(생성 문서가 아니다).
            # 존재는 하지만(빠진 게 아니라) 다른 문서이므로 비교 자체를 하지 않는다 — 존재 여부로
            # 판정하는 나머지 _OPTIONAL 항목과 달리, 여기선 "있어도 비교 안 함"이 필요하다.
            continue
        try:
            doc, facts = g.produce(ctx)
        except Exception as e:  # 증거 부재 등 — 죽지 않고 ✗ 행(M4/N6)
            rows.append({"doc": g.doc, "ok": False, "note": f"생성 실패: {type(e).__name__}: {e}"})
            continue
        doc_path = g.path(ctx) if g.path else res / g.doc
        cmp(g.doc, doc, doc_path, legacy and g.doc in _OPTIONAL)
        if g.facts:
            cmp(g.facts, facts_text(facts), res / g.facts, legacy and g.facts in _OPTIONAL)
    return rows


def load_facts(results_dir) -> dict:
    """`facts-reconcile.json`(직전 실행의 정본 검증 결과)은 제외한다 — reconcile.* 마커는
    이번 실행에서 방금 계산한 값과 대조해야 한다(리뷰 I7). 포함하면 문서가 "직전 실행 통과"를
    이번 실행 위반이 새로 생겨도 계속 인용할 수 있게 된다."""
    facts: dict = {}
    for p in sorted(Path(results_dir).glob("facts*.json")):
        if p.name == "facts-reconcile.json":
            continue
        facts.update(json.loads(p.read_text(encoding="utf-8")))
    return facts


def _esc(s) -> str:
    """N4 — 표 셀에 넣는 임의 텍스트(문서명·id·인용 헤더 등)의 `|` 를 이스케이프한다.
    셀 안에 원본 그대로의 `|` 가 섞이면(예: 인용된 표 헤더 자체가 `| a | b |`) 표 구조가 깨진다."""
    return str(s).replace("|", "\\|")


def render_report(regen: list[dict], markers: dict[str, list[dict]], unmarked: dict[str, list[str]],
                  prov: list[dict], rvt: dict, quotes: list[dict] | None = None,
                  stats: dict[str, tuple[int, int]] | None = None) -> str:
    quotes = quotes or []
    stats = stats or {}
    L = ["# 정본 검증 (spec §4.5 · 축 9)", "", "## 생성 문서 재생성 비교", "| 문서 | 일치 | 비고 |", "|---|---|---|"]
    L += [f"| {_esc(r['doc'])} | {'✓' if r['ok'] else '✗'} | {_esc(r['note'])} |" for r in regen]
    L += ["", "## fact 마커 대조", "| 문서 | id | 문서값 | 정본값 | 일치 |", "|---|---|---|---|---|"]
    L += [f"| {_esc(doc)} | {_esc(r['id'])} | {_esc(r['doc'])} | {_esc(r['fact'])} | {'✓' if r['ok'] else '✗'} |"
          for doc, rows in markers.items() for r in rows]
    un = [f"- {doc}: {', '.join(v)}" for doc, v in unmarked.items() if v]
    L += ["", "## 출처 불명 수치(마커 없음)", *(un or ["- 없음"])]
    st = [f"- {doc}: 검사 대상 표 {t} / 값 열 없는 표 {n}" for doc, (t, n) in stats.items()]
    L += ["", "## 표 검사 범위(M6 — 값 열 없는 표는 출처 불명 검사에서 빠진다)", *(st or ["- 없음"])]
    L += ["", "## 인용 표 대조(spec §4.5 (f))", "| 인용 | 원본 | 일치 |", "|---|---|---|"]
    if quotes:
        for q in quotes:
            origin = q["quote"] + (f" — {q['note']}" if q["note"] else "")
            L.append(f"| {_esc(q['header']) or '(표 없음)'} | {_esc(origin)} | {'✓' if q['ok'] else '✗'} |")
    else:
        L.append("| - | 없음 | - |")
    pv = [f"- {r['dedup_key']}: {r['provenance']} {'✓' if r['ok'] else '✗'}" for r in prov]
    L += ["", "## override provenance", *(pv or ["- override 없음"])]
    L += ["", "## raw↔typed 카디널리티 (a483b3b1-standard)",
          f"- raw trivy 고유 VulnerabilityID: {rvt['raw_count']}", f"- typed SCA 고유 advisory: {rvt['typed_count']}",
          f"- raw 에만: {', '.join(rvt['only_raw']) or '없음'}", f"- typed 에만: {', '.join(rvt['only_typed']) or '없음'}"]
    fails = (sum(not r["ok"] for r in regen) + sum(not r["ok"] for rows in markers.values() for r in rows)
             + sum(len(v) for v in unmarked.values()) + sum(not r["ok"] for r in prov)
             + sum(not q["ok"] for q in quotes))
    L += ["", f"## 판정: {'✓ 통과' if fails == 0 else f'✗ 위반 {fails}건 — 문서를 고친다(정본 불변)'}"]
    return "\n".join(L) + "\n"


def collect_facts(regen: list[dict], markers: dict[str, list[dict]], unmarked: dict[str, list[str]],
                  prov: list[dict], rvt: dict, quotes: list[dict] | None = None) -> dict:
    """정본 검증 자체의 결과 수치(spec §4.5, 축 9). 다음 실행에서 `facts*.json` 글롭에 합류한다."""
    quotes = quotes or []
    regen_mismatch = sum(not r["ok"] for r in regen)
    marker_mismatch = sum(not r["ok"] for rows in markers.values() for r in rows)
    unmarked_n = sum(len(v) for v in unmarked.values())
    prov_violations = sum(not r["ok"] for r in prov)
    raw_typed_mismatch = len(rvt["only_raw"]) + len(rvt["only_typed"])  # raw/typed 각각의 고유분 합 — 둘 다 비면 0
    quote_mismatch = sum(not q["ok"] for q in quotes)
    total = regen_mismatch + marker_mismatch + unmarked_n + prov_violations + quote_mismatch
    return {
        "reconcile.regen_mismatch": regen_mismatch,
        "reconcile.marker_mismatch": marker_mismatch,
        "reconcile.unmarked": unmarked_n,
        "reconcile.provenance_violations": prov_violations,
        "reconcile.raw_typed_mismatch": raw_typed_mismatch,
        "reconcile.raw_count": rvt["raw_count"],
        "reconcile.typed_count": rvt["typed_count"],
        "reconcile.only_raw": len(rvt["only_raw"]),
        "reconcile.only_typed": len(rvt["only_typed"]),
        "reconcile.quote_mismatch": quote_mismatch,
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
    facts = load_facts(res)  # facts-reconcile.json 제외(I7) — 아래에서 이번 실행 값으로 다시 채운다
    regen = regenerate(res, a.evidence_root, a.gt_b, a.gt_a)
    docs: dict[str, tuple[Path, str | None]] = {"gate-v2.md": (res / "gate-v2.md", None), "gate-v3.md": (res / "gate-v3.md", None),
                                                "gate.md": (res / "gate.md", None)}
    if a.measurement:
        docs["measurement"] = (Path(a.measurement), "요약")
    mds: dict[str, str] = {}
    unmarked: dict[str, list[str]] = {}
    stats: dict[str, tuple[int, int]] = {}
    for name, (path, section) in docs.items():
        if not path.exists():
            continue
        mds[name] = path.read_text(encoding="utf-8")
        unmarked[name] = unmarked_numbers(mds[name], section)
        stats[name] = table_stats(mds[name], section)
    triage = res / "extras-triage.json"
    prov = check_provenance(json.loads(triage.read_text(encoding="utf-8"))) if triage.exists() else []
    std = Path(a.evidence_root) / "a483b3b1-standard"
    rvt = raw_vs_typed((std / "raw" / "trivy.json").read_text(encoding="utf-8"),
                       from_json((std / "findings.json").read_text(encoding="utf-8")))
    quotes = check_quoted_tables(mds["measurement"], res) if "measurement" in mds else []

    # I7 — reconcile.* 마커는 직전 실행의 facts-reconcile.json 이 아니라 "이번 실행에서 방금 계산한"
    # 값과 대조해야 한다. 자기참조 순환을 끊기 위해 2단계로 계산한다:
    # 1단계: reconcile.* 자기인용 행을 제외한 채로(아직 값을 모르므로) 이번 실행 reconcile facts 를 구한다.
    seed_markers = {name: [r for r in check_markers(md, facts) if not r["id"].startswith("reconcile.")]
                    for name, md in mds.items()}
    this_run_reconcile = collect_facts(regen, seed_markers, unmarked, prov, rvt, quotes)
    # 2단계: 그 값을 facts 에 병합해 문서 전체(자기인용 행 포함)를 다시 대조한다 — 이제 reconcile.*
    # 마커도 "이번 실행" 값과 비교되므로, 문서가 과거 통과 상태를 그대로 인용해도 들통난다.
    facts_full = {**facts, **this_run_reconcile}
    markers = {name: check_markers(md, facts_full) for name, md in mds.items()}

    # N5 — reconcile.marker_mismatch 는 1단계(seed, reconcile.* 자기인용 제외) 값으로 고정한다:
    # 문서가 인용하는 그 값 자체가 자기인용 여부에 따라 흔들리면 안 된다(자기참조로 값이 값을
    # 정의하는 순환을 피한다). reconcile.* 자기인용 불일치는 별도 facts.self_marker_mismatch 로
    # 낸다 — 판정(문서의 "## 판정" 행, render_report 의 fails)에는 여전히 markers(전체, 2단계)를
    # 써서 반영하고, facts-reconcile.json 의 verdict 합에도 self_mm 을 더한다.
    self_mm = sum(not r["ok"] for rows in markers.values() for r in rows if r["id"].startswith("reconcile."))

    text = render_report(regen, markers, unmarked, prov, rvt, quotes, stats)
    Path(a.out or res / "reconcile-report.md").write_text(text, encoding="utf-8")
    # M2(최종 리뷰) — this_run_reconcile 은 이미 (regen, seed_markers, unmarked, prov, rvt, quotes)
    # 로 계산했다. 같은 인자로 collect_facts 를 다시 부르지 않고 그 값을 그대로 재사용한다 —
    # "문서를 대조한 값"과 "facts-reconcile.json 에 남기는 값"이 정의상 같은 계산임을 코드로 보장한다.
    final_facts = dict(this_run_reconcile)
    final_facts["reconcile.self_marker_mismatch"] = self_mm
    if self_mm:
        final_facts["reconcile.verdict"] = "위반"
    (res / "facts-reconcile.json").write_text(facts_text(final_facts), encoding="utf-8")
    print(text.splitlines()[-1])
    return 0 if text.rstrip().endswith("✓ 통과") else 1


if __name__ == "__main__":
    raise SystemExit(main())
