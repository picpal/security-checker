"""5 시트 빌더(spec §5.5) — 열 계약, 사실/추정 분리, 비밀값 미노출, 결정성, 골든."""
import json
from pathlib import Path

from secscan.output.json_io import from_json
from secscan.report.derive import derive_all
from secscan.report.kb import entry_for
from secscan.report.models import Interpretation
from secscan.report.workbook import (ACTION_HEADER, QUESTION_HEADER, RESULT_HEADER, SHEET_ACTIONS, SHEET_QUESTIONS,
                                     SHEET_RESULT, SHEET_RULES, SHEET_SUMMARY, build_report_sheets, guard_rows, write_report)

FIX = Path("fixtures/report/work-note-findings.json")
GOLDEN = Path("tests/golden/report-work-note-sheets.json")
FS = from_json(FIX.read_text(encoding="utf-8"))
META = json.loads(FIX.read_text(encoding="utf-8"))["meta"]
KBS = {f.id: entry_for(f) for f in FS}
DER = derive_all(FS, KBS)


def _sheets(interps=None, interp_meta=None):
    return build_report_sheets(FS, META, KBS, DER, interps, interp_meta)


def test_sheet_names_and_headers():
    s = _sheets()
    assert list(s) == [SHEET_SUMMARY, SHEET_ACTIONS, SHEET_QUESTIONS, SHEET_RULES, SHEET_RESULT]
    assert s[SHEET_ACTIONS][0] == ACTION_HEADER and len(ACTION_HEADER) == 17
    assert s[SHEET_QUESTIONS][0] == QUESTION_HEADER and len(QUESTION_HEADER) == 9
    assert s[SHEET_RESULT][0] == RESULT_HEADER and len(RESULT_HEADER) == 6
    assert ACTION_HEADER[5] == "의존 경로" and ACTION_HEADER[11] == "같이 해결"


def test_action_rows_sorted_and_first_row_is_hardcoded_credential():
    rows = _sheets()[SHEET_ACTIONS][1]
    assert len(rows) == 15 and rows[0][0] == 1 and rows[0][1] == "P1" and rows[0][2] == "356e4bbab00c"
    assert rows[0][3] == "소스코드에 박힌 자격증명" and rows[0][10] == "사람 확인 후"
    assert rows[0][12] == "SAST · 룰 신뢰도 high → tier actionable → 조치대상"
    assert rows[0][15] == "KISA SF-06 하드코드된 중요정보 · PCI-DSS 6.2.4 — access control"


def test_question_rows_only_for_needs_question_and_interpretation_columns_empty_without_file():
    rows = _sheets()[SHEET_QUESTIONS][1]
    assert len(rows) == 15  # 사람 확인 후 11 + evidence 없는 강등 SCA 4
    for r in rows:
        assert r[5] == "" and r[6] == "" and r[7] == ""  # 추정·확인 방법·인용 비어 있음
        assert r[8].startswith("① 수정")


def test_interpretations_fill_guess_columns_and_summary_reports_status():
    interps = {"356e4bbab00c": Interpretation("상수 PASSWORD 가 KNOWN_KEYS 집합에 들어감.", "88행 리터럴 값 확인.",
                                             ("backend/src/main/java/com/worknote/admin/BreakGlassFile.java:87-89",))}
    s = _sheets(interps, {"status": "ok", "rejected": [{"id": "108d8ee4651c", "reason": "no_cite"}]})
    row = next(r for r in s[SHEET_QUESTIONS][1] if r[1] == "356e4bbab00c")
    assert row[5].startswith("상수 PASSWORD") and row[6] == "88행 리터럴 값 확인." and "87-89" in row[7]
    summary = {r[0]: (r[1], r[2]) for r in s[SHEET_SUMMARY][1]}
    assert summary["해석 상태"][0] == "ok" and "108d8ee4651c: no_cite" in summary["해석 상태"][1]


def test_summary_conclusion_and_counts_and_unregistered_rules():
    summary = {r[0]: (r[1], r[2]) for r in _sheets()[SHEET_SUMMARY][1]}
    assert summary["결론"][0].startswith("총 15건. 즉시 조치 대상 8건(자동 수정 0, 사람 확인 후 8).")
    assert summary["즉시 조치 대상(P1·P2)"][0] == 8 and summary["강등(P4)"][0] == 4 and summary["제외"][0] == 23
    assert summary["스캐너 trivy"][0] == "ok"
    assert summary["지식베이스 미등록 룰"][0] == "없음"  # 12건 등록으로 work-note 는 전부 커버


def test_result_sheet_has_guard_rows_then_one_row_per_finding():
    rows = _sheets()[SHEET_RESULT][1]
    assert [r[0] for r in rows[:4]] == ["#허용 범위", "#금지", "#완료 판정", "#status 값"]
    assert "secscan scan --target work-note" in rows[2][1]
    assert [r[0] for r in rows[4:]] == [r[2] for r in _sheets()[SHEET_ACTIONS][1]]
    assert all(r[1:] == ["", "", "", "", ""] for r in rows[4:])


def test_rules_sheet_is_fixed_table():
    header, rows = _sheets()[SHEET_RULES]
    assert header == ["항목", "규칙 / 뜻"] and [r[0] for r in rows][:3] == ["판정(disposition) 규칙", "우선순위 규칙", "담당 규칙"]


def test_no_secret_values_and_all_cells_sanitized():
    s = _sheets()
    blob = json.dumps({k: v[1] for k, v in s.items()}, ensure_ascii=False)
    assert "pend-" not in blob and "ghp_" not in blob
    for _, rows in s.values():
        for r in rows:
            for c in r:
                assert c is None or isinstance(c, (int, float)) or (isinstance(c, str) and not c.lstrip().startswith(("=", "+", "-", "@")))


def test_deterministic_regardless_of_input_order():
    rev = list(reversed(FS))
    assert build_report_sheets(rev, META, {f.id: KBS[f.id] for f in rev}, derive_all(rev, KBS)) == _sheets()


def test_matches_golden():
    got = {k: {"header": h, "rows": r} for k, (h, r) in _sheets().items()}
    assert got == json.loads(GOLDEN.read_text(encoding="utf-8"))


def test_write_report_xlsx_or_csv(tmp_path):
    paths, warn = write_report(_sheets(), tmp_path, created="2026-09-06", prefer_xlsx=False)
    assert warn and (tmp_path / "report-xlsx" / "1_조치목록.csv").exists()
    try:
        import openpyxl  # noqa: F401
    except ImportError:
        return
    paths, warn = write_report(_sheets(), tmp_path, created="2026-09-06", prefer_xlsx=True)
    assert warn is None and paths == [tmp_path / "report.xlsx"]
    from openpyxl import load_workbook
    wb = load_workbook(paths[0])
    assert wb.sheetnames == [SHEET_SUMMARY, SHEET_ACTIONS, SHEET_QUESTIONS, SHEET_RULES, SHEET_RESULT]
    assert wb.properties.modified == wb.properties.created
