"""LLM 결과 반환 ↔ 재스캔 대조(spec §5.6). fixed 주장은 기계로 검증한다."""
import json
from pathlib import Path

import pytest

from secscan.report.models import ResultRow
from secscan.report.result_check import RESULT_CONTEXT, check, has_mismatch, load_result, render


def test_verdict_table():
    rows = [ResultRow("a", "fixed"), ResultRow("b", "fixed"), ResultRow("c", "skipped", reason="dry-run"),
            ResultRow("d", "needs_confirmation", reason="q?"), ResultRow("e", "done")]
    res = check(rows, {"b", "c"})
    assert [(r["id"], r["verdict"]) for r in res] == [("a", "일치"), ("b", "불일치"), ("c", "미검증"),
                                                       ("d", "미검증(재스캔에서 사라짐)"), ("e", "불일치(status 값 오류)")]
    assert has_mismatch(res) is True and has_mismatch(check([ResultRow("a", "fixed")], set())) is False


def test_render_is_markdown_table():
    out = render(check([ResultRow("a", "fixed", changed_files="build.gradle")], set()))
    assert out.splitlines()[0].startswith("| ID | status | 재스캔 존재 | 판정 |") and "| a | fixed | 부재 | 일치 |" in out


def test_load_result_json_shapes(tmp_path):
    p = tmp_path / "r.json"
    p.write_text(json.dumps({"@context": RESULT_CONTEXT, "rows": [{"id": "a", "status": "fixed", "commit": "abc"}]}), encoding="utf-8")
    assert load_result(p) == [ResultRow("a", "fixed", commit="abc")]
    p2 = tmp_path / "r2.json"; p2.write_text(json.dumps([{"id": "b", "status": "skipped", "reason": "x"}]), encoding="utf-8")
    assert load_result(p2) == [ResultRow("b", "skipped", reason="x")]


def test_load_result_xlsx_skips_guard_rows(tmp_path):
    pytest.importorskip("openpyxl")
    from openpyxl import Workbook
    wb = Workbook(); ws = wb.active; ws.title = "4_결과반환"
    ws.append(["ID", "status", "changed_files", "verification", "question_or_reason", "commit"])
    ws.append(["#허용 범위", "…", "", "", "", ""])
    ws.append(["a", "fixed", "build.gradle", "id 부재", "", "abc"])
    p = tmp_path / "r.xlsx"; wb.save(p)
    assert load_result(p) == [ResultRow("a", "fixed", "build.gradle", "id 부재", "", "abc")]
