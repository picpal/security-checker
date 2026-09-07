"""LLM 결과 반환 ↔ 재스캔 대조(spec §5.6). fixed 주장은 기계로 검증한다."""
import json
from pathlib import Path

import pytest

from secscan.output.json_io import from_json
from secscan.report.models import ResultRow
from secscan.report.result_check import RESULT_CONTEXT, check, has_mismatch, load_result, render, rescan_ids

FIX = Path("fixtures/report/work-note-findings.json")


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
    ws.append(["이 시트는", "안내 행 — 첫 열이 finding ID 형식이 아니면 건너뛴다", "", "", "", ""])
    ws.append(["a1b2c3d4e5f6", "fixed", "build.gradle", "id 부재", "", "abc", "문제(참고)", "담당(참고)", "위치(참고)"])
    p = tmp_path / "r.xlsx"; wb.save(p)
    assert load_result(p) == [ResultRow("a1b2c3d4e5f6", "fixed", "build.gradle", "id 부재", "", "abc")]  # 참고 열 3개는 무시


def test_rescan_ids_relativizes_absolute_paths_to_meta_target(tmp_path):
    """FR-1(Critical): --check-result 의 ID 공간 불일치. 재스캔 findings.json 은 절대경로일 수
    있고, 보고서·request·결과반환 의 ID 는 --target 상대화 공간이다(spec §12(f)). rescan_ids 가
    상대화하지 않으면 SAST/secret 의 id(경로 포함 dedup_key)가 전부 달라져 fixed 주장이 거짓으로
    '일치' 판정된다."""
    text = FIX.read_text(encoding="utf-8")
    doc = json.loads(text)
    for item in doc["findings"]:
        loc = item.get("location")
        if loc and loc.get("file"):
            loc["file"] = "/repo/work-note/" + loc["file"]
        if item.get("source"):
            item["source"] = "/repo/work-note/" + item["source"]
    doc["meta"]["target"] = "/repo/work-note"
    p = tmp_path / "abs-findings.json"
    p.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")

    fixture_ids = {f.id for f in from_json(text)}
    assert rescan_ids(p) == fixture_ids  # meta.target 기본으로 상대화 후 대조

    # 상대화 없이 절대경로 그대로 읽으면(구현 버그 재현) id 집합이 달라진다 — SAST/secret 11건.
    abs_ids = {f.id for f in from_json(p.read_text(encoding="utf-8"))}
    assert abs_ids != fixture_ids

    from secscan import cli

    r = tmp_path / "r.json"
    r.write_text(json.dumps([{"id": "356e4bbab00c", "status": "fixed"}]), encoding="utf-8")
    assert cli.main(["report", "--check-result", str(r), "--rescan", str(p)]) == 2  # meta.target 기본
    assert cli.main(["report", "--check-result", str(r), "--rescan", str(p), "--target", "/repo/work-note"]) == 2  # --target 명시
