"""`secscan report` — findings.json 만으로 워크북 생성. 상대경로 통일. scan 은 report 유무와 무관하게 exit 불변."""
import json
from pathlib import Path

from secscan import cli
from secscan.output.json_io import from_json
from secscan.report.cli import build_report, write_report_bundle
from secscan.report.workbook import SHEET_ACTIONS, SHEET_SUMMARY

FIX = Path("fixtures/report/work-note-findings.json")


def _load():
    text = FIX.read_text(encoding="utf-8")
    return from_json(text), json.loads(text)["meta"]


def test_build_report_relativizes_absolute_paths_under_target():
    fs, meta = _load()
    abs_fs = [f for f in fs]
    from dataclasses import replace
    from secscan.models import Location
    f0 = abs_fs[0]
    abs_fs[0] = replace(f0, location=Location("/repo/work-note/" + f0.location.file, f0.location.start_line))
    s = build_report(abs_fs, meta, target="/repo/work-note")
    row = next(r for r in s[SHEET_ACTIONS][1] if r[2] == f0.id)
    assert row[4].startswith(f0.location.file.split("/")[0])  # 접두 제거됨


def test_write_report_bundle_writes_report_xlsx_or_csv(tmp_path):
    fs, meta = _load()
    paths, warn = write_report_bundle(fs, meta, tmp_path, prefer_xlsx=False)
    assert warn and (tmp_path / "report-xlsx" / f"{SHEET_SUMMARY}.csv").exists()


def test_main_report_command_writes_outputs(tmp_path):
    rc = cli.main(["report", "--findings", str(FIX), "--out", str(tmp_path)])
    assert rc == 0
    assert (tmp_path / "report.xlsx").exists() or (tmp_path / "report-xlsx").is_dir()


def test_main_report_requires_findings(capsys):
    rc = cli.main(["report", "--out", "x"])
    assert rc == 2 and "--findings" in capsys.readouterr().out


def test_report_with_bom_fills_dependency_path_column(tmp_path):
    fs, meta = _load()
    from secscan.report.cli import build_report
    s = build_report(fs, meta, bom="fixtures/report/work-note-bom.cdx.json")
    rows = {r[2]: r for r in s[SHEET_ACTIONS][1]}
    assert rows["0442ba114c70"][5] == "전이 ← spring-boot-starter-tomcat ← spring-boot-starter-web"
    assert rows["356e4bbab00c"][5] == ""  # SAST 는 의존 경로 없음
    s2 = build_report(fs, meta, bom="nope.json")
    assert {r[2]: r for r in s2[SHEET_ACTIONS][1]}["0442ba114c70"][5] == "BOM 없음"


def test_report_with_bom_and_interp_meta_still_fills_dependency_path_column():
    fs, meta = _load()
    s = build_report(fs, meta, bom="fixtures/report/work-note-bom.cdx.json",
                     interp_meta={"status": "absent", "rejected": []})
    rows = {r[2]: r for r in s[SHEET_ACTIONS][1]}
    assert rows["0442ba114c70"][5] == "전이 ← spring-boot-starter-tomcat ← spring-boot-starter-web"


def test_main_report_accepts_bom_flag(tmp_path):
    rc = cli.main(["report", "--findings", str(FIX), "--bom", "fixtures/report/work-note-bom.cdx.json", "--out", str(tmp_path)])
    assert rc == 0


def test_bundle_writes_request_and_merges_interpretations(tmp_path):
    fs, meta = _load()
    from secscan.report.interpret import RESPONSE_CONTEXT
    resp = {"@context": RESPONSE_CONTEXT, "items": {
        "356e4bbab00c": {"guess": "상수 PASSWORD 가 KNOWN_KEYS 집합에 들어감.", "check": "88행 리터럴 값 확인.",
                          "cites": ["backend/src/main/java/com/worknote/admin/BreakGlassFile.java:87-89"]},
        "108d8ee4651c": {"guess": "예시값으로 보임.", "check": "실계정 여부 확인.", "cites": []}}}
    ip = tmp_path / "interpretations.json"; ip.write_text(json.dumps(resp, ensure_ascii=False), encoding="utf-8")
    paths, _ = write_report_bundle(fs, meta, tmp_path, interpretations=ip, prefer_xlsx=False)
    req = json.loads((tmp_path / "report-request.json").read_text(encoding="utf-8"))
    assert req["@context"] == "secscan-report-request/v1" and len(req["items"]) == 15
    assert (tmp_path / "report-request.json") in paths
    import csv
    rows = list(csv.reader((tmp_path / "report-xlsx" / "2_확인질문.csv").open(encoding="utf-8")))
    row = next(r for r in rows if r[1] == "356e4bbab00c")
    assert row[5].startswith("상수 PASSWORD") and "87-89" in row[7]
    summary = {r[0]: r for r in csv.reader((tmp_path / "report-xlsx" / "0_요약.csv").open(encoding="utf-8"))}
    assert summary["해석 상태"][1] == "ok" and "108d8ee4651c: no_cite" in summary["해석 상태"][2]


def test_bundle_without_interpretations_marks_absent(tmp_path):
    fs, meta = _load()
    write_report_bundle(fs, meta, tmp_path, prefer_xlsx=False)
    import csv
    summary = {r[0]: r for r in csv.reader((tmp_path / "report-xlsx" / "0_요약.csv").open(encoding="utf-8"))}
    assert summary["해석 상태"][1] == "absent"


def test_main_report_with_interpretations_flag(tmp_path):
    ip = tmp_path / "i.json"; ip.write_text(json.dumps({"@context": "secscan-interpretations/v1", "items": {}}), encoding="utf-8")
    rc = cli.main(["report", "--findings", str(FIX), "--interpretations", str(ip), "--out", str(tmp_path)])
    assert rc == 0 and (tmp_path / "report-request.json").exists()


def test_main_report_check_result_exit_codes(tmp_path):
    r = tmp_path / "r.json"
    r.write_text(json.dumps([{"id": "0442ba114c70", "status": "fixed"}, {"id": "356e4bbab00c", "status": "needs_confirmation", "reason": "q"}]), encoding="utf-8")
    assert cli.main(["report", "--check-result", str(r), "--rescan", str(FIX)]) == 2  # 0442… 가 재스캔에 존재 → 불일치
    r.write_text(json.dumps([{"id": "ffffffffffff", "status": "fixed"}]), encoding="utf-8")
    assert cli.main(["report", "--check-result", str(r), "--rescan", str(FIX)]) == 0
