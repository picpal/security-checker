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


def test_main_report_accepts_bom_flag(tmp_path):
    rc = cli.main(["report", "--findings", str(FIX), "--bom", "fixtures/report/work-note-bom.cdx.json", "--out", str(tmp_path)])
    assert rc == 0
