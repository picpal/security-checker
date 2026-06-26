"""M0 doctor — CLI 렌더링/exit code 테스트.

렌더링은 순수(report -> str)라 결정적으로 검증한다. main 은 run_doctor 를
주입/대체해 exit code 계약만 검증한다.
"""

from secscan import cli
from secscan.adapters.base import FAILED, RawResult
from secscan.doctor import (
    MISSING,
    OK,
    DoctorReport,
    Requirement,
    ToolStatus,
)
from secscan.models import (
    REACHABLE,
    UNREACHABLE,
    Advisory,
    Component,
    Finding,
    Reachability,
)
from secscan.scan import ScanResult


def _status(name, present, version, satisfies, state, kind="scanner", optional=False):
    req = Requirement(
        name=name, kind=kind, purpose=f"{name} 용도",
        install_hint=f"install {name}", optional=optional,
    )
    return ToolStatus(req, present, version, satisfies, state)


def test_render_shows_each_tool_and_version():
    report = DoctorReport([
        _status("trivy", True, "0.50.0", True, OK),
        _status("depscan", False, None, False, MISSING),
    ])
    out = cli.render_doctor(report)
    assert "trivy" in out
    assert "0.50.0" in out
    assert "depscan" in out


def test_render_includes_install_hint_for_missing_tool():
    report = DoctorReport([_status("depscan", False, None, False, MISSING)])
    out = cli.render_doctor(report)
    assert "install depscan" in out  # 누락 도구엔 설치 가이드 노출


def test_render_marks_ok_and_problem_distinctly():
    report = DoctorReport([
        _status("trivy", True, "0.50.0", True, OK),
        _status("depscan", False, None, False, MISSING),
    ])
    out = cli.render_doctor(report)
    # ok 줄과 문제 줄의 마커가 다르다
    trivy_line = next(l for l in out.splitlines() if "trivy" in l)
    depscan_line = next(l for l in out.splitlines() if "depscan" in l and "install" not in l)
    assert trivy_line.strip()[0] != depscan_line.strip()[0]


def test_render_present_tool_without_version_shows_installed_not_purpose():
    # atom 처럼 --version 출력이 없어 버전을 못 읽는 present 도구
    report = DoctorReport([_status("atom", True, None, True, OK)])
    out = cli.render_doctor(report)
    line = next(l for l in out.splitlines() if "atom" in l)
    assert "설치됨" in line
    assert "atom 용도" not in line  # purpose 잡음을 상태줄에 노출하지 않음


def test_main_doctor_returns_0_when_environment_ok(monkeypatch):
    ok_report = DoctorReport([_status("trivy", True, "0.50.0", True, OK)])
    monkeypatch.setattr(cli, "run_doctor", lambda: ok_report)
    assert cli.main(["doctor"]) == 0


def test_main_doctor_returns_1_when_problems(monkeypatch):
    bad_report = DoctorReport([_status("depscan", False, None, False, MISSING)])
    monkeypatch.setattr(cli, "run_doctor", lambda: bad_report)
    assert cli.main(["doctor"]) == 1


# --- scan 커맨드 ---

def _reach(pkg, cve, sev, reach):
    return Finding(
        category="sca", severity=sev, rule_id=cve,
        component=Component("maven", pkg, "1.0"),
        advisory=Advisory(cve, aliases=(cve,)),
        reachability=Reachability(reach),
    )


def test_render_scan_summary_shows_counts_and_reachability():
    res = ScanResult(
        findings=[_reach("a", "CVE-1", "critical", REACHABLE),
                  _reach("b", "CVE-2", "high", UNREACHABLE)],
        raw_results=[], reachability_ran=True, reachability_reason="ok",
    )
    out = cli.render_scan_summary(res)
    assert "도달 가능" in out
    assert "2" in out


def test_render_scan_summary_reports_partial_failures():
    res = ScanResult(
        findings=[], raw_results=[],
        partial_failures=[RawResult("osv-scanner", FAILED, error="boom")],
    )
    out = cli.render_scan_summary(res)
    assert "osv-scanner" in out


def test_render_scan_summary_notes_reachability_fallback():
    res = ScanResult(findings=[], raw_results=[], reachability_ran=False,
                     reachability_reason="timeout")
    out = cli.render_scan_summary(res)
    assert "timeout" in out  # 폴백 사유 노출


def test_main_scan_writes_outputs(monkeypatch, tmp_path):
    findings = [_reach("commons-text", "CVE-2022-42889", "critical", REACHABLE)]
    monkeypatch.setattr(
        cli, "run_scan",
        lambda *a, **k: ScanResult(findings, [], True, "ok", []),
    )
    rc = cli.main([
        "scan", "--target", "/proj", "--profile", "accurate-sca",
        "--out", str(tmp_path), "--no-reachability",
    ])
    assert (tmp_path / "report.md").exists()
    assert (tmp_path / "findings.sarif").exists()
    assert rc == 1  # 도달 가능 critical 존재 → actionable


def test_main_scan_clean_returns_0(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "run_scan", lambda *a, **k: ScanResult([], [], False, "off", []))
    rc = cli.main([
        "scan", "--target", "/proj", "--profile", "quick", "--out", str(tmp_path),
    ])
    assert rc == 0


def test_main_scan_verify_secrets_sets_policy(monkeypatch, tmp_path):
    captured = {}

    def fake(*a, **k):
        captured.update(k)
        return ScanResult([], [], False, "off", [])

    monkeypatch.setattr(cli, "run_scan", fake)
    cli.main(["scan", "--target", "/proj", "--profile", "quick",
              "--out", str(tmp_path), "--verify-secrets"])
    assert captured["secret_policy"] == "verify"
    assert captured["secret_runner"] is not None  # opt-in 시 runner 전달


def test_main_scan_network_off_forces_never_and_no_runner(monkeypatch, tmp_path):
    captured = {}

    def fake(*a, **k):
        captured.update(k)
        return ScanResult([], [], False, "off", [])

    monkeypatch.setattr(cli, "run_scan", fake)
    cli.main(["scan", "--target", "/proj", "--profile", "quick", "--out", str(tmp_path),
              "--verify-secrets", "--network-off"])
    assert captured["secret_policy"] == "never"  # network-off 가 verify 이김
    assert captured["secret_runner"] is None  # 네트워크 runner 미전달(전송 불가)
