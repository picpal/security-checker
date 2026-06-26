"""M0 doctor — CLI 렌더링/exit code 테스트.

렌더링은 순수(report -> str)라 결정적으로 검증한다. main 은 run_doctor 를
주입/대체해 exit code 계약만 검증한다.
"""

from secscan import cli
from secscan.doctor import (
    MISSING,
    OK,
    DoctorReport,
    Requirement,
    ToolStatus,
)


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


def test_main_doctor_returns_0_when_environment_ok(monkeypatch):
    ok_report = DoctorReport([_status("trivy", True, "0.50.0", True, OK)])
    monkeypatch.setattr(cli, "run_doctor", lambda: ok_report)
    assert cli.main(["doctor"]) == 0


def test_main_doctor_returns_1_when_problems(monkeypatch):
    bad_report = DoctorReport([_status("depscan", False, None, False, MISSING)])
    monkeypatch.setattr(cli, "run_doctor", lambda: bad_report)
    assert cli.main(["doctor"]) == 1
