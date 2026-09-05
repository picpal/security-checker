"""M0 doctor — CLI 렌더링/exit code 테스트.

렌더링은 순수(report -> str)라 결정적으로 검증한다. main 은 run_doctor 를
주입/대체해 exit code 계약만 검증한다.
"""

import json

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


def test_render_marks_optional_missing_tool_as_non_blocking():
    """/secscan-setup 이 차단 항목을 먼저 설치하려면 출력에 선택 여부가 보여야 한다."""
    report = DoctorReport([
        _status("depscan", False, None, False, MISSING),
        _status("trufflehog", False, None, False, MISSING, optional=True),
    ])
    lines = cli.render_doctor(report).splitlines()
    blocker = next(ln for ln in lines if "depscan" in ln)
    opt = next(ln for ln in lines if "trufflehog" in ln)
    assert "선택" not in blocker
    assert "선택" in opt


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
    # 판정 H 를 거친 finding 을 반환한다 — run_scan 이 항상 decide() 를 적용하므로
    # (출력은 disposition/tier 만 읽고 재계산하지 않는다, spec §7.4).
    from secscan.disposition import decide_one

    return decide_one(Finding(
        category="sca", severity=sev, rule_id=cve,
        component=Component("maven", pkg, "1.0"),
        advisory=Advisory(cve, aliases=(cve,)),
        reachability=Reachability(reach),
    ))


def test_render_scan_summary_shows_counts_and_reachability():
    res = ScanResult(
        findings=[_reach("a", "CVE-1", "critical", REACHABLE),
                  _reach("b", "CVE-2", "high", UNREACHABLE)],
        raw_results=[], reachability_ran=True, reachability_reason="ok",
    )
    out = cli.render_scan_summary(res)
    assert "도달 가능" in out
    assert "2" in out


def test_render_scan_summary_shows_compliance_count():
    from secscan.compliance import map_compliance
    from secscan.models import Finding, Location

    f = Finding(category="sast", severity="high", rule_id="x",
                location=Location("A.java", start_line=1), cwe=("CWE-89",))
    f.compliance = map_compliance(f.cwe)
    out = cli.render_scan_summary(ScanResult(findings=[f], raw_results=[]))
    assert "컴플라이언스" in out
    assert "KISA" in out


def test_has_actionable_gates_by_sast_tier_and_reachability():
    # _has_actionable 은 disposition 만 읽는다(재계산 금지) — 입력은 판정 H(decide)를 거친다.
    from secscan.disposition import decide
    from secscan.models import UNREACHABLE, Finding, Location, Reachability

    review = Finding(category="sast", severity="high", confidence="low",
                     location=Location("A.java", start_line=1))
    actionable = Finding(category="sast", severity="high", confidence="high",
                         location=Location("B.java", start_line=1))
    secret = Finding(category="secret", severity="high", location=Location("c", start_line=1))
    unreach_sca = Finding(category="sca", severity="high",
                          reachability=Reachability(UNREACHABLE))
    assert cli._has_actionable(decide([review])) is False       # review SAST 비게이트(P1③)
    assert cli._has_actionable(decide([actionable])) is True    # actionable SAST 게이트
    assert cli._has_actionable(decide([secret])) is True        # secret 게이트
    assert cli._has_actionable(decide([unreach_sca])) is False  # 도달 불가 SCA 비게이트
    assert cli._has_actionable(decide([review, actionable])) is True


def test_render_scan_summary_shows_sast_tiers():
    from secscan.models import Finding, Location

    act = Finding(category="sast", severity="high", confidence="high",
                  location=Location("A.java", start_line=1))
    rev = Finding(category="sast", severity="high", confidence="low",
                  location=Location("B.java", start_line=2))
    out = cli.render_scan_summary(ScanResult(findings=[act, rev], raw_results=[]))
    assert "검토후보" in out


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


def test_main_scan_write_baseline(monkeypatch, tmp_path):
    findings = [_reach("commons-text", "CVE-1", "high", UNREACHABLE)]
    monkeypatch.setattr(cli, "run_scan", lambda *a, **k: ScanResult(findings, [], False, "off", []))
    bl = tmp_path / "baseline.json"
    cli.main(["scan", "--target", "/p", "--profile", "quick",
              "--out", str(tmp_path), "--write-baseline", str(bl)])
    import json as _json
    assert bl.exists()
    assert "keys" in _json.loads(bl.read_text())


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


# --- fetch / clean 커맨드 (슬래시 커맨드가 호출하는 결정적 진입점) ---

def test_main_fetch_prints_path_and_sha(tmp_path, capsys, monkeypatch):
    from secscan.fetch import Clone

    dest = tmp_path / "github.com__owner__repo"
    monkeypatch.setattr(
        cli, "fetch",
        lambda url, base, **kw: Clone("github.com__owner__repo", dest, url, "deadbeef"),
    )
    rc = cli.main(["fetch", "https://github.com/owner/repo.git", "--base", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert str(dest) in out
    assert "deadbeef" in out


def test_main_fetch_reports_failure_without_traceback(tmp_path, capsys, monkeypatch):
    from secscan.fetch import FetchError

    def boom(url, base, **kw):
        raise FetchError("클론 실패(128): repository not found")

    monkeypatch.setattr(cli, "fetch", boom)
    rc = cli.main(["fetch", "https://github.com/owner/nope.git", "--base", str(tmp_path)])
    captured = capsys.readouterr()
    assert rc == 1
    assert "repository not found" in (captured.out + captured.err)


def test_main_clean_list_shows_clones(tmp_path, capsys):
    (tmp_path / "github.com__owner__repo").mkdir(parents=True)
    rc = cli.main(["clean", "--list", "--base", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "github.com__owner__repo" in out


def test_main_clean_list_on_empty_base_is_not_an_error(tmp_path, capsys):
    rc = cli.main(["clean", "--list", "--base", str(tmp_path / "missing")])
    assert rc == 0
    assert "없" in capsys.readouterr().out


def test_main_clean_removes_all(tmp_path, capsys):
    (tmp_path / "github.com__a__app").mkdir(parents=True)
    (tmp_path / "github.com__b__app").mkdir(parents=True)
    rc = cli.main(["clean", "--base", str(tmp_path)])
    assert rc == 0
    assert list(tmp_path.iterdir()) == []
    assert "2" in capsys.readouterr().out


def test_main_clean_one_slug(tmp_path):
    (tmp_path / "github.com__a__app").mkdir(parents=True)
    keep = tmp_path / "github.com__b__app"
    keep.mkdir(parents=True)
    rc = cli.main(["clean", "--slug", "github.com__a__app", "--base", str(tmp_path)])
    assert rc == 0
    assert keep.exists()


def test_main_clean_unknown_slug_returns_1(tmp_path, capsys):
    rc = cli.main(["clean", "--slug", "nope", "--base", str(tmp_path)])
    assert rc == 1
    assert "nope" in (capsys.readouterr().out + capsys.readouterr().err)


# --- Task 5: 출력이 disposition/tier 만 읽는다 ---

import pytest
from secscan.disposition import decide
from secscan.models import Location, Suppression


def test_exit_code_ignores_human_suppressed_secret():
    """spec §7.4 알려진 결함: 억제된 secret 만 있어도 exit 1 이었다. H 이후에는 exit 0."""
    sec = Finding(category="secret", severity="high", rule_id="aws", location=Location("a.properties", 4))
    sec.suppression = Suppression("suppressed", "회수 완료", "alice 2026-09-05", "revoke 로그", "2027-01-01", sec.dedup_key)
    assert cli._has_actionable(decide([sec])) is False


def test_exit_code_true_for_actionable_and_error_when_undecided():
    sec = Finding(category="secret", severity="high", rule_id="aws", location=Location("a.properties", 4))
    assert cli._has_actionable(decide([sec])) is True
    with pytest.raises(ValueError):
        cli._has_actionable([sec])  # H 미실행 입력은 CI 게이트에서 조용히 0 이 되면 안 된다


# --- Task 6: findings.json 출력 ---

def test_scan_writes_findings_json_with_context(tmp_path, monkeypatch):
    from secscan.scan import ScanResult
    from secscan.disposition import decide
    sec = decide([Finding(category="secret", severity="high", rule_id="aws", location=Location("a.properties", 4))])
    monkeypatch.setattr(cli, "run_scan", lambda *a, **k: ScanResult(findings=sec, raw_results=[]))
    monkeypatch.setattr(cli, "build_adapters", lambda p: [])
    rc = cli.main(["scan", "--target", str(tmp_path), "--out", str(tmp_path / "out"), "--profile", "quick", "--no-reachability"])
    doc = json.loads((tmp_path / "out" / "findings.json").read_text())
    assert doc["@context"] == "secscan-findings/v1" and doc["findings"][0]["disposition"] == "actionable"
    assert rc == 1
