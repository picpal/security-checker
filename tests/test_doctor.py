"""M0 doctor — 환경 진단 순수 로직 테스트.

probe(부수효과)는 raw 텍스트만 캡처하고, evaluate(순수)가 버전 추출·비교·판정을
한다. 따라서 여기 테스트는 실제 시스템을 건드리지 않고 캔드 raw probe로 결정적으로
검증한다.
"""

import pytest

from secscan.doctor import (
    LOW,
    MISSING,
    OK,
    OUTDATED,
    REQUIREMENTS,
    UNKNOWN,
    Requirement,
    RawProbe,
    _parse_meminfo,
    _parse_sysctl_memsize,
    evaluate,
    memory_status,
    probe_tool,
    run_doctor,
)


def _req(name="trivy", **kw):
    base = dict(
        name=name,
        kind="scanner",
        purpose="의존성 취약점 탐지",
        install_hint=f"brew install {name}",
    )
    base.update(kw)
    return Requirement(**base)


def test_tool_present_and_meets_min_version_is_ok():
    reqs = [
        Requirement(
            name="java",
            kind="runtime",
            purpose="dep-scan/atom 런타임",
            min_version=(21,),
            version_regex=r'version "?(\d+(?:\.\d+)*)',
            install_hint="brew install openjdk@21",
        )
    ]
    probes = {
        "java": RawProbe(
            present=True,
            raw_version_output='openjdk version "21.0.10" 2026-01-20 LTS',
        )
    }

    report = evaluate(reqs, probes)

    s = report.statuses[0]
    assert s.version == "21.0.10"
    assert s.state == "ok"
    assert s.satisfies is True
    assert report.ok is True


def test_missing_required_tool_breaks_report():
    reqs = [_req("trivy")]
    probes = {"trivy": RawProbe(present=False)}

    report = evaluate(reqs, probes)

    s = report.statuses[0]
    assert s.present is False
    assert s.state == MISSING
    assert s.satisfies is False
    assert s.version is None
    assert report.ok is False


def test_present_but_outdated_is_flagged():
    reqs = [_req("java", kind="runtime", min_version=(21,),
                 version_regex=r'version "?(\d+(?:\.\d+)*)')]
    probes = {"java": RawProbe(present=True,
                               raw_version_output='openjdk version "17.0.9" 2024')}

    report = evaluate(reqs, probes)

    s = report.statuses[0]
    assert s.version == "17.0.9"
    assert s.state == OUTDATED
    assert s.satisfies is False
    assert report.ok is False


def test_optional_tool_missing_does_not_break_report():
    reqs = [_req("trufflehog", optional=True)]
    probes = {"trufflehog": RawProbe(present=False)}

    report = evaluate(reqs, probes)

    assert report.statuses[0].state == MISSING
    assert report.statuses[0].satisfies is False
    assert report.ok is True  # optional 누락은 전체를 깨지 않음


def test_present_without_min_version_is_ok_even_if_version_unparsed():
    # 스캐너는 보통 min_version 없음 → 존재만으로 ok
    reqs = [_req("osv-scanner", version_regex=r"nope (\d+)")]
    probes = {"osv-scanner": RawProbe(present=True, raw_version_output="weird output")}

    report = evaluate(reqs, probes)

    s = report.statuses[0]
    assert s.present is True
    assert s.version is None
    assert s.state == OK
    assert s.satisfies is True


def test_min_version_required_but_unparseable_is_not_silently_ok():
    reqs = [_req("java", kind="runtime", min_version=(21,),
                 version_regex=r"no-match (\d+)")]
    probes = {"java": RawProbe(present=True, raw_version_output="garbage output")}

    report = evaluate(reqs, probes)

    s = report.statuses[0]
    assert s.version is None
    assert s.satisfies is False
    assert s.state == UNKNOWN
    assert report.ok is False


def test_require_version_fails_when_unextractable():
    # require_version 도구(semgrep)는 버전 추출 실패 시 미충족 — 런타임 손상 감지(codex P2⑪).
    from secscan.doctor import RawProbe, Requirement, evaluate

    req = Requirement(name="semgrep", kind="scanner", purpose="p", install_hint="h",
                      version_regex=r"(\d+\.\d+\.\d+)", require_version=True)
    report = evaluate([req], {"semgrep": RawProbe(present=True,
                                                  raw_version_output="CA trust anchor error")})
    s = report.statuses[0]
    assert s.satisfies is False
    assert s.state == UNKNOWN


def test_semgrep_requirement_requires_version():
    from secscan.doctor import REQUIREMENTS

    semgrep = next(r for r in REQUIREMENTS if r.name == "semgrep")
    assert semgrep.require_version is True


# --- 메모리 자원 점검 (dep-scan 도달성용 — 경고일 뿐 전체를 깨지 않음) ---

def test_sufficient_memory_is_ok():
    s = memory_status(available_gb=16.0, recommended_gb=8.0)
    assert s.state == OK
    assert s.satisfies is True
    assert "16" in s.version  # 감지된 양 표시


def test_low_memory_is_flagged_but_optional():
    s = memory_status(available_gb=4.0, recommended_gb=8.0)
    assert s.state == LOW
    assert s.satisfies is False
    assert s.req.optional is True  # 경고 — report.ok 안 깨뜨림


def test_unmeasurable_memory_is_unknown():
    s = memory_status(available_gb=None, recommended_gb=8.0)
    assert s.state == UNKNOWN
    assert s.satisfies is False


# --- 메모리 파서 (순수) ---

def test_parse_sysctl_memsize_bytes_to_gib():
    assert _parse_sysctl_memsize("17179869184\n") == pytest.approx(16.0)


def test_parse_sysctl_memsize_garbage_is_none():
    assert _parse_sysctl_memsize("not a number") is None


def test_parse_meminfo_kb_to_gib():
    text = "MemTotal:       16384000 kB\nMemFree:  100 kB\n"
    assert _parse_meminfo(text) == pytest.approx(15.625)


def test_parse_meminfo_missing_field_is_none():
    assert _parse_meminfo("SwapTotal: 0 kB\n") is None


# --- probe 레이어 (의존성 주입) ---

def test_probe_reports_absent_when_not_on_path():
    p = probe_tool(_req("trivy"), which=lambda n: None, run=lambda r: "")
    assert p.present is False
    assert p.raw_version_output == ""


def test_probe_captures_version_output_when_present():
    p = probe_tool(
        _req("trivy"),
        which=lambda n: "/opt/homebrew/bin/trivy",
        run=lambda r: "Version: 0.50.0",
    )
    assert p.present is True
    assert "0.50.0" in p.raw_version_output


# --- 기본 REQUIREMENTS 셋 ---

def test_requirements_cover_m0_tools_and_runtimes():
    names = {r.name for r in REQUIREMENTS}
    assert {"trivy", "osv-scanner", "depscan", "atom"} <= names  # 스캐너
    assert {"java", "node"} <= names  # 런타임
    java = next(r for r in REQUIREMENTS if r.name == "java")
    assert java.min_version == (21,)  # spec: Java 21


# --- run_doctor 조립 (probe + evaluate + memory) ---

def test_run_doctor_assembles_tools_and_memory(monkeypatch):
    fake_probes = {
        r.name: RawProbe(present=True, raw_version_output="v99.0.0")
        for r in REQUIREMENTS
    }
    # java 는 min_version (21,) 이므로 21 이상으로 보이게
    fake_probes["java"] = RawProbe(present=True, raw_version_output='version "21.0.1"')

    report = run_doctor(
        probe=lambda r: fake_probes[r.name],
        mem=lambda: 16.0,
    )

    names = {s.req.name for s in report.statuses}
    assert "memory" in names  # 메모리 자원도 포함
    assert report.ok is True
