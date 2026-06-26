"""M0 doctor — 환경 진단 순수 로직 테스트.

probe(부수효과)는 raw 텍스트만 캡처하고, evaluate(순수)가 버전 추출·비교·판정을
한다. 따라서 여기 테스트는 실제 시스템을 건드리지 않고 캔드 raw probe로 결정적으로
검증한다.
"""

from secscan.doctor import (
    MISSING,
    OK,
    OUTDATED,
    UNKNOWN,
    Requirement,
    RawProbe,
    evaluate,
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
