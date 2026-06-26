"""M1 도달성 엔진 — 4중 안전장치(spec §10.1).

provider(실제 dep-scan)는 주입해 결정적으로 테스트한다. 안전장치:
1) doctor 사전점검 실패 → 스킵   2) 크기 인지(임계 초과) → 스킵(허용 시 진행)
3) 예산+폴백(타임아웃/에러) → reachability=unknown, 탐지결과 유지
4) 캐싱(코드 해시) → provider 재호출 안 함
"""

from secscan.models import (
    REACHABLE,
    UNKNOWN,
    UNREACHABLE,
    Advisory,
    Component,
    Finding,
)
from secscan.reachability.engine import (
    Budget,
    ReachabilityResult,
    enrich_reachability,
)


def _sca(pkg, ver, cve):
    return Finding(
        category="sca", severity="high",
        component=Component("maven", pkg, ver),
        advisory=Advisory(id=cve, aliases=(cve,)),
    )


def _findings():
    return [
        _sca("org.apache.commons:commons-text", "1.9", "CVE-2022-42889"),
        _sca("org.yaml:snakeyaml", "1.30", "CVE-2022-1471"),
    ]


def _provider_ok(target, timeout, findings):
    return ReachabilityResult(
        verdicts={
            "org.apache.commons:commons-text@1.9": REACHABLE,
            "org.yaml:snakeyaml@1.30": UNREACHABLE,
        },
        evidence={
            "org.apache.commons:commons-text@1.9": "App.interpolate -> StringSubstitutor.replace",
        },
        status="ok",
    )


def test_env_precheck_failure_skips_reachability():
    out = enrich_reachability(
        _findings(), "/proj",
        provider=_provider_ok, env_ok=lambda: False, count_loc=lambda t: 10,
    )
    assert out.ran is False
    assert out.reason == "env"
    assert all(f.reachability.status == UNKNOWN for f in out.findings)


def test_size_over_threshold_skips():
    out = enrich_reachability(
        _findings(), "/proj",
        provider=_provider_ok, env_ok=lambda: True,
        count_loc=lambda t: 999999, budget=Budget(max_loc=1000),
    )
    assert out.ran is False
    assert out.reason == "size"
    assert all(f.reachability.status == UNKNOWN for f in out.findings)


def test_size_over_threshold_runs_when_allow_large():
    out = enrich_reachability(
        _findings(), "/proj",
        provider=_provider_ok, env_ok=lambda: True,
        count_loc=lambda t: 999999, budget=Budget(max_loc=1000, allow_large=True),
    )
    assert out.ran is True


def test_provider_timeout_falls_back_to_unknown_keeping_findings():
    def slow(target, timeout, findings):
        raise TimeoutError()

    out = enrich_reachability(
        _findings(), "/proj",
        provider=slow, env_ok=lambda: True, count_loc=lambda t: 10,
    )
    assert out.ran is False
    assert out.reason == "timeout"
    assert len(out.findings) == 2  # 탐지 결과 유지
    assert all(f.reachability.status == UNKNOWN for f in out.findings)


def test_provider_error_falls_back_to_unknown():
    def boom(target, timeout, findings):
        raise RuntimeError("atom crashed")

    out = enrich_reachability(
        _findings(), "/proj",
        provider=boom, env_ok=lambda: True, count_loc=lambda t: 10,
    )
    assert out.ran is False
    assert out.reason == "error"
    assert len(out.findings) == 2


def test_provider_ok_applies_verdicts_with_source():
    out = enrich_reachability(
        _findings(), "/proj",
        provider=_provider_ok, env_ok=lambda: True, count_loc=lambda t: 10,
    )
    assert out.ran is True
    by = {f.component.package: f for f in out.findings}
    text = by["org.apache.commons:commons-text"]
    yaml = by["org.yaml:snakeyaml"]
    assert text.reachability.status == REACHABLE
    assert text.reachability.source == "dep-scan"
    assert "StringSubstitutor" in (text.reachability.evidence or "")
    assert yaml.reachability.status == UNREACHABLE


def test_component_absent_from_verdicts_stays_unknown():
    findings = _findings() + [_sca("org.apache.commons:commons-lang3", "3.11", "CVE-2025-48924")]
    out = enrich_reachability(
        findings, "/proj",
        provider=_provider_ok, env_ok=lambda: True, count_loc=lambda t: 10,
    )
    lang3 = next(f for f in out.findings if "lang3" in f.component.package)
    assert lang3.reachability.status == UNKNOWN  # 판정 없으면 unknown 유지


def test_cache_hit_skips_provider():
    calls = []

    def prov(target, timeout, findings):
        calls.append(1)
        return _provider_ok(target, timeout, findings)

    cache = {}
    common = dict(provider=prov, env_ok=lambda: True, count_loc=lambda t: 10,
                  cache=cache, code_hash=lambda t: "H1")
    enrich_reachability(_findings(), "/proj", **common)
    out2 = enrich_reachability(_findings(), "/proj", **common)
    assert len(calls) == 1  # 두 번째는 캐시 사용
    assert out2.ran is True
    assert out2.reason == "cache"
