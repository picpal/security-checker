"""M1 스캔 파이프라인 — run_scan (orchestrate → 정규화 → 도달성 → 부분실패 집계).

fake 어댑터(골든 페이로드) + 골든 슬라이스 기반 provider 로 결정적 검증.
"""

import time
from pathlib import Path

from secscan.adapters.base import FAILED, OK, RawResult
from secscan.profiles import build_adapters, get_profile
from secscan.reachability.depscan import decide_reachability, parse_invoked_symbols
from secscan.scan import run_scan
from secscan.suppress.engine import record_suppression

GOLDEN = Path(__file__).parent / "golden"
TRIVY = (GOLDEN / "trivy-vuln-maven-app.json").read_text()
OSV = (GOLDEN / "osv-vuln-maven-app.json").read_text()
SLICE = (GOLDEN / "atom-usages-vuln-maven-app.json").read_text()
GITLEAKS = (GOLDEN / "gitleaks-secret-app.json").read_text()
SECRET_FILE = "fixtures/secret-app/config/application.properties"


class FakeAdapter:
    def __init__(self, name, payload="", status=OK, delay=0.0):
        self.name = name
        self._payload = payload
        self._status = status
        self._delay = delay  # M1(최종 리뷰) — 완료 순서를 뒤집는 테스트용 지연

    def run(self, target, **kw):
        if self._delay:
            time.sleep(self._delay)
        return RawResult(self.name, self._status, payload=self._payload)


def _by_cve(findings, cve):
    return next(f for f in findings if f.advisory and (f.advisory.id == cve or cve in f.advisory.aliases))


def _depscan_provider(target, timeout, findings):
    return decide_reachability(findings, parse_invoked_symbols(SLICE))


def test_run_scan_merges_two_tools_into_consensus():
    res = run_scan(
        "/proj", get_profile("accurate-sca"),
        adapters=[FakeAdapter("trivy", TRIVY), FakeAdapter("osv-scanner", OSV)],
        reachability_provider=None,
    )
    assert _by_cve(res.findings, "CVE-2022-42889").consensus.score == 2


def test_run_scan_merge_order_independent_of_adapter_completion_order():
    """M1(최종 리뷰) — `merge_consensus` 는 첫 finding 을 base 로 삼는데, 그 순서가 스레드 완료
    순서(orchestrate 의 as_completed 도착 순서)를 그대로 물려받으면 같은 입력도 실행마다 다른
    `tool`(`"+".join(tools)`)·`consensus.tools` 순서를 낼 수 있다. `run_scan` 은 orchestrate 직후
    도구 이름으로 정렬해 이 비결정성을 없앤다 — 어느 쪽이 늦게 끝나든 결과가 같아야 한다."""
    slow_trivy = run_scan(
        "/proj", get_profile("accurate-sca"),
        adapters=[FakeAdapter("trivy", TRIVY, delay=0.05), FakeAdapter("osv-scanner", OSV)],
        reachability_provider=None,
    )
    slow_osv = run_scan(
        "/proj", get_profile("accurate-sca"),
        adapters=[FakeAdapter("trivy", TRIVY), FakeAdapter("osv-scanner", OSV, delay=0.05)],
        reachability_provider=None,
    )
    a = _by_cve(slow_trivy.findings, "CVE-2022-42889")
    b = _by_cve(slow_osv.findings, "CVE-2022-42889")
    assert a.tool == b.tool == "osv-scanner+trivy"
    assert a.consensus.tools == b.consensus.tools == ("osv-scanner", "trivy")


def test_run_scan_applies_reachability_when_enabled():
    res = run_scan(
        "/proj", get_profile("accurate-sca"),
        adapters=[FakeAdapter("trivy", TRIVY), FakeAdapter("osv-scanner", OSV)],
        reachability_provider=_depscan_provider,
        env_ok=lambda: True, count_loc=lambda t: 10,
    )
    assert res.reachability_ran is True
    assert _by_cve(res.findings, "CVE-2022-42889").reachability.status == "reachable"
    assert _by_cve(res.findings, "CVE-2022-1471").reachability.status == "unreachable"


def test_run_scan_quick_profile_does_not_run_reachability():
    def boom(*a, **k):
        raise AssertionError("reachability should not run for quick")

    res = run_scan(
        "/proj", get_profile("quick"),
        adapters=[FakeAdapter("trivy", TRIVY)],
        reachability_provider=boom,
    )
    assert res.reachability_ran is False


def test_run_scan_reports_partial_failures():
    res = run_scan(
        "/proj", get_profile("accurate-sca"),
        adapters=[FakeAdapter("trivy", TRIVY), FakeAdapter("osv-scanner", "", status=FAILED)],
        reachability_provider=None,
    )
    assert [r.tool for r in res.partial_failures] == ["osv-scanner"]
    # trivy 결과는 온전히 유지
    assert _by_cve(res.findings, "CVE-2022-42889").consensus.tools == ("trivy",)


def test_run_scan_verifies_secrets_when_policy_verify():
    res = run_scan(
        "/proj", get_profile("quick"),
        adapters=[FakeAdapter("gitleaks", GITLEAKS)],
        reachability_provider=None,
        secret_policy="verify",
        secret_runner=lambda t: {SECRET_FILE},
    )
    assert res.secret_verified_count == 3  # 골든의 시크릿 3건 모두 같은 파일
    assert all(f.verified for f in res.findings if f.category == "secret")


def test_run_scan_off_policy_never_calls_secret_runner():
    def boom(t):
        raise AssertionError("off 정책에서 검증 runner 호출 금지(네트워크 전송 없음)")

    res = run_scan(
        "/proj", get_profile("quick"),
        adapters=[FakeAdapter("gitleaks", GITLEAKS)],
        reachability_provider=None,
        secret_policy="off",
        secret_runner=boom,
    )
    assert res.secret_verified_count == 0
    assert all(f.verified is None for f in res.findings if f.category == "secret")


def test_run_scan_exclude_drops_findings_by_path():
    # trivy 골든의 SCA 출처는 pom.xml. --exclude 로 그 경로를 빼면 SCA 가 사라진다.
    base = run_scan("/p", get_profile("quick"),
                    adapters=[FakeAdapter("trivy", TRIVY)], reachability_provider=None)
    assert len(base.findings) > 0
    src = base.findings[0].source  # "pom.xml"
    out = run_scan("/p", get_profile("quick"),
                   adapters=[FakeAdapter("trivy", TRIVY)], reachability_provider=None,
                   exclude=[src])
    assert len(out.findings) == 0


def test_run_scan_enriches_compliance_from_cwe():
    # 골든 SCA(snakeyaml CVE-2022-1471 = CWE-502 역직렬화)는 KISA/PCI 로 매핑된다.
    res = run_scan("/p", get_profile("quick"),
                   adapters=[FakeAdapter("trivy", TRIVY)], reachability_provider=None)
    deser = _by_cve(res.findings, "CVE-2022-1471")
    assert deser.compliance is not None
    assert any(w.name == "신뢰할 수 없는 데이터의 역직렬화" for w in deser.compliance.kisa)
    assert any("injection" in p for p in deser.compliance.pci)


def test_run_scan_applies_human_confirmed_suppression():
    base = run_scan("/p", get_profile("quick"),
                    adapters=[FakeAdapter("trivy", TRIVY)], reachability_provider=None)
    key = base.findings[0].dedup_key
    s = record_suppression(scope=key, reason="r", provenance="alice", evidence="e",
                           expiry="2099-12-31")
    res = run_scan("/p", get_profile("quick"),
                   adapters=[FakeAdapter("trivy", TRIVY)], reachability_provider=None,
                   suppressions=[s], today="2026-06-27")
    suppressed = [f for f in res.findings if f.suppression]
    assert len(suppressed) == 1
    assert res.suppressed_count == 1


def test_run_scan_baseline_suppresses_known_findings():
    base = run_scan("/p", get_profile("quick"),
                    adapters=[FakeAdapter("trivy", TRIVY)], reachability_provider=None)
    keys = {f.dedup_key for f in base.findings}
    res = run_scan("/p", get_profile("quick"),
                   adapters=[FakeAdapter("trivy", TRIVY)], reachability_provider=None,
                   baseline_keys=keys)
    assert res.suppressed_count == len(base.findings)  # 모두 baseline → 억제


def test_profiles_build_expected_adapters():
    # accurate-sca 는 BOM 기반 SCA (tool name 은 trivy, parse_trivy 재사용)
    names = [a.name for a in build_adapters(get_profile("accurate-sca"))]
    assert names == ["trivy"]
    assert get_profile("quick").reachability is False
    assert get_profile("accurate-sca").reachability is True


def test_all_profiles_build_valid_adapters():
    from secscan.profiles import PROFILES
    for name in ("quick", "accurate-sca", "standard", "deep"):
        assert name in PROFILES
        adapters = build_adapters(get_profile(name))
        assert adapters and all(hasattr(a, "run") for a in adapters)


# --- V0: TraceSink ---
from secscan.scan import TraceSink


def test_trace_sink_records_stage_order_and_counts():
    sink = TraceSink()
    run_scan(
        "/proj", get_profile("accurate-sca"),
        adapters=[FakeAdapter("trivy", TRIVY), FakeAdapter("osv-scanner", OSV),
                  FakeAdapter("gitleaks", "", status=FAILED)],
        reachability_provider=_depscan_provider,
        env_ok=lambda: True, count_loc=lambda t: 10,
        trace=sink,
    )
    raw_tools = {(r["tool"], r["status"]) for r in sink.raw}
    assert ("gitleaks", FAILED) in raw_tools and ("trivy", OK) in raw_tools
    names = [s["stage"] for s in sink.stages]
    assert names[:2] == sorted(names[:2]) and all(n.startswith("normalize:") for n in names[:2])
    assert names[2:] == ["merge", "exclude", "reachability", "disposition", "final"]
    merge = next(s for s in sink.stages if s["stage"] == "merge")
    assert merge["count"] == len(merge["keys"]) > 0
    d = sink.to_dict()
    assert set(d) == {"raw", "stages"}


def test_run_scan_without_trace_is_unchanged():
    a = run_scan("/proj", get_profile("accurate-sca"),
                 adapters=[FakeAdapter("trivy", TRIVY)], reachability_provider=None)
    b = run_scan("/proj", get_profile("accurate-sca"),
                 adapters=[FakeAdapter("trivy", TRIVY)], reachability_provider=None, trace=TraceSink())
    assert [f.dedup_key for f in a.findings] == [f.dedup_key for f in b.findings]


from secscan.models import ScannerStatus

def test_run_scan_reports_actual_scanner_status_sorted_by_tool():
    res = run_scan("/proj", get_profile("quick"),
                   adapters=[FakeAdapter("trivy", TRIVY), FakeAdapter("gitleaks", "", status=FAILED)],
                   reachability_provider=None)
    tools = [s.tool for s in res.scanner_status]
    assert tools == ["gitleaks", "trivy"]
    assert {s.tool: s.status for s in res.scanner_status} == {"gitleaks": "failed", "trivy": "ok"}
    assert all(isinstance(s, ScannerStatus) for s in res.scanner_status)


def test_run_scan_ends_with_disposition_stage_and_every_finding_decided():
    sink = TraceSink()
    res = run_scan("/proj", get_profile("quick"), adapters=[FakeAdapter("trivy", TRIVY), FakeAdapter("gitleaks", GITLEAKS)],
                   reachability_provider=None, trace=sink)
    stages = [s["stage"] for s in sink.stages]
    assert "disposition" in stages and "compliance" not in stages
    assert stages.index("disposition") == stages.index("final") - 1
    assert all(f.disposition is not None for f in res.findings)
    assert all(f.compliance is not None for f in res.findings if f.category == "sast" and f.cwe)
