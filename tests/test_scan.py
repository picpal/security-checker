"""M1 스캔 파이프라인 — run_scan (orchestrate → 정규화 → 도달성 → 부분실패 집계).

fake 어댑터(골든 페이로드) + 골든 슬라이스 기반 provider 로 결정적 검증.
"""

from pathlib import Path

from secscan.adapters.base import FAILED, OK, RawResult
from secscan.profiles import build_adapters, get_profile
from secscan.reachability.depscan import decide_reachability, parse_invoked_symbols
from secscan.scan import run_scan

GOLDEN = Path(__file__).parent / "golden"
TRIVY = (GOLDEN / "trivy-vuln-maven-app.json").read_text()
OSV = (GOLDEN / "osv-vuln-maven-app.json").read_text()
SLICE = (GOLDEN / "atom-usages-vuln-maven-app.json").read_text()


class FakeAdapter:
    def __init__(self, name, payload="", status=OK):
        self.name = name
        self._payload = payload
        self._status = status

    def run(self, target, **kw):
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


def test_profiles_build_expected_adapters():
    names = [a.name for a in build_adapters(get_profile("accurate-sca"))]
    assert names == ["trivy", "osv-scanner"]
    assert get_profile("quick").reachability is False
    assert get_profile("accurate-sca").reachability is True
