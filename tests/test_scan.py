"""M1 스캔 파이프라인 — run_scan (orchestrate → 정규화 → 도달성 → 부분실패 집계).

fake 어댑터(골든 페이로드) + 골든 슬라이스 기반 provider 로 결정적 검증.
"""

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
