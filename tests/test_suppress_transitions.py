"""억제 전이(spec §6) — 현행 동작을 그대로 고정한다. 자동 억제 없음."""
from dataclasses import replace

from secscan.models import REACHABLE, UNREACHABLE, Advisory, Component, Finding, Reachability
from secscan.suppress.engine import apply_suppressions, record_suppression


def _sca(ver="1.30", reach=UNREACHABLE):
    return Finding(category="sca", severity="high", component=Component("maven", "org.yaml:snakeyaml", ver),
                   advisory=Advisory("CVE-2022-1471"), reachability=Reachability(reach))


def _sup(f, expiry="2027-01-01", basis="unreachable"):
    return record_suppression(scope=f.dedup_key, reason="도달 불가", provenance="alice 2026-09-05", evidence="콜패스 없음",
                              expiry=expiry, basis=basis)


def test_expiry_transition_resurfaces_and_reports_invalidated():
    f = _sca()
    out = apply_suppressions([f], [_sup(f, expiry="2026-01-01")], today="2026-09-05")
    assert out.findings[0].suppression is None and out.invalidated == [f.dedup_key]


def test_version_bump_transition_silently_unmatches():
    """현행: 버전이 오르면 dedup_key 가 달라져 억제가 매칭되지 않는다(재노출). invalidated 보고는 백로그(spec §13.2)."""
    old = _sca("1.30")
    new = _sca("1.31")
    out = apply_suppressions([new], [_sup(old)], today="2026-09-05")
    assert out.findings[0].suppression is None and out.applied == 0 and out.invalidated == []


def test_reachability_change_transition_invalidates_unreachable_basis():
    f = _sca(reach=UNREACHABLE)
    now_reachable = replace(f, reachability=Reachability(REACHABLE))
    out = apply_suppressions([now_reachable], [_sup(f, basis="unreachable")], today="2026-09-05")
    assert out.findings[0].suppression is None and out.invalidated == [f.dedup_key]
