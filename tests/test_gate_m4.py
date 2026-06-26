"""M4 인수(게이트) — 억제 후 재발 억제 + stale 무효화 (결정적·오프라인 골든)."""

from dataclasses import replace
from pathlib import Path

from secscan.adapters.base import OK, RawResult
from secscan.models import REACHABLE, Reachability
from secscan.normalize import to_findings
from secscan.suppress.engine import (
    apply_suppressions,
    propose_suppressions,
    record_suppression,
)

GOLDEN = Path(__file__).parent / "golden" / "trivy-vuln-maven-app.json"


def _findings():
    return to_findings([RawResult("trivy", OK, payload=GOLDEN.read_text())])


def test_gate_suppression_resuppresses_on_rescan():
    target = _findings()[0]
    s = record_suppression(scope=target.dedup_key, reason="검토 완료",
                           provenance="alice 2026-06-27", evidence="수용 위험",
                           expiry="2099-12-31")
    out1 = apply_suppressions(_findings(), [s], today="2026-06-27")
    out2 = apply_suppressions(_findings(), [s], today="2026-06-27")  # 재스캔
    assert out1.applied == 1
    assert out2.applied == 1  # 재발 억제(결정적)


def test_gate_version_bump_invalidates_suppression():
    target = _findings()[0]
    s = record_suppression(scope=target.dedup_key, reason="r", provenance="p",
                           evidence="e", expiry="2099-12-31")
    # 의존성 버전이 올라간 동일 취약점 → dedup_key 변경
    bumped = replace(target, component=replace(target.component, version="999.0"))
    out = apply_suppressions([bumped], [s], today="2026-06-27")
    assert out.findings[0].suppression is None  # 무효화(재검토)


def test_gate_reachability_change_invalidates_unreachable_suppression():
    f = _findings()[0]
    f_unreach = replace(f, reachability=Reachability("unreachable"))
    s = record_suppression(scope=f.dedup_key, reason="도달 불가", provenance="p",
                           evidence="미호출", expiry="2099-12-31", basis="unreachable")
    # 이제 도달 가능으로 바뀜
    f_reach = replace(f, reachability=Reachability(REACHABLE))
    out = apply_suppressions([f_reach], [s], today="2026-06-27")
    assert out.findings[0].suppression is None
    assert f.dedup_key in out.invalidated


def test_gate_no_auto_suppression_propose_only():
    f = replace(_findings()[0], reachability=Reachability("unreachable"))
    candidates = propose_suppressions([f])
    assert candidates  # 후보 제시
    assert f.suppression is None  # 그러나 적용/기록은 사람 몫
