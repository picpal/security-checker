"""M4 억제 안전장치 (spec §12).

- record: provenance/evidence/expiry/scope 필수 (자동 생성 금지, 사람이 확정)
- apply: scope(dedup_key) 정확 매칭. 만료/버전변경/도달성변화 시 무효화(재표면)
- propose: 후보만 반환하고 적용하지 않음 (Claude 는 제안만)
"""

import pytest

from secscan.models import (
    REACHABLE,
    UNREACHABLE,
    Advisory,
    Component,
    Finding,
    Reachability,
)
from secscan.suppress.engine import (
    apply_suppressions,
    propose_suppressions,
    record_suppression,
)
from secscan.suppress.store import (
    apply_baseline,
    load_baseline,
    load_suppressions,
    save_baseline,
    save_suppressions,
)


def _sca(pkg="org.yaml:snakeyaml", ver="1.30", cve="CVE-2022-1471", reach=UNREACHABLE):
    return Finding(
        category="sca", severity="high",
        component=Component("maven", pkg, ver),
        advisory=Advisory(cve, aliases=(cve,)),
        reachability=Reachability(reach),
    )


def _suppress_for(finding, **over):
    base = dict(
        scope=finding.dedup_key,
        reason="도달 불가로 악용 불가",
        provenance="alice 2026-06-27 트리아지",
        evidence="dep-scan: snakeyaml 미호출",
        expiry="2026-12-31",
        basis="unreachable",
    )
    base.update(over)
    return record_suppression(**base)


# --- record: 필수 필드 검증 ---

def test_record_requires_provenance_evidence_expiry_scope():
    with pytest.raises(ValueError):
        record_suppression(scope="k", reason="r", provenance="", evidence="e", expiry="2026-12-31")
    with pytest.raises(ValueError):
        record_suppression(scope="k", reason="r", provenance="p", evidence="", expiry="2026-12-31")
    with pytest.raises(ValueError):
        record_suppression(scope="k", reason="r", provenance="p", evidence="e", expiry=None)
    with pytest.raises(ValueError):
        record_suppression(scope="", reason="r", provenance="p", evidence="e", expiry="2026-12-31")


def test_record_valid_returns_suppressed_entry():
    s = record_suppression(scope="k", reason="r", provenance="p", evidence="e", expiry="2026-12-31")
    assert s.state == "suppressed"


# --- apply: scope 정확 매칭 ---

def test_apply_suppresses_matching_finding():
    f = _sca()
    out = apply_suppressions([f], [_suppress_for(f)], today="2026-06-27")
    assert out.findings[0].suppression is not None
    assert out.applied == 1


def test_apply_does_not_touch_unmatched_finding():
    f = _sca()
    other = _suppress_for(_sca(cve="CVE-9999-0000"))  # 다른 scope
    out = apply_suppressions([f], [other], today="2026-06-27")
    assert out.findings[0].suppression is None
    assert out.applied == 0


# --- 무효화(stale): 만료 ---

def test_expired_suppression_resurfaces_and_queues_review():
    f = _sca()
    s = _suppress_for(f, expiry="2026-01-01")  # 과거
    out = apply_suppressions([f], [s], today="2026-06-27")
    assert out.findings[0].suppression is None  # 재표면
    assert f.dedup_key in out.invalidated  # 재검토 큐


# --- 무효화(stale): 의존성 버전 변경 ---

def test_version_bump_invalidates_suppression_by_scope():
    old = _sca(ver="1.30")
    s = _suppress_for(old)  # scope = 1.30 기준
    new = _sca(ver="1.31")  # 버전 올림 → dedup_key 변경
    out = apply_suppressions([new], [s], today="2026-06-27")
    assert out.findings[0].suppression is None  # 새 버전엔 억제 미적용(재검토)


# --- 무효화(stale): 도달성 변화 (unreachable→reachable) ---

def test_reachability_change_invalidates_unreachable_basis():
    f = _sca(reach=REACHABLE)  # 이제 도달 가능
    s = _suppress_for(f, basis="unreachable")  # 도달 불가 근거로 억제했었음
    out = apply_suppressions([f], [s], today="2026-06-27")
    assert out.findings[0].suppression is None  # 근거 무효 → 재표면
    assert f.dedup_key in out.invalidated


# --- propose: 제안만, 적용 안 함 ---

def test_propose_returns_candidates_without_applying():
    f = _sca(reach=UNREACHABLE)
    candidates = propose_suppressions([f])
    assert len(candidates) == 1
    assert candidates[0]["scope"] == f.dedup_key
    # 제안은 finding 을 건드리지 않는다
    assert f.suppression is None


# --- 영속화 (git 추적·감사 가능) ---

def test_suppressions_roundtrip(tmp_path):
    s = record_suppression(scope="k", reason="r", provenance="p", evidence="e",
                           expiry="2026-12-31", basis="unreachable")
    path = tmp_path / "vex.json"
    save_suppressions(path, [s])
    loaded = load_suppressions(path)
    assert len(loaded) == 1
    assert loaded[0].scope == "k"
    assert loaded[0].basis == "unreachable"
    assert loaded[0].provenance == "p"


def test_load_suppressions_missing_file_is_empty(tmp_path):
    assert load_suppressions(tmp_path / "nope.json") == []


# --- baseline (기존 이슈 일괄 억제, 신규만 알림) ---

def test_apply_baseline_suppresses_known_only():
    f1 = _sca(cve="CVE-1")
    f2 = _sca(cve="CVE-2")
    out = apply_baseline([f1, f2], {f1.dedup_key})
    by = {x.advisory.id: x for x in out}
    assert by["CVE-1"].suppression is not None
    assert by["CVE-1"].suppression.state == "baseline"
    assert by["CVE-2"].suppression is None  # 신규는 표면


def test_baseline_roundtrip_is_deterministic(tmp_path):
    f = _sca()
    path = tmp_path / "baseline.json"
    save_baseline(path, [f])
    keys = load_baseline(path)
    assert f.dedup_key in keys
    # 재스캔(같은 finding) → 같은 키 → 재억제
    out = apply_baseline([f], keys)
    assert out[0].suppression is not None
