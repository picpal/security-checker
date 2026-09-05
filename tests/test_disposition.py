"""판정 단계 H (spec §7.4) — 억제를 먼저 보고, SAST 는 tier, SCA 는 도달성, secret 은 actionable."""

import pytest

from secscan.disposition import decide, decide_one
from secscan.models import (
    ACTIONABLE, DEMOTED, REVIEW, SUPPRESSED, REACHABLE, UNKNOWN, UNREACHABLE,
    Advisory, Component, Finding, Location, Reachability, Suppression,
)


def _sca(reach=UNREACHABLE, cwe=("CWE-94",)):
    return Finding(category="sca", severity="high", rule_id="CVE-1", cwe=cwe,
                   component=Component("maven", "a:b", "1.0"), advisory=Advisory("CVE-1"),
                   reachability=Reachability(reach))


def _sast(conf="high", sev="high", file="src/main/A.java"):
    return Finding(category="sast", severity=sev, rule_id="r", confidence=conf, cwe=("CWE-89",),
                   location=Location(file, 3))


def _secret():
    return Finding(category="secret", severity="high", rule_id="aws", location=Location("app.properties", 4))


def _sup(f):
    return Suppression("suppressed", "사유", "alice 2026-09-05", "증거", "2027-01-01", f.dedup_key)


@pytest.mark.parametrize("f,expect", [
    (_sca(UNREACHABLE), DEMOTED),
    (_sca(REACHABLE), ACTIONABLE),
    (_sca(UNKNOWN), ACTIONABLE),
    (_sast("high", "high"), ACTIONABLE),
    (_sast("low", "high"), REVIEW),
    (_sast("high", "low"), REVIEW),
    (_sast("high", "high", "src/test/ATest.java"), REVIEW),
    (_secret(), ACTIONABLE),
])
def test_disposition_rules(f, expect):
    assert decide_one(f).disposition == expect


def test_suppression_wins_over_everything():
    for f in (_sca(REACHABLE), _sast("high", "high"), _secret()):
        g = Finding(**{**f.__dict__, "suppression": _sup(f)})
        assert decide_one(g).disposition == SUPPRESSED


def test_tier_is_stored_for_sast_only():
    assert decide_one(_sast("high", "high")).tier == "actionable"
    assert decide_one(_sast("low", "high")).tier == "review"
    assert decide_one(_sca()).tier is None and decide_one(_secret()).tier is None


def test_decide_fills_compliance_and_returns_new_objects():
    src = _sca(cwe=("CWE-89",))
    out = decide([src])
    assert out[0] is not src and src.compliance is None  # 입력 불변(in-place 아님)
    assert out[0].compliance is not None and out[0].compliance.kisa


def test_decide_is_idempotent():
    once = decide([_sca(), _sast(), _secret()])
    assert decide(once) == once
