"""M1 정확도 측정 — 도달성 on/off FP 감소 + ground truth 채점(순수)."""

import pytest

from secscan.measure import reachability_stats, score_ground_truth
from secscan.models import (
    REACHABLE,
    UNKNOWN,
    UNREACHABLE,
    Advisory,
    Component,
    Finding,
    Reachability,
)


def _f(pkg, cve, reach):
    return Finding(
        category="sca", severity="high",
        component=Component("maven", pkg, "1.0"),
        advisory=Advisory(cve, aliases=(cve,)),
        reachability=Reachability(reach),
    )


def test_reachability_stats_counts_and_noise_reduction():
    findings = [
        _f("a", "CVE-1", REACHABLE),
        _f("b", "CVE-2", UNREACHABLE),
        _f("c", "CVE-3", UNKNOWN),
    ]
    s = reachability_stats(findings)
    assert s.total == 3
    assert s.reachable == 1
    assert s.unreachable == 1
    assert s.unknown == 1
    # off=모두 actionable(3), on=actionable(reachable+unknown=2) → 1건 강등
    assert s.actionable_off == 3
    assert s.actionable_on == 2
    assert s.noise_reduction == pytest.approx(1 / 3)


def test_score_ground_truth_all_correct():
    findings = [
        _f("org.apache.commons:commons-text", "CVE-2022-42889", REACHABLE),
        _f("org.yaml:snakeyaml", "CVE-2022-1471", UNREACHABLE),
    ]
    gt = {
        "reachable": [{"package": "commons-text", "cve": "CVE-2022-42889"}],
        "unreachable": [{"package": "snakeyaml", "cve": "CVE-2022-1471"}],
    }
    score = score_ground_truth(findings, gt)
    assert score.reachable_correct == 1
    assert score.unreachable_correct == 1
    assert score.mistakes == []
    assert score.accuracy == pytest.approx(1.0)


def test_score_ground_truth_detects_mistake():
    # snakeyaml 이 잘못 reachable 로 판정된 경우
    findings = [
        _f("org.yaml:snakeyaml", "CVE-2022-1471", REACHABLE),
    ]
    gt = {"reachable": [], "unreachable": [{"package": "snakeyaml", "cve": "CVE-2022-1471"}]}
    score = score_ground_truth(findings, gt)
    assert score.unreachable_correct == 0
    assert len(score.mistakes) == 1
    assert "snakeyaml" in score.mistakes[0]
