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


# --- V0: GT 매니페스트 로더 ---
from pathlib import Path

from secscan.measure import GtEntry, GtManifest, load_gt_manifest

GT_DIR = Path(__file__).parent.parent / "docs" / "verification" / "ground-truth"


def test_gt_b_manifest_loads_and_counts():
    m = load_gt_manifest(GT_DIR / "gt-b-sca.json")
    assert m.kind == "sca"
    assert m.snapshot == "a483b3b1"
    assert len(m.absent()) == 1
    assert m.absent()[0].advisory == "CVE-2025-59250"
    # CVE 단위 분모 46 = 보안팀 34 + 개발자 12 (absent 제외)
    assert len(m.cves()) == 46
    assert sum(1 for e in m.present() if e.origin == "dev-found") == 12
    assert "org.apache.tomcat.embed:tomcat-embed-core" in m.packages()


def test_gt_manifest_rejects_duplicate_keys(tmp_path):
    p = tmp_path / "gt.json"
    p.write_text('{"kind":"sca","snapshot":"x","scan_date":"2026-01-01","entries":['
                 '{"advisory":"CVE-1","package":"a:b","installed":"1"},'
                 '{"advisory":"CVE-1","package":"a:b","installed":"1"}]}')
    import pytest
    with pytest.raises(ValueError, match="중복"):
        load_gt_manifest(p)


def test_gt_manifest_rejects_bad_expected(tmp_path):
    p = tmp_path / "gt.json"
    p.write_text('{"kind":"sca","snapshot":"x","scan_date":"2026-01-01","entries":['
                 '{"advisory":"CVE-1","package":"a:b","installed":"1","expected":"maybe"}]}')
    import pytest
    with pytest.raises(ValueError, match="expected"):
        load_gt_manifest(p)


def test_gt_a_manifest_classes_are_fixed():
    m = load_gt_manifest(GT_DIR / "gt-a-source.json")
    assert m.kind == "source"
    classes = {e.get("class") for e in m.raw_entries}
    assert classes == {"in-category", "measure-then-classify", "out-of-category"}
    in_cat = [e for e in m.raw_entries if e["class"] == "in-category"]
    assert {e["cwe"] for e in in_cat} == {"CWE-259", "CWE-760", "CWE-89"}
    assert all(e["expected_rule_suffix"] for e in in_cat)
