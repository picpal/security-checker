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


# --- V0: 대조기 ---
from secscan.measure import classify_extras, match_ground_truth


def _sca(pkg, ver, cve, aliases=()):
    return Finding(
        category="sca", severity="high", tool="trivy", rule_id=cve,
        component=Component("maven", pkg, ver),
        advisory=Advisory(cve, aliases=(cve, *aliases)),
        reachability=Reachability(UNKNOWN),
    )


def _manifest(entries):
    return GtManifest(kind="sca", snapshot="s", scan_date="2026-08-31",
                      entries=tuple(entries), raw_entries=[])


def test_match_kinds_exact_version_mismatch_alias_missed():
    m = _manifest([
        GtEntry("CVE-1", "g:a", "1.0"),
        GtEntry("CVE-2", "g:b", "2.0"),
        GtEntry("CVE-3", "g:c", "3.0", aliases=("GHSA-x",)),
        GtEntry("CVE-4", "g:d", "4.0"),
    ])
    findings = [
        _sca("g:a", "1.0", "CVE-1"),          # exact
        _sca("g:b", "2.0.jre11", "CVE-2"),    # version-mismatch
        _sca("g:c", "3.0", "GHSA-x"),         # alias
        _sca("g:z", "9.9", "CVE-9"),          # extra
    ]
    r = match_ground_truth(findings, m)
    assert r.by_kind() == {"exact": 1, "version-mismatch": 1, "alias": 1, "missed": 1}
    assert r.recall_cve() == (3, 4)
    assert r.recall_entry(strict=True) == (2, 4)     # exact+alias
    assert r.recall_entry(strict=False) == (3, 4)    # + version-mismatch
    assert [x.entry.advisory for x in r.missed()] == ["CVE-4"]
    assert [f.advisory.id for f in r.extras] == ["CVE-9"]
    vm = next(x for x in r.matches if x.kind == "version-mismatch")
    assert vm.got_version == "2.0.jre11"


def test_match_absent_entry_reported_as_false_positive():
    m = _manifest([GtEntry("CVE-FP", "g:m", "1.0.jre11", expected="absent"),
                   GtEntry("CVE-OK", "g:n", "1.0", expected="absent")])
    r = match_ground_truth([_sca("g:m", "1.0", "CVE-FP")], m)
    kinds = {x.entry.advisory: x.kind for x in r.matches}
    assert kinds == {"CVE-FP": "false-positive", "CVE-OK": "absent-ok"}
    assert [x.entry.advisory for x in r.false_positives()] == ["CVE-FP"]
    assert r.extras == []  # FP 매칭에 쓰인 finding 은 초과분이 아니다


def test_match_same_cve_two_packages_counts_entries_separately():
    m = _manifest([GtEntry("CVE-J", "com.fasterxml.jackson.core:jackson-databind", "2.21.2"),
                   GtEntry("CVE-J", "tools.jackson.core:jackson-databind", "3.1.2")])
    r = match_ground_truth([_sca("com.fasterxml.jackson.core:jackson-databind", "2.21.2", "CVE-J")], m)
    assert r.recall_cve() == (1, 1)
    assert r.recall_entry(strict=True) == (1, 2)


def test_classify_extras_by_published_date_and_inventory():
    m = _manifest([GtEntry("CVE-1", "g:a", "1.0")])
    extras = [_sca("g:a", "1.0", "CVE-OLD"), _sca("g:a", "1.0", "CVE-NEW"),
              _sca("g:q", "1.0", "CVE-Q"), _sca("g:a", "1.0", "CVE-NODATE")]
    published = {"CVE-OLD": "2026-08-01", "CVE-NEW": "2026-09-02", "CVE-Q": "2026-08-01"}
    c = classify_extras(extras, m, published)
    assert c[extras[0].dedup_key] == "team-missed"
    assert c[extras[1].dedup_key] == "db-drift"
    assert c[extras[2].dedup_key] == "inventory-diff"
    assert c[extras[3].dedup_key] == "unknown-date"
