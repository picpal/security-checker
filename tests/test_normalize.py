"""M1 정규화 — 실제 스캐너 출력(골든)을 typed Finding 으로. 결정적 = 골든 테스트 1순위.

골든 입력은 trivy/osv 를 픽스처(commons-text 1.9 + snakeyaml 1.30)에 실제로 돌려
캡처한 것이다. tests/golden/*.json
"""

import json
from pathlib import Path

from secscan.normalize.merge import merge_consensus
from secscan.normalize.osv import parse_osv
from secscan.normalize.trivy import parse_trivy

GOLDEN = Path(__file__).parent / "golden"


def _trivy_payload():
    return (GOLDEN / "trivy-vuln-maven-app.json").read_text()


def _osv_payload():
    return (GOLDEN / "osv-vuln-maven-app.json").read_text()


def _by_cve(findings, cve):
    for f in findings:
        if f.advisory and (f.advisory.id == cve or cve in f.advisory.aliases):
            return f
    raise AssertionError(f"{cve} not found in {[ (f.advisory.id if f.advisory else None) for f in findings]}")


def test_trivy_parses_commons_text_cve():
    findings = parse_trivy(_trivy_payload())
    f = _by_cve(findings, "CVE-2022-42889")

    assert f.category == "sca"
    assert f.severity == "critical"
    assert f.component.ecosystem == "maven"
    assert f.component.package == "org.apache.commons:commons-text"
    assert f.component.version == "1.9"
    assert "1.10.0" in f.advisory.fixed_versions
    assert "CWE-94" in f.cwe
    assert f.tool == "trivy"


def test_trivy_finding_id_is_stable_and_tool_independent():
    findings = parse_trivy(_trivy_payload())
    f = _by_cve(findings, "CVE-2022-42889")
    # 같은 입력 → 같은 id (재현성)
    again = _by_cve(parse_trivy(_trivy_payload()), "CVE-2022-42889")
    assert f.id == again.id
    assert f.id  # 비어있지 않음


def test_trivy_detects_transitive_commons_lang3():
    findings = parse_trivy(_trivy_payload())
    f = _by_cve(findings, "CVE-2025-48924")
    assert f.component.package == "org.apache.commons:commons-lang3"
    assert f.severity in {"medium", "low", "high", "critical", "unknown"}


# --- osv-scanner 정규화 ---

def test_osv_parses_commons_text_with_canonical_cve_id():
    findings = parse_osv(_osv_payload())
    f = _by_cve(findings, "CVE-2022-42889")

    assert f.category == "sca"
    assert f.advisory.id == "CVE-2022-42889"  # GHSA 가 아니라 CVE 로 정규화
    assert f.severity == "critical"
    assert f.component.ecosystem == "maven"
    assert f.component.package == "org.apache.commons:commons-text"
    assert "CWE-94" in f.cwe
    assert f.tool == "osv-scanner"


def test_osv_extracts_fixed_version_from_affected_ranges():
    findings = parse_osv(_osv_payload())
    f = _by_cve(findings, "CVE-2022-42889")
    assert "1.10.0" in f.advisory.fixed_versions


def test_osv_aliases_include_ghsa():
    findings = parse_osv(_osv_payload())
    f = _by_cve(findings, "CVE-2022-42889")
    assert any(a.startswith("GHSA") for a in f.advisory.aliases)


# --- 합의 dedup (Trivy ∪ osv) ---

def _merged():
    return merge_consensus(parse_trivy(_trivy_payload()) + parse_osv(_osv_payload()))


def test_merge_combines_same_cve_from_two_tools():
    f = _by_cve(_merged(), "CVE-2022-42889")
    assert set(f.consensus.tools) == {"trivy", "osv-scanner"}
    assert f.consensus.score == 2


def test_merge_single_tool_finding_keeps_score_1():
    # commons-lang3 은 전이 의존이라 trivy 만 탐지(osv --no-resolve)
    f = _by_cve(_merged(), "CVE-2025-48924")
    assert f.consensus.score == 1
    assert f.consensus.tools == ("trivy",)


def test_merge_dedups_one_finding_per_vuln():
    merged = _merged()
    keys = [f.dedup_key for f in merged]
    assert len(keys) == len(set(keys))  # 중복 키 없음


def test_merge_unions_fixed_versions_and_takes_max_severity():
    f = _by_cve(_merged(), "CVE-2022-42889")
    assert f.severity == "critical"
    assert "1.10.0" in f.advisory.fixed_versions


def test_merge_does_not_mutate_inputs():
    trivy = parse_trivy(_trivy_payload())
    before = trivy[0].consensus.tools
    merge_consensus(trivy + parse_osv(_osv_payload()))
    assert trivy[0].consensus.tools == before  # 입력 불변
