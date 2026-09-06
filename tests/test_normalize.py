"""M1 정규화 — 실제 스캐너 출력(골든)을 typed Finding 으로. 결정적 = 골든 테스트 1순위.

골든 입력은 trivy/osv 를 픽스처(commons-text 1.9 + snakeyaml 1.30)에 실제로 돌려
캡처한 것이다. tests/golden/*.json
"""

import json
from dataclasses import replace
from pathlib import Path

from secscan.adapters.base import FAILED, OK, RawResult
from secscan.models import Cvss, Occurrence
from secscan.normalize import to_findings
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


# --- to_findings: RawResult -> Finding 배선 ---

def test_to_findings_dispatches_and_merges():
    raws = [
        RawResult("trivy", OK, payload=_trivy_payload()),
        RawResult("osv-scanner", OK, payload=_osv_payload()),
    ]
    findings = to_findings(raws)
    f = _by_cve(findings, "CVE-2022-42889")
    assert f.consensus.score == 2  # 두 도구 병합


def test_to_findings_skips_failed_results():
    raws = [
        RawResult("trivy", OK, payload=_trivy_payload()),
        RawResult("osv-scanner", FAILED, error="boom"),
    ]
    findings = to_findings(raws)
    f = _by_cve(findings, "CVE-2022-42889")
    assert f.consensus.tools == ("trivy",)  # 실패한 osv 는 무시(부분 실패)


def test_to_findings_ignores_unknown_tool():
    assert to_findings([RawResult("mystery", OK, payload="{}")]) == []


_TRIVY_GOLDEN = (Path(__file__).parent / "golden" / "trivy-vuln-maven-app.json").read_text()


def test_trivy_parses_all_cvss_sources_and_published():
    f = parse_trivy(_TRIVY_GOLDEN)[0]  # 골든 첫 항목: ghsa V3 6.5 · redhat V3 3.7
    assert {(c.source, c.version, c.score) for c in f.advisory.cvss} == {("ghsa", "3.1", 6.5), ("redhat", "3.1", 3.7)}
    assert all(c.vector.startswith("CVSS:3.1/") for c in f.advisory.cvss)
    assert f.advisory.published == "2025-07-11T15:15:24.347Z"


def test_trivy_records_occurrence_with_target():
    f = parse_trivy(_TRIVY_GOLDEN)[0]
    assert f.occurrences == (Occurrence("trivy", "pom.xml", f.component.package, f.component.version),)


def test_trivy_cvss_v2_and_v40_versions():
    payload = json.dumps({"Results": [{"Target": "t", "Vulnerabilities": [{
        "VulnerabilityID": "CVE-9", "PkgName": "a:b", "InstalledVersion": "1", "Severity": "HIGH",
        "CVSS": {"nvd": {"V2Score": 5.0, "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N", "V3Score": 7.5,
                         "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
                 "ghsa": {"V40Score": 2.9, "V40Vector": "CVSS:4.0/AV:N/AC:H"}}}]}]})
    f = parse_trivy(payload)[0]
    assert [(c.source, c.version) for c in f.advisory.cvss] == [("ghsa", "4.0"), ("nvd", "2.0"), ("nvd", "3.0")]


def test_merge_unions_occurrences_and_cvss_keeps_published():
    a = parse_trivy(_TRIVY_GOLDEN)[0]
    b = replace(a, occurrences=(Occurrence("trivy", "build.gradle", a.component.package, a.component.version),),
                advisory=replace(a.advisory, cvss=(Cvss("nvd", "3.1", 7.5, "CVSS:3.1/x"),), published=None))
    m = merge_consensus([a, b])
    assert len(m) == 1
    assert {o.target for o in m[0].occurrences} == {"pom.xml", "build.gradle"}
    assert {c.source for c in m[0].advisory.cvss} == {"ghsa", "redhat", "nvd"}
    assert m[0].advisory.published == "2025-07-11T15:15:24.347Z"
