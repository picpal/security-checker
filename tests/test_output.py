"""M1 출력 — typed Finding → SARIF 2.1.0 (출력 전용) / Markdown.

SARIF 는 location 중심이라 SCA 전용 필드(package/advisory/reachability)는
properties bag 에 싣는다(spec §6). 도달성은 주석만, 자동 억제는 하지 않는다(원칙 4).
"""

import json

from secscan.models import (
    REACHABLE,
    UNKNOWN,
    UNREACHABLE,
    Advisory,
    Component,
    Consensus,
    Finding,
    Location,
    Reachability,
)
from secscan.output.markdown import to_markdown
from secscan.output.sarif import to_sarif


def _f(cve="CVE-2022-42889", sev="critical", reach=UNREACHABLE):
    return Finding(
        category="sca", severity=sev, title="Text4Shell", rule_id=cve,
        tool="trivy+osv-scanner", cwe=("CWE-94",),
        component=Component("maven", "org.apache.commons:commons-text", "1.9"),
        advisory=Advisory(cve, aliases=(cve,), fixed_versions=("1.10.0",)),
        reachability=Reachability(reach, source="dep-scan"),
        consensus=Consensus(("trivy", "osv-scanner"), 2),
    )


def test_sarif_top_level_shape():
    sarif = to_sarif([_f()])
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "secscan"


def test_sarif_result_carries_sca_fields_in_properties():
    res = to_sarif([_f()])["runs"][0]["results"][0]
    assert res["ruleId"] == "CVE-2022-42889"
    assert res["level"] == "error"  # critical -> error
    props = res["properties"]
    assert props["category"] == "sca"
    assert props["package"] == "org.apache.commons:commons-text"
    assert props["version"] == "1.9"
    assert "1.10.0" in props["fixedVersions"]
    assert props["reachability"] == "unreachable"
    assert props["consensus"]["score"] == 2


def test_sarif_severity_levels():
    levels = {
        "critical": "error", "high": "error",
        "medium": "warning", "low": "note", "unknown": "note",
    }
    for sev, lvl in levels.items():
        res = to_sarif([_f(sev=sev)])["runs"][0]["results"][0]
        assert res["level"] == lvl, f"{sev} -> {lvl}"


def test_sarif_rules_are_deduplicated():
    sarif = to_sarif([_f(cve="CVE-1"), _f(cve="CVE-1"), _f(cve="CVE-2")])
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    ids = [r["id"] for r in rules]
    assert ids.count("CVE-1") == 1
    assert "CVE-2" in ids


def test_sarif_does_not_auto_suppress_unreachable():
    # 도달 불가여도 결과를 숨기지 않는다(주석만). suppressions 비어있음.
    res = to_sarif([_f(reach=UNREACHABLE)])["runs"][0]["results"][0]
    assert res.get("suppressions", []) == []


def test_sarif_is_json_serializable():
    json.dumps(to_sarif([_f()]))  # 예외 없어야 함


# --- Markdown 보고서 ---

def _reachable():
    return Finding(
        category="sca", severity="critical", title="Text4Shell",
        rule_id="CVE-2022-42889", cwe=("CWE-94",),
        component=Component("maven", "org.apache.commons:commons-text", "1.9"),
        advisory=Advisory("CVE-2022-42889", fixed_versions=("1.10.0",)),
        reachability=Reachability(REACHABLE, evidence="App.interpolate -> replace", source="dep-scan"),
        consensus=Consensus(("trivy", "osv-scanner"), 2),
    )


def _unreachable():
    return Finding(
        category="sca", severity="high", title="SnakeYAML RCE",
        rule_id="CVE-2022-1471",
        component=Component("maven", "org.yaml:snakeyaml", "1.30"),
        advisory=Advisory("CVE-2022-1471", fixed_versions=("2.0",)),
        reachability=Reachability(UNREACHABLE, source="dep-scan"),
        consensus=Consensus(("trivy", "osv-scanner"), 2),
    )


def test_markdown_has_title_and_packages():
    md = to_markdown([_reachable(), _unreachable()])
    assert md.lstrip().startswith("#")
    assert "commons-text" in md
    assert "snakeyaml" in md


def test_markdown_prioritizes_reachable_before_unreachable():
    md = to_markdown([_unreachable(), _reachable()])  # 입력 순서 반대
    assert md.index("CVE-2022-42889") < md.index("CVE-2022-1471")


def test_markdown_marks_unreachable_as_lower_priority():
    md = to_markdown([_unreachable()])
    assert "도달 불가" in md


def test_markdown_shows_fix_version():
    md = to_markdown([_reachable()])
    assert "1.10.0" in md


def test_markdown_notes_static_analysis_blind_spots():
    md = to_markdown([_reachable()])
    assert "리플렉션" in md or "사각지대" in md


def test_markdown_summary_counts_by_reachability():
    md = to_markdown([_reachable(), _unreachable()])
    # 요약에 도달 가능/불가 카운트가 있다
    assert "도달 가능" in md
    assert "도달 불가" in md


def _secret():
    return Finding(
        category="secret", severity="high", title="AWS access token",
        rule_id="aws-access-token",
        location=Location("config/application.properties", start_line=4),
    )


def test_markdown_secret_is_prioritized_not_treated_as_unreachable():
    # 시크릿은 도달성 개념이 없다(unknown). 도달 불가 SCA 와 함께 묶이면 안 된다.
    md = to_markdown([_unreachable(), _secret()])
    # 시크릿이 도달 불가 SCA(snakeyaml) 보다 앞(우선 조치)에 온다
    assert md.index("aws-access-token") < md.index("CVE-2022-1471")


def test_markdown_secret_shows_location_not_fix_version():
    md = to_markdown([_secret()])
    assert "application.properties" in md


def _sast():
    return Finding(
        category="sast", severity="high", title="SQL injection",
        rule_id="formatted-sql-string", cwe=("CWE-89",),
        location=Location("src/Vuln.java", start_line=15),
    )


def test_markdown_notes_sast_ce_taint_limitation_when_sast_present():
    md = to_markdown([_sast()])
    assert "intraprocedural" in md  # CE taint 한계 명시(spec §10.2)


def test_markdown_omits_sast_note_when_no_sast():
    md = to_markdown([_reachable()])
    assert "intraprocedural" not in md
