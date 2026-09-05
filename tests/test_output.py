"""M1 출력 — typed Finding → SARIF 2.1.0 (출력 전용) / Markdown.

SARIF 는 location 중심이라 SCA 전용 필드(package/advisory/reachability)는
properties bag 에 싣는다(spec §6). 도달성은 주석만, 자동 억제는 하지 않는다(원칙 4).
"""

import json
import re

from secscan.disposition import decide, decide_one
from secscan.models import (
    ACTIONABLE,
    REACHABLE,
    UNKNOWN,
    UNREACHABLE,
    Advisory,
    Component,
    Consensus,
    Finding,
    Location,
    Reachability,
    Suppression,
)
from secscan.output.markdown import to_markdown
from secscan.output.sarif import to_sarif


def _f(cve="CVE-2022-42889", sev="critical", reach=UNREACHABLE):
    return decide_one(Finding(
        category="sca", severity=sev, title="Text4Shell", rule_id=cve,
        tool="trivy+osv-scanner", cwe=("CWE-94",),
        component=Component("maven", "org.apache.commons:commons-text", "1.9"),
        advisory=Advisory(cve, aliases=(cve,), fixed_versions=("1.10.0",)),
        reachability=Reachability(reach, source="dep-scan"),
        consensus=Consensus(("trivy", "osv-scanner"), 2),
    ))


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


def test_sarif_human_confirmed_suppression_is_emitted():
    from secscan.models import Suppression
    f = _f()
    f.suppression = Suppression(
        state="suppressed", reason="도달 불가", provenance="alice",
        evidence="미호출", expiry="2099-12-31", scope="k", basis="unreachable",
    )
    res = to_sarif([f])["runs"][0]["results"][0]
    assert len(res["suppressions"]) == 1
    assert res["suppressions"][0]["justification"] == "도달 불가"


def test_sarif_location_based_finding_emits_locations():
    f = Finding(category="secret", severity="high", rule_id="aws-access-token",
                location=Location("config/app.properties", start_line=4, end_line=4))
    res = to_sarif([f])["runs"][0]["results"][0]
    assert "locations" in res
    phys = res["locations"][0]["physicalLocation"]
    assert phys["artifactLocation"]["uri"] == "config/app.properties"
    assert phys["region"]["startLine"] == 4


def test_sarif_component_finding_has_no_locations():
    # SCA(component 기반)는 위치가 없으므로 locations 를 만들지 않는다(빈 리스트 아님)
    res = to_sarif([_f()])["runs"][0]["results"][0]
    assert "locations" not in res


def test_sarif_carries_compliance_in_properties():
    from secscan.compliance import map_compliance

    f = _f()  # CWE-94 코드삽입
    f.compliance = map_compliance(f.cwe)
    props = to_sarif([f])["runs"][0]["results"][0]["properties"]
    assert any(w["name"] == "코드 삽입" for w in props["compliance"]["kisa"])
    assert any("injection" in p for p in props["compliance"]["pci"])
    json.dumps(props)  # dict/list/str 만 — 직렬화 가능


def test_sarif_no_compliance_key_when_unmapped():
    props = to_sarif([_f()])["runs"][0]["results"][0]["properties"]  # compliance None
    assert "compliance" not in props


def test_sarif_is_json_serializable():
    json.dumps(to_sarif([_f()]))  # 예외 없어야 함
    json.dumps(to_sarif([Finding(category="secret", severity="high", rule_id="x",
                                 location=Location("a.txt", start_line=1))]))


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


def test_markdown_suppressed_findings_go_to_separate_section():
    from secscan.models import Suppression
    f = _reachable()
    f.suppression = Suppression(state="suppressed", reason="도달 불가 확정",
                                provenance="alice", evidence="e", expiry="2099-12-31",
                                scope="k", basis="unreachable")
    md = to_markdown([decide_one(f)])  # 버킷은 판정 H 를 거친 disposition 만 읽는다
    assert "억제됨" in md
    assert "alice" in md  # provenance 노출(감사)
    # 억제된 항목은 우선 조치에 중복 노출되지 않는다
    assert md.count("CVE-2022-42889") == 1


def test_markdown_omits_sast_note_when_no_sast():
    md = to_markdown([_reachable()])
    assert "intraprocedural" not in md


def test_markdown_shows_kisa_and_pci_labels_for_mapped_finding():
    from secscan.compliance import map_compliance

    f = _sast()  # CWE-89
    f.compliance = map_compliance(f.cwe)
    md = to_markdown([f])
    assert "SQL 삽입" in md
    assert "KISA" in md
    assert "PCI-DSS 6.2.4" in md


def test_markdown_omits_compliance_when_unmapped():
    md = to_markdown([_secret()])  # cwe 없음 → compliance None
    assert "KISA" not in md
    assert "컴플라이언스" not in md


def test_markdown_summary_shows_compliance_rollup():
    from secscan.compliance import map_compliance

    f = _sast()
    f.compliance = map_compliance(f.cwe)
    md = to_markdown([f])
    assert "컴플라이언스" in md  # 요약 롤업


# --- B2: severity 한글 + SAST 검토 후보 섹션 ---

def test_markdown_uses_korean_severity_in_heading_and_summary():
    md = to_markdown([_reachable()])  # critical
    assert "심각" in md
    assert "CRITICAL" not in md  # 영문 heading 사라짐
    assert "critical" not in md  # 영문 요약 사라짐


def test_markdown_sast_review_goes_to_review_section():
    f = Finding(category="sast", severity="high", rule_id="weak-rule", confidence="low",
                location=Location("A.java", start_line=1))
    md = to_markdown([f])
    assert "검토 후보" in md
    assert "weak-rule" in md


def test_markdown_separates_sast_actionable_and_review():
    act = Finding(category="sast", severity="high", rule_id="ACT-RULE", confidence="high",
                  location=Location("A.java", start_line=1))
    rev = Finding(category="sast", severity="high", rule_id="REV-RULE", confidence="low",
                  location=Location("B.java", start_line=2))
    md = to_markdown(decide([act, rev]))  # 버킷은 판정 H 를 거친 disposition 만 읽는다
    assert md.index("우선 조치") < md.index("검토 후보")
    assert md.index("ACT-RULE") < md.index("검토 후보")  # actionable 은 우선 조치에
    assert md.index("검토 후보") < md.index("REV-RULE")  # review 는 검토 후보 섹션에


def test_sarif_carries_confidence_and_sast_tier():
    f = decide_one(Finding(category="sast", severity="high", confidence="high", rule_id="x",
                           location=Location("A.java", start_line=1)))
    props = to_sarif([f])["runs"][0]["results"][0]["properties"]
    assert props["confidence"] == "high"
    assert props["sastTier"] == "actionable"


def test_sarif_no_confidence_or_tier_for_non_sast():
    props = to_sarif([_f()])["runs"][0]["results"][0]["properties"]  # SCA, confidence unknown
    assert "confidence" not in props
    assert "sastTier" not in props


def test_markdown_sast_note_mentions_ce_and_kotlin_limits():
    md = to_markdown([_sast()])
    assert "Pro" in md or "Kotlin" in md


def test_markdown_renders_actual_scanner_status_not_configured_names():
    md = to_markdown([], meta={"scanner_status": [
        {"name": "trivy", "status": "ok", "tool_version": "0.71.2", "duration_s": 8.5},
        {"name": "spotbugs", "status": "skipped", "message": "빌드 실패"},
    ]})
    line = next(l for l in md.splitlines() if l.startswith("- 스캐너:"))
    assert "trivy ok (0.71.2, 8.5s)" in line and "spotbugs skipped (빌드 실패)" in line


# --- Task 5: 출력이 disposition/tier 만 읽는다 ---

def test_markdown_buckets_come_from_disposition_only():
    reachable, unreachable = _f(cve="CVE-A", reach=REACHABLE), _f(cve="CVE-B", reach=UNREACHABLE)
    sup = Finding(**{**unreachable.__dict__, "disposition": None, "tier": None,
                     "suppression": Suppression("suppressed", "r", "alice", "e", None, unreachable.dedup_key)})
    md = to_markdown(decide([reachable, unreachable, sup]))
    pri = md.split("## 우선 조치")[1].split("## 검토 후보")[0]
    low = md.split("## 낮은 우선순위")[1].split("## 억제됨")[0]
    assert "CVE-A" in pri and "CVE-B" not in pri
    assert "CVE-B" in low and "CVE-A" not in low
    assert "## 억제됨 (사람 확정)" in md


def test_markdown_line_carries_finding_id():
    f = _f()
    assert f"· id `{f.id}`" in to_markdown([f])


def test_markdown_undecided_findings_are_visible_not_hidden():
    raw = Finding(category="secret", severity="high", rule_id="aws", location=Location("a.properties", 4))
    md = to_markdown([raw])  # H 미실행
    assert "## 미판정 (판정 단계 미실행)" in md and "aws" in md.split("## 미판정")[1]


def test_sarif_carries_id_disposition_and_tier_from_fields():
    sast = decide_one(Finding(category="sast", severity="high", rule_id="r", confidence="high",
                              location=Location("src/main/A.java", 3)))
    res = to_sarif([sast])["runs"][0]["results"][0]
    assert res["properties"]["id"] == sast.id
    assert res["properties"]["disposition"] == ACTIONABLE
    assert res["properties"]["sastTier"] == "actionable"


def test_three_outputs_agree_on_actionable_set():
    fs = decide([
        Finding(category="sast", severity="high", rule_id="s1", confidence="high", location=Location("src/main/A.java", 1)),
        Finding(category="sast", severity="high", rule_id="s2", confidence="low", location=Location("src/main/B.java", 1)),
        Finding(category="secret", severity="high", rule_id="k", location=Location("c.properties", 1)),
        Finding(category="sca", severity="high", rule_id="CVE-Z", component=Component("maven", "x:y", "1"),
                advisory=Advisory("CVE-Z"), reachability=Reachability(UNREACHABLE)),
    ])
    want = {f.id for f in fs if f.disposition == ACTIONABLE}
    md = to_markdown(fs)
    md_ids = set(re.findall(r"· id `([0-9a-f]{12})`", md.split("## 우선 조치")[1].split("## 검토 후보")[0]))
    sarif_ids = {r["properties"]["id"] for r in to_sarif(fs)["runs"][0]["results"] if r["properties"].get("disposition") == ACTIONABLE}
    assert md_ids == sarif_ids == want and len(want) == 2
