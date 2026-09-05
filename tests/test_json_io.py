"""findings.json — typed Finding 의 lossless 직렬화(spec §7.2). SARIF 가 아니다."""

import json

from secscan.models import (
    UNREACHABLE, Advisory, Component, Compliance, Consensus, Finding, KisaWeakness,
    Location, Reachability, Suppression,
)
from secscan.output.json_io import finding_from_dict, finding_to_dict, from_json, to_json


def _sca():
    return Finding(
        category="sca", severity="critical", title="Text4Shell", rule_id="CVE-2022-42889",
        tool="trivy+osv-scanner", cwe=("CWE-94",), owasp=("A03",), confidence="unknown",
        component=Component("maven", "org.apache.commons:commons-text", "1.9"),
        advisory=Advisory("CVE-2022-42889", aliases=("CVE-2022-42889", "GHSA-599f-7c49-w659"),
                          fixed_versions=("1.10.0",)),
        source="pom.xml",
        reachability=Reachability(UNREACHABLE, evidence="미호출", source="dep-scan"),
        consensus=Consensus(("trivy", "osv-scanner"), 2),
        references=("https://nvd.nist.gov/x",),
        suppression=Suppression("suppressed", "도달 불가", "alice 2026-09-01", "콜패스 없음",
                                "2026-12-31", "sca|maven|org.apache.commons:commons-text|1.9|CVE-2022-42889",
                                basis="unreachable"),
        compliance=Compliance(kisa=(KisaWeakness("IV-01", "입력데이터 검증 및 표현", "SQL 삽입"),),
                              pci=("PCI-DSS 6.2.4 — injection",)),
    )


def _sast():
    return Finding(category="sast", severity="high", title="SQLi", rule_id="java.sqli",
                   tool="semgrep", cwe=("CWE-89",), confidence="high",
                   location=Location("src/A.java", 10, 12, None), verified=None)


def test_round_trip_is_lossless():
    fs = [_sca(), _sast()]
    back = from_json(to_json(fs))
    assert back == fs
    assert [f.dedup_key for f in back] == [f.dedup_key for f in fs]


def test_json_shape_and_meta():
    d = json.loads(to_json([_sast()], meta={"profile": "standard"}))
    assert d["@context"] == "secscan-findings/v1"
    assert d["meta"] == {"profile": "standard"}
    f = d["findings"][0]
    assert f["id"] == _sast().id and f["dedup_key"] == _sast().dedup_key
    assert f["location"] == {"file": "src/A.java", "start_line": 10, "end_line": 12, "snippet_ref": None}
    assert f["cwe"] == ["CWE-89"]


def test_finding_from_dict_ignores_derived_fields():
    d = finding_to_dict(_sast())
    d["id"] = "zzz"; d["dedup_key"] = "zzz"; d["unknown_future_field"] = 1
    assert finding_from_dict(d) == _sast()
