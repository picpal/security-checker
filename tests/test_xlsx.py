"""xlsx projection(spec §8) — 순수 시트 빌더. 방어(formula injection·절단·불법 문자)·집계·결정성·골든 스키마."""
import json
from pathlib import Path

from secscan.compliance import map_compliance
from secscan.disposition import decide
from secscan.models import (UNREACHABLE, REACHABLE, Advisory, Component, Consensus, Cvss, Finding,
                            Location, Occurrence, Reachability)
from secscan.output.xlsx import MAX_CHARS, TEAM_HEADER, build_sheets, sanitize_cell

SCHEMA = json.loads(Path("docs/verification/ground-truth/golden/security-team-schema.json").read_text())


def _sca(cve="CVE-1", pkg="a:b", ver="1.0", target="pom.xml", reach=UNREACHABLE, sev="high", cvss=()):
    return Finding(category="sca", severity=sev, title=f"T {cve}", tool="trivy", rule_id=cve, cwe=("CWE-89",),
                   component=Component("maven", pkg, ver),
                   advisory=Advisory(cve, aliases=(cve,), fixed_versions=("2.0",), cvss=tuple(cvss), published="2025-01-01T00:00:00Z"),
                   reachability=Reachability(reach, evidence="ev"), consensus=Consensus(("trivy",), 1),
                   references=("https://x/" + cve,), occurrences=(Occurrence("trivy", target, pkg, ver),))


def _meta():
    return {"profile": "standard", "target": "/repo", "run_date": "2026-09-05", "commit": "abc",
            "scanner_status": [{"name": "trivy", "status": "ok", "tool_version": "0.71.2", "duration_s": 8.5, "message": ""}],
            "reachability": {"ran": True, "reason": "ok"}, "secret_policy": "never", "excluded_count": 0}


def test_sanitize_formula_injection_and_controls():
    assert sanitize_cell("=SUM(A1)") == "'=SUM(A1)"
    assert sanitize_cell("  +1") == "'  +1" and sanitize_cell("\t-x") == "'\t-x" and sanitize_cell("@cmd") == "'@cmd"
    assert sanitize_cell("ok\x00\x1f text") == "ok text"
    assert sanitize_cell(3) == 3 and sanitize_cell(None) is None and sanitize_cell(True) == "True"


def test_sanitize_truncates_over_excel_limit():
    s = sanitize_cell("x" * (MAX_CHARS + 10))
    assert len(s) == MAX_CHARS and s.endswith("…[truncated]")


def test_sheet_names_and_deduped_header_match_team_schema():
    sheets = build_sheets(decide([_sca()]), _meta())
    assert list(sheets) == ["Summary", "Findings", "Deduped_CVEs", "Targets", "SAST", "Secret", "Meta"]
    assert set(SCHEMA["sheets"]) <= set(sheets)
    header, _ = sheets["Deduped_CVEs"]
    assert header[:12] == SCHEMA["deduped_cves_header"] == list(TEAM_HEADER)


def test_deduped_aggregates_occurrences_and_cvss():
    a = _sca(cvss=[Cvss("nvd", "3.1", 7.5, "v"), Cvss("redhat", "3.1", 5.9, "v")])
    b = Finding(**{**a.__dict__, "occurrences": (Occurrence("trivy", "build.gradle", "a:b", "1.0"),)})
    # merge 를 흉내: 같은 advisory 의 두 occurrence 를 가진 finding 하나
    m = Finding(**{**a.__dict__, "occurrences": a.occurrences + b.occurrences})
    header, rows = build_sheets(decide([m]), _meta())["Deduped_CVEs"]
    row = dict(zip(header, rows[0]))
    assert row["Vulnerability ID"] == "CVE-1" and row["Finding Count"] == 2
    assert row["Targets"] == "build.gradle, pom.xml" and row["Affected Packages"] == "a:b"
    assert row["Max CVSS Score"] == 7.5 and row["CVSS Source"] == "nvd"
    assert row["Disposition"] == "demoted" and row["KISA"] == map_compliance(("CWE-89",)).kisa[0].name and row["URL"] == "https://x/CVE-1"
    assert row["Published"] == "2025-01-01T00:00:00Z"
    f_header, f_rows = build_sheets(decide([m]), _meta())["Findings"]
    assert len(f_rows) == 2 and {dict(zip(f_header, r))["Target"] for r in f_rows} == {"pom.xml", "build.gradle"}


def test_secret_sheet_has_no_secret_values_and_sast_sheet_has_tier():
    sec = Finding(category="secret", severity="high", rule_id="aws-access-token", title="AWS",
                  location=Location("app.properties", 4, snippet_ref="fp123"))
    sast = Finding(category="sast", severity="high", rule_id="java.sqli", confidence="high", cwe=("CWE-89",),
                   location=Location("src/main/A.java", 10))
    sheets = build_sheets(decide([sec, sast]), _meta())
    s_header, s_rows = sheets["Secret"]
    assert s_header == ["Finding ID", "Rule", "File", "Line", "Verified", "Severity", "Suppressed", "Disposition"]
    assert "fp123" not in str(s_rows) and "AKIA" not in str(s_rows)
    t_header, t_rows = sheets["SAST"]
    assert dict(zip(t_header, t_rows[0]))["Tier"] == "actionable"


def test_meta_sheet_carries_actual_scanner_status():
    _, rows = build_sheets([], _meta())["Meta"]
    d = dict(rows)
    assert d["scanner.trivy.status"] == "ok" and d["scanner.trivy.tool_version"] == "0.71.2" and d["secret_policy"] == "never"


def test_build_is_deterministic_and_sorted():
    fs = decide([_sca("CVE-2", reach=REACHABLE), _sca("CVE-1"), _sca("CVE-3", sev="low")])
    assert build_sheets(fs, _meta()) == build_sheets(list(reversed(fs)), _meta())
    _, rows = build_sheets(fs, _meta())["Deduped_CVEs"]
    assert [r[1] for r in rows] == ["CVE-1", "CVE-2", "CVE-3"] and [r[0] for r in rows] == [1, 2, 3]


def test_all_string_cells_are_sanitized():
    f = _sca(cve="=HYPERLINK(\"x\")")
    _, rows = build_sheets(decide([f]), _meta())["Deduped_CVEs"]
    assert rows[0][1].startswith("'=")
