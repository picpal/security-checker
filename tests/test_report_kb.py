"""지식베이스(spec §5.1) — rules.json 덮어쓰기 > 합성 폴백. 스캔 시점 생성 없음. 문장은 골든 대상."""
from pathlib import Path

from secscan.models import Advisory, Component, Finding, Location
from secscan.output.json_io import from_json
from secscan.report.kb import entry_for, load_bom_props, load_cwe, load_rules, target_version, validate_rules
from secscan.report.models import ACTIONS

FS = {f.id: f for f in from_json(Path("fixtures/report/work-note-findings.json").read_text(encoding="utf-8"))}


def test_shipped_rules_json_validates_and_covers_custom_and_work_note_rules():
    rules = load_rules()
    assert validate_rules(rules) == []
    assert {"secscan.rules.hardcoded-credential", "secscan.rules.mybatis-sqli-value", "secscan.rules.mybatis-sqli-identifier",
            "secscan.rules.zero-salt", "generic-api-key"} <= set(rules)
    assert all(r["action"] in ACTIONS for r in rules.values())


def test_validate_rules_reports_bad_action_and_missing_confirm():
    bad = {"r1": {"name": "n", "what": "w", "why": "y", "how": "h", "action": "delete-it", "ctx": False, "done": "d"},
           "r2": {"name": "n", "what": "w", "why": "y", "how": "h", "action": "code-fix", "ctx": True, "done": "d"},
           "r3": {"name": "n"}}
    errs = validate_rules(bad)
    assert any("r1" in e and "delete-it" in e for e in errs)
    assert any("r2" in e and "confirm" in e for e in errs)
    assert any("r3" in e and "누락" in e for e in errs)


def test_target_version_prefers_same_major_minimum():
    assert target_version("10.1.55", ("11.0.25", "10.1.58", "9.0.121")) == "10.1.58"
    assert target_version("2.24.3", ("2.25.5", "2.26.1")) == "2.25.5"
    assert target_version("1.0", ("2.0",)) == "2.0"
    assert target_version("1.0", ("2.0", "unknown")) == "2.0"
    assert target_version("1.0", ()) is None


def test_hand_written_rule_wins_over_composition():
    e = entry_for(FS["356e4bbab00c"])
    assert e.source == "rules.json" and e.action == "externalize-secret" and e.ctx is True and e.confirm


def test_sca_composed_entry_has_target_and_bom_hint():
    e = entry_for(FS["0442ba114c70"])
    assert e.source == "composed" and e.action == "upgrade" and e.ctx is False
    assert e.name == "tomcat-embed-core 알려진 취약점 CVE-2026-65182"
    assert "10.1.58" in e.how and "ext['tomcat.version']" in e.how
    assert e.done == "재스캔 findings.json 에 이 ID 부재 + tomcat-embed-core 설치 버전 ≥ 10.1.58"
    assert "2.25.5" in entry_for(FS["cae6cff5ca45"]).how and "ext['log4j2.version']" in entry_for(FS["cae6cff5ca45"]).how


def test_sca_without_fixed_version_says_so():
    f = Finding(category="sca", severity="high", title="T", tool="trivy", rule_id="CVE-0",
                component=Component("maven", "a:b", "1.0"), advisory=Advisory("CVE-0"))
    e = entry_for(f, rules={}, cwe={}, bom_props={})
    assert "수정 버전이 공개되지 않음" in e.how and e.action == "upgrade"


def test_unknown_sast_rule_composes_from_cwe_table_and_is_conservative():
    f = Finding(category="sast", severity="medium", title="Rule message here", tool="semgrep", rule_id="x.y.some-rule",
                cwe=("CWE-79",), references=("https://ref/1",), location=Location("a.js", 1))
    e = entry_for(f, rules={})
    assert e.source == "composed" and e.ctx is True and e.action == "code-fix"
    assert e.name == load_cwe()["CWE-79"]["name"] and e.what == "Rule message here"
    assert "https://ref/1" in e.how and e.confirm


def test_unknown_sast_rule_without_cwe_uses_fixed_sentence():
    f = Finding(category="sast", severity="low", title="", tool="semgrep", rule_id="x.y.no-cwe", location=Location("a.js", 1))
    e = entry_for(f, rules={})
    assert e.name == "no-cwe" and e.why == "도구가 CWE 를 주지 않아 위험 설명이 없음(지식베이스 등록 필요)" and e.what == "x.y.no-cwe"


def test_secret_entry_is_hand_written_for_known_rule_and_composed_otherwise():
    assert entry_for(FS["108d8ee4651c"]).source == "rules.json"
    f = Finding(category="secret", severity="high", title="t", tool="gitleaks", rule_id="unknown-secret-rule", location=Location("a", 1))
    e = entry_for(f, rules={})
    assert e.action == "externalize-secret" and e.ctx is True and e.source == "composed"


def test_cwe_and_bom_tables_shape():
    cwe = load_cwe()
    assert {"CWE-79", "CWE-89", "CWE-798", "CWE-345", "CWE-829", "CWE-116", "CWE-863"} <= set(cwe)
    assert all({"name", "why", "fix"} <= set(v) for v in cwe.values())
    props = load_bom_props()
    assert props["org.apache.tomcat.embed:"] == "ext['tomcat.version']" and props["org.apache.logging.log4j:"] == "ext['log4j2.version']"
