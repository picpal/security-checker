"""M3 SAST — Semgrep 정규화(골든) + 어댑터.

골든: SAST 픽스처(Vuln.java)에 실제 semgrep(p/java+p/security-audit)을 돌린 출력.
SAST 는 위치형 finding. CE 의 intraprocedural taint 한계는 보고서에 명시한다(spec §10.2).
"""

from pathlib import Path

from secscan.adapters.semgrep import SemgrepAdapter
from secscan.models import Finding, Location, is_test_path, normalize_confidence, sast_tier
from secscan.normalize.merge import merge_consensus
from secscan.normalize.semgrep import _cwe_codes, parse_semgrep

GOLDEN = Path(__file__).parent / "golden" / "semgrep-sast-app.json"


def _golden():
    return GOLDEN.read_text()


def test_parse_semgrep_produces_sast_finding():
    findings = parse_semgrep(_golden())
    assert len(findings) >= 1
    f = findings[0]
    assert f.category == "sast"
    assert f.tool == "semgrep"
    assert f.location is not None
    assert f.location.file.endswith("Vuln.java")
    assert f.location.start_line == 15


def test_parse_semgrep_extracts_cwe_and_severity():
    f = parse_semgrep(_golden())[0]
    assert "CWE-89" in f.cwe  # "CWE-89: ..." 에서 코드만 추출
    assert f.severity == "high"  # semgrep ERROR -> high


def test_parse_semgrep_extracts_owasp():
    f = parse_semgrep(_golden())[0]
    assert any("Injection" in o for o in f.owasp)


def test_parse_semgrep_empty():
    assert parse_semgrep('{"results": []}') == []


def test_semgrep_adapter_build_argv_uses_json_and_configs():
    argv = SemgrepAdapter().build_argv("/proj", {})
    assert argv[0] == "semgrep"
    assert "--json" in argv
    assert "/proj" in argv
    assert any("p/java" in a for a in argv)  # Java 룰셋 포함


# --- B1: confidence 추출/정규화 + cwe shape 방어 + 팩 확대 ---

def test_parse_semgrep_extracts_normalized_confidence():
    # 골든 confidence 는 "MEDIUM"(대문자) → 정규화로 소문자 "medium"
    f = parse_semgrep(_golden())[0]
    assert f.confidence == "medium"


def test_normalize_confidence_lowercases_and_defaults():
    assert normalize_confidence("MEDIUM") == "medium"
    assert normalize_confidence("HIGH") == "high"
    assert normalize_confidence("LOW") == "low"
    assert normalize_confidence(None) == "unknown"
    assert normalize_confidence("") == "unknown"
    assert normalize_confidence("bogus") == "unknown"


def test_cwe_codes_handles_list_string_and_missing():
    # P2: metadata.cwe 가 list/string/missing 모두 안전 — 문자열을 char 단위로 쪼개지 않는다
    assert _cwe_codes(["CWE-89: SQL Injection"]) == ("CWE-89",)
    assert _cwe_codes("CWE-89: SQL Injection") == ("CWE-89",)
    assert _cwe_codes(None) == ()
    assert _cwe_codes([]) == ()
    assert _cwe_codes(["CWE-79: XSS", "CWE-79: dup"]) == ("CWE-79",)  # dedup


def test_semgrep_adapter_includes_expanded_packs():
    argv = SemgrepAdapter().build_argv("/proj", {})
    assert any("p/owasp-top-ten" in a for a in argv)
    assert any("p/cwe-top-25" in a for a in argv)


# --- B2: sast_tier (신뢰도 계층화) ---

def _sast(sev, conf):
    return Finding(category="sast", severity=sev, confidence=conf,
                   location=Location("A.java", 1))


def test_sast_tier_actionable_needs_conf_and_severity():
    assert sast_tier(_sast("critical", "high")) == "actionable"
    assert sast_tier(_sast("high", "medium")) == "actionable"
    assert sast_tier(_sast("medium", "medium")) == "actionable"


def test_sast_tier_low_or_unknown_confidence_is_review():
    assert sast_tier(_sast("critical", "low")) == "review"
    assert sast_tier(_sast("critical", "unknown")) == "review"  # missing→review (원칙1)


def test_sast_tier_low_or_unknown_severity_is_review():
    assert sast_tier(_sast("low", "high")) == "review"
    assert sast_tier(_sast("unknown", "high")) == "review"


def test_sast_tier_none_for_non_sast():
    assert sast_tier(Finding(category="sca", severity="high", confidence="high")) is None
    assert sast_tier(Finding(category="secret", severity="high")) is None


def test_merge_takes_conservative_confidence():
    # 같은 dedup_key 병합 시 더 낮은(불확실한) confidence 를 택한다 — 순서 비의존.
    a = Finding(category="sast", severity="high", rule_id="r", confidence="high",
                location=Location("A.java", 1))
    b = Finding(category="sast", severity="high", rule_id="r", confidence="low",
                location=Location("A.java", 1))
    assert merge_consensus([a, b])[0].confidence == "low"
    assert merge_consensus([b, a])[0].confidence == "low"  # 순서 바꿔도 동일


# --- D1: is_test_path + sast_tier test 경로 강등 ---


def test_is_test_path_patterns():
    assert is_test_path("src/test/java/Foo.java")
    assert is_test_path("module/src/androidTest/java/Bar.java")
    assert is_test_path("com/example/FooTest.java")
    assert is_test_path("com/example/FooTests.java")
    assert is_test_path("com/example/FooIT.java")
    assert is_test_path("src/main/java/loadtest/Seeder.java")
    assert is_test_path("src/main/java/com/x/LoadtestSeederConfig.java")  # 파일명 loadtest
    # main 소스/리소스/유사단어는 아님
    assert not is_test_path("src/main/java/com/example/Service.java")
    assert not is_test_path("src/main/resources/app.yml")
    assert not is_test_path("com/example/audit.java")  # 'IT' 대문자 경계 — 오분류 방지
    assert not is_test_path("")
    assert not is_test_path(None)


def test_sast_tier_demotes_test_path_to_review():
    main_f = Finding(category="sast", severity="high", confidence="high",
                     location=Location("src/main/java/Svc.java", 10))
    assert sast_tier(main_f) == "actionable"
    test_f = Finding(category="sast", severity="high", confidence="high",
                     location=Location("src/test/java/SvcTest.java", 10))
    assert sast_tier(test_f) == "review"  # 같은 신호여도 test 경로면 강등


def test_sast_tier_no_location_is_safe():
    # location 없는 SAST 도 강등 로직이 터지지 않는다
    f = Finding(category="sast", severity="high", confidence="high")
    assert sast_tier(f) == "actionable"
