"""M3 SAST — Semgrep 정규화(골든) + 어댑터.

골든: SAST 픽스처(Vuln.java)에 실제 semgrep(p/java+p/security-audit)을 돌린 출력.
SAST 는 위치형 finding. CE 의 intraprocedural taint 한계는 보고서에 명시한다(spec §10.2).
"""

from pathlib import Path

from secscan.adapters.semgrep import SemgrepAdapter
from secscan.models import normalize_confidence
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
