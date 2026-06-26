"""M3 SAST — Semgrep 정규화(골든) + 어댑터.

골든: SAST 픽스처(Vuln.java)에 실제 semgrep(p/java+p/security-audit)을 돌린 출력.
SAST 는 위치형 finding. CE 의 intraprocedural taint 한계는 보고서에 명시한다(spec §10.2).
"""

from pathlib import Path

from secscan.adapters.semgrep import SemgrepAdapter
from secscan.normalize.semgrep import parse_semgrep

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
