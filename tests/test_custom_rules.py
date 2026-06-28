"""D — 커스텀 룰 골든 테스트.

`secscan/rules/` 를 `fixtures/custom-rule-app/` 에 실제 semgrep 으로 돌린 출력(골든).
위치 분기(value=actionable / 식별자=review), 경로 강등(loadtest→review), FP 0 을
결정적으로 검증한다.
골든 재생성: `semgrep --config secscan/rules/ fixtures/custom-rule-app/ --json
--disable-version-check --quiet > tests/golden/semgrep-custom-rules.json`
"""

from pathlib import Path

from secscan.models import sast_tier
from secscan.normalize.semgrep import parse_semgrep

GOLDEN = Path(__file__).parent / "golden" / "semgrep-custom-rules.json"


def _findings():
    return parse_semgrep(GOLDEN.read_text())


# --- D2: MyBatis ${} 위치 분기 ---


def test_mybatis_value_position_is_actionable():
    fs = [f for f in _findings() if f.rule_id.endswith("mybatis-sqli-value")]
    assert len(fs) == 1
    f = fs[0]
    assert f.location.file.endswith("Sample.xml")
    assert f.location.start_line == 8        # WHERE name = '${name}'
    assert "CWE-89" in f.cwe
    assert f.confidence == "high"            # 룰 metadata HIGH → 정규화 소문자
    assert sast_tier(f) == "actionable"      # 값 위치 = 우선조치


def test_mybatis_identifier_position_is_review():
    fs = [f for f in _findings() if f.rule_id.endswith("mybatis-sqli-identifier")]
    assert len(fs) >= 1                       # FROM logs_${month}, ORDER BY ${sortCol}
    for f in fs:
        assert f.location.start_line == 13
        assert "CWE-89" in f.cwe
        assert f.confidence == "low"
        assert sast_tier(f) == "review"       # 식별자 위치 = 검토후보(불가피 가능)


def test_mybatis_safe_binding_zero_findings():
    # #{} 파라미터 바인딩(Sample.xml line 18)은 어떤 룰도 잡지 않는다 (FP 0 — 원칙1)
    xml = [f for f in _findings() if f.location.file.endswith("Sample.xml")]
    assert all(f.location.start_line != 18 for f in xml)
    assert all("mybatis-sqli" in f.rule_id for f in xml)


# --- D3: hardcoded-credential + zero-salt + 경로 강등 ---


def test_hardcoded_credential_main_is_actionable():
    fs = [f for f in _findings()
          if f.rule_id.endswith("hardcoded-credential")
          and f.location.file.endswith("Creds.java")]
    assert len(fs) == 2                        # PASSWORD, apiKey
    for f in fs:
        assert "CWE-798" in f.cwe
        assert f.confidence == "high"
        assert sast_tier(f) == "actionable"    # main 경로 = 우선조치


def test_hardcoded_credential_loadtest_is_review():
    fs = [f for f in _findings() if f.location.file.endswith("LoadtestSeeder.java")]
    assert len(fs) == 1
    f = fs[0]
    assert f.rule_id.endswith("hardcoded-credential")
    assert sast_tier(f) == "review"            # loadtest 파일명 → 강등(원칙1)


def test_zero_salt_is_actionable():
    fs = [f for f in _findings() if f.rule_id.endswith("zero-salt")]
    assert len(fs) == 2                        # 고정 getBytes salt + 고정 base64 salt
    for f in fs:
        assert "CWE-760" in f.cwe
        assert f.confidence == "high"
        assert sast_tier(f) == "actionable"


def test_credential_and_salt_negatives_not_flagged():
    # 음성: 환경변수 주입·빈 문자열·SecureRandom 은 미탐 (FP 0)
    fs = _findings()
    creds = {f.location.start_line for f in fs if f.location.file.endswith("Creds.java")}
    assert creds == {5, 6}                      # 9(env)·12(empty) 미포함
    hashing = {f.location.start_line for f in fs if f.location.file.endswith("Hashing.java")}
    assert hashing == {7, 8}                    # freshSalt(SecureRandom) 미포함
