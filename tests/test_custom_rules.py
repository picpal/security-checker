"""D — 커스텀 룰 골든 테스트.

`secscan/rules/` 를 `fixtures/custom-rule-app/` 에 실제 semgrep 으로 돌린 출력(골든).
위치 분기(value=actionable / 식별자=review)와 #{} 바인딩 FP 0 을 결정적으로 검증한다.
골든 재생성: `semgrep --config secscan/rules/ fixtures/custom-rule-app/ --json
--disable-version-check --quiet > tests/golden/semgrep-custom-rules.json`
"""

from pathlib import Path

from secscan.models import sast_tier
from secscan.normalize.semgrep import parse_semgrep

GOLDEN = Path(__file__).parent / "golden" / "semgrep-custom-rules.json"


def _findings():
    return parse_semgrep(GOLDEN.read_text())


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
    # #{} 파라미터 바인딩(line 18)은 어떤 룰도 잡지 않는다 (FP 0 — 원칙1)
    fs = _findings()
    assert all(f.location.start_line != 18 for f in fs)
    assert all("mybatis-sqli" in f.rule_id for f in fs)
