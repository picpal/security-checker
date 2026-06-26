"""스택 감지 + 프로파일 추천 — Claude 레이어의 결정적 부분.

Claude 가 자연어를 intent 로 해석하면, suggest_profile 이 stack+intent 를 프로파일로
결정한다. detect_stack 은 빌드도구/언어를 파일로 감지한다.
"""

from pathlib import Path

from secscan.detect import detect_stack, suggest_profile

FIX = Path(__file__).parent.parent / "fixtures"


def test_detect_maven_java_project():
    s = detect_stack(FIX / "vuln-maven-app")
    assert s["build_tool"] == "maven"
    assert "java" in s["languages"]


def test_detect_handles_no_build_tool():
    s = detect_stack(FIX / "secret-app")  # pom 없음 (config 만)
    assert s["build_tool"] is None


def test_suggest_profile_defaults_to_standard_for_jvm():
    s = {"build_tool": "maven", "languages": ["java"]}
    assert suggest_profile(s, intent="full") == "standard"


def test_suggest_profile_patch_check_uses_accurate_sca():
    s = {"build_tool": "maven", "languages": ["java"]}
    assert suggest_profile(s, intent="patch") == "accurate-sca"


def test_suggest_profile_quick_and_deep():
    s = {"build_tool": "maven", "languages": ["java"]}
    assert suggest_profile(s, intent="quick") == "quick"
    assert suggest_profile(s, intent="deep") == "deep"
