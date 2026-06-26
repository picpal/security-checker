"""스택/빌드도구 감지 + 프로파일 추천.

하이브리드 경계: Claude 가 자연어 요청을 intent 로 해석하고, 이 모듈이 결정적으로
스택을 감지해 프로파일을 고른다(spec §4 데이터 흐름 1단계).
"""

from __future__ import annotations

from pathlib import Path


def detect_stack(target) -> dict:
    t = Path(target)
    build_tool = None
    if (t / "pom.xml").exists():
        build_tool = "maven"
    elif (t / "build.gradle").exists() or (t / "build.gradle.kts").exists():
        build_tool = "gradle"

    languages = []
    if any(t.rglob("*.java")):
        languages.append("java")
    if any(t.rglob("*.kt")):
        languages.append("kotlin")

    modules = len(list(t.rglob("pom.xml"))) or len(list(t.rglob("build.gradle*")))

    return {
        "build_tool": build_tool,
        "languages": languages,
        "modules": modules,
        "is_jvm": bool(build_tool) or bool(languages),
    }


# intent(자연어 해석 결과) → 프로파일
_INTENT_PROFILE = {
    "quick": "quick",       # 초고속 확인
    "patch": "accurate-sca",  # 신규 라이브러리 패치 체크 (SCA+도달성)
    "sca": "accurate-sca",
    "full": "standard",     # 기본 풀스캔
    "standard": "standard",
    "deep": "deep",         # 정밀(바이트코드)
}


def suggest_profile(stack: dict, intent: str = "full") -> str:
    return _INTENT_PROFILE.get(intent, "standard")
