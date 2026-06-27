"""스택/빌드도구 감지 + 프로파일 추천.

하이브리드 경계: Claude 가 자연어 요청을 intent 로 해석하고, 이 모듈이 결정적으로
스택을 감지해 프로파일을 고른다(spec §4 데이터 흐름 1단계).
"""

from __future__ import annotations

from pathlib import Path

# 스택 감지에서 제외할 디렉토리(빌드 산출물·벤더·VCS·테스트 픽스처). 프로젝트의
# "주 스택"을 보려는 것이므로 fixtures/testdata 등은 감지를 오염시키지 않게 뺀다.
_EXCLUDE = {
    ".git", ".venv", "venv", "node_modules", "target", "build", ".gradle",
    "__pycache__", "dist", ".eggs", "site-packages",
    "fixtures", "testdata", "test-fixtures", "testdata", "examples",
}


def _walk(root: Path, pattern: str, exclude: set[str]):
    for p in root.rglob(pattern):
        rel = p.relative_to(root)
        if any(part in exclude for part in rel.parts):
            continue
        yield p


def detect_stack(target, *, exclude: set[str] = _EXCLUDE) -> dict:
    t = Path(target)

    # build_tool: 루트 우선(가장 신뢰), 없으면 제외 디렉토리 밖 하위 모듈
    build_tool = None
    if (t / "pom.xml").exists():
        build_tool = "maven"
    elif (t / "build.gradle").exists() or (t / "build.gradle.kts").exists():
        build_tool = "gradle"
    elif any(_walk(t, "pom.xml", exclude)):
        build_tool = "maven"
    elif any(_walk(t, "build.gradle*", exclude)):
        build_tool = "gradle"

    languages = []
    if any(_walk(t, "*.java", exclude)):
        languages.append("java")
    if any(_walk(t, "*.kt", exclude)):
        languages.append("kotlin")

    modules = len(list(_walk(t, "pom.xml", exclude))) or len(list(_walk(t, "build.gradle*", exclude)))

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
