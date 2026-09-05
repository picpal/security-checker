"""V3 도달성 쌍 픽스처(spec §5 축 6·§6) — false-unreachable 게이트.

판정 코드는 `tools/verify/reach_app.py`(정본, 게이트 facts 생성기가 쓰는 그 코드)와 공유한다 —
단일 소스. 골든 usage 슬라이스로 결정적 검증. (c) 프레임워크 활성화 케이스는 현 엔진(패키지 prefix
존재)이 unreachable 을 내는 것이 알려진 갭이라 xfail(strict) 로 고정한다: 엔진이 고쳐지면 이 xfail 이
XPASS 로 실패해 제거를 강제한다.
"""

import pytest

from secscan.models import REACHABLE, UNREACHABLE
from tools.verify.reach_app import EXPECTED, evaluate


def _row(package: str) -> dict:
    return next(r for r in evaluate()["rows"] if r["package"] == package)


def test_vulnerable_api_use_is_reachable():
    assert _row("commons-text")["status"] == REACHABLE


@pytest.mark.xfail(strict=True, reason="백로그 P1: Maven 좌표→Java 패키지 prefix 추정 실패(jackson-databind 실사용인데 unreachable) — false-unreachable")
def test_used_library_with_mismatched_prefix_must_not_be_unreachable():
    assert _row("jackson-databind")["status"] != UNREACHABLE


@pytest.mark.xfail(strict=True, reason="백로그 P1: 프레임워크 활성화 라이브러리(앱 미참조)를 unreachable 로 판정 — false-unreachable")
def test_framework_activated_library_must_not_be_unreachable():
    assert _row("tomcat-embed-core")["status"] != UNREACHABLE


def test_current_engine_false_unreachable_modes_documented():
    # 위 두 xfail 의 반대 진술 — 갭이 실재함을 명시적으로 고정(엔진이 고쳐지면 셋 다 갱신).
    assert _row("jackson-databind")["status"] == UNREACHABLE
    assert _row("tomcat-embed-core")["status"] == UNREACHABLE
    assert EXPECTED["must_not_be_unreachable"][0]["package"] == "jackson-databind"
    assert EXPECTED["must_not_be_unreachable"][1]["package"] == "tomcat-embed-core"
