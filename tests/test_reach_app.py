"""V3 도달성 쌍 픽스처(spec §5 축 6·§6) — false-unreachable 게이트.

골든 usage 슬라이스로 결정적 검증. (c) 프레임워크 활성화 케이스는 현 엔진(패키지 prefix 존재)이
unreachable 을 내는 것이 알려진 갭이라 xfail(strict) 로 고정한다: 엔진이 고쳐지면 이 xfail 이
XPASS 로 실패해 제거를 강제한다.
"""

import json
from pathlib import Path

import pytest

from secscan.models import REACHABLE, UNREACHABLE, Advisory, Component, Finding, Reachability
from secscan.reachability.depscan import decide_reachability, parse_invoked_symbols

ROOT = Path(__file__).parent.parent
SLICE = (ROOT / "tests" / "golden" / "atom-usages-reach-app.json").read_text()
EXPECTED = json.loads((ROOT / "fixtures" / "reach-app" / "expected.json").read_text())


def _f(pkg, ver, cve):
    return Finding(category="sca", severity="high", tool="trivy", rule_id=cve,
                   component=Component("maven", pkg, ver), advisory=Advisory(cve, aliases=(cve,)))


FINDINGS = [
    _f("org.apache.commons:commons-text", "1.9", "CVE-2022-42889"),
    _f("com.fasterxml.jackson.core:jackson-databind", "2.13.0", "CVE-2022-42003"),
    _f("org.apache.tomcat.embed:tomcat-embed-core", "9.0.46", "CVE-2021-41079"),
]


def _verdicts():
    return decide_reachability(FINDINGS, parse_invoked_symbols(SLICE)).verdicts


def test_vulnerable_api_use_is_reachable():
    assert _verdicts()["org.apache.commons:commons-text@1.9"] == REACHABLE


@pytest.mark.xfail(strict=True, reason="백로그 P1: Maven 좌표→Java 패키지 prefix 추정 실패(jackson-databind 실사용인데 unreachable) — false-unreachable")
def test_used_library_with_mismatched_prefix_must_not_be_unreachable():
    assert _verdicts()["com.fasterxml.jackson.core:jackson-databind@2.13.0"] != UNREACHABLE


@pytest.mark.xfail(strict=True, reason="백로그 P1: 프레임워크 활성화 라이브러리(앱 미참조)를 unreachable 로 판정 — false-unreachable")
def test_framework_activated_library_must_not_be_unreachable():
    assert _verdicts()["org.apache.tomcat.embed:tomcat-embed-core@9.0.46"] != UNREACHABLE


def test_current_engine_false_unreachable_modes_documented():
    # 위 두 xfail 의 반대 진술 — 갭이 실재함을 명시적으로 고정(엔진이 고쳐지면 셋 다 갱신).
    v = _verdicts()
    assert v["com.fasterxml.jackson.core:jackson-databind@2.13.0"] == UNREACHABLE
    assert v["org.apache.tomcat.embed:tomcat-embed-core@9.0.46"] == UNREACHABLE
    assert EXPECTED["must_not_be_unreachable"][0]["package"] == "jackson-databind"
    assert EXPECTED["must_not_be_unreachable"][1]["package"] == "tomcat-embed-core"
