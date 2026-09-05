"""축 6(b) 도달성 픽스처 정본 — fixtures/reach-app/expected.json × tests/golden/atom-usages-reach-app.json.

tests/test_reach_app.py 와 같은 판정 코드를 공유한다(단일 소스). 게이트는 gate.py 가 facts 로 내린다.
"""
from __future__ import annotations

import json
from pathlib import Path

from secscan.models import UNREACHABLE, Advisory, Component, Finding
from secscan.reachability.depscan import decide_reachability, parse_invoked_symbols

FIXTURE = Path("fixtures/reach-app/expected.json")
SLICE = Path("tests/golden/atom-usages-reach-app.json")

# expected.json 은 짧은 아티팩트명만 담는다(예: "commons-text") — decide_reachability 의 verdicts
# 키는 `Component.package`("group:artifact") 기준이라(tests/test_reach_app.py 의 기존 _f() 헬퍼와
# 동일 표기), fixtures/reach-app/pom.xml 의 groupId 로 좌표를 복원한다.
_GROUP = {
    "commons-text": "org.apache.commons",
    "jackson-databind": "com.fasterxml.jackson.core",
    "tomcat-embed-core": "org.apache.tomcat.embed",
}


def _coord(e: dict) -> str:
    return f"{_GROUP[e['package']]}:{e['package']}"


def build_findings(expected: dict) -> list[Finding]:
    fs = []
    for kind in ("reachable", "must_not_be_unreachable"):
        for e in expected[kind]:
            fs.append(Finding(category="sca", severity="high", rule_id=e["cve"],
                              component=Component("maven", _coord(e), e["version"]), advisory=Advisory(e["cve"])))
    return fs


def evaluate(fixture: Path | None = None, slice_path: Path | None = None) -> dict:
    """`fixture`/`slice_path` 생략 시 모듈 전역 FIXTURE/SLICE 를 **호출 시점**에 읽는다(리뷰 I1) —
    이 함수는 임포트 시점에 파일을 읽지 않으므로, 픽스처가 없거나 손상됐을 때
    reconcile.regenerate 의 예외 격리(M4/N6)가 reach-app 생성기 한 행으로만 잡힌다(생성기
    레지스트리 전체가 임포트 단계에서 죽지 않는다). 이 지연 조회 덕분에 테스트가
    `reach_app.FIXTURE` 를 monkeypatch 하면 인자 없는 호출도 그 값을 따라간다."""
    fixture = FIXTURE if fixture is None else fixture
    slice_path = SLICE if slice_path is None else slice_path
    expected = json.loads(fixture.read_text(encoding="utf-8"))
    fs = build_findings(expected)
    result = decide_reachability(fs, parse_invoked_symbols(slice_path.read_text(encoding="utf-8")))
    verdict = {k: v for k, v in result.verdicts.items()}  # "group:artifact@version" -> status
    rows = []
    for kind in ("reachable", "must_not_be_unreachable"):
        for e in expected[kind]:
            status = verdict.get(f"{_coord(e)}@{e['version']}", "unknown")
            rows.append({"case": kind, "package": e["package"], "cve": e["cve"], "status": status,
                         "ok": (status == "reachable") if kind == "reachable" else (status != UNREACHABLE)})
    return {"cases": len(rows), "rows": rows,
            "false_unreachable": sum(1 for r in rows if r["case"] == "must_not_be_unreachable" and r["status"] == UNREACHABLE),
            "reachable_hit": (sum(1 for r in rows if r["case"] == "reachable" and r["ok"]), sum(1 for r in rows if r["case"] == "reachable"))}


def collect_facts(r: dict) -> dict:
    return {"reachapp.cases": r["cases"], "reachapp.false_unreachable": r["false_unreachable"],
            "reachapp.reachable_expected_hit": f"{r['reachable_hit'][0]}/{r['reachable_hit'][1]}"}


def render(r: dict) -> str:
    L = ["# reach-app 도달성 픽스처 (축 6(b) — 생성 문서)", "", "| 케이스 | 패키지 | CVE | 현 엔진 판정 | 기대 충족 |", "|---|---|---|---|---|"]
    L += [f"| {x['case']} | {x['package']} | {x['cve']} | {x['status']} | {x['ok']} |" for x in r["rows"]]
    return "\n".join(L) + "\n"
