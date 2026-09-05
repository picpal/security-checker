"""게이트 문서 생성기(spec §5 상수 → facts 비교, 정오표 (g)). 판정 열은 이 코드의 출력이다 — 사람·AI 가 쓰지 않는다."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


def _ratio(v) -> tuple[int, int]:
    a, b = str(v).split("/")
    return int(a), int(b)


def _axis7_ok(f: dict) -> bool:
    """M6(리뷰 최종) — `a == b` 만으로는 `0/0`(범주 내 항목이 아예 없음)도 통과로 보인다.
    분모가 0 이면 측정 불능이지 100% 달성이 아니므로 통과시키지 않는다(vacuous pass 금지)."""
    a, b = _ratio(f["gta.in_category_pass"])
    return b > 0 and a == b


@dataclass(frozen=True)
class Gate:
    axis: str
    criterion: str
    facts: tuple[str, ...]  # 측정값 열에 인용할 id(전부 있어야 판정)
    verdict: Callable[[dict], bool] | None  # None = 기록만


GATES: tuple[Gate, ...] = (
    Gate("1 프로파일 계약", "드리프트 전건 문서화 + spec 갱신 백로그 — 기계 판정 없음(문서화는 생성 문서 profile-contract.md 존재로 충족)",
         ("profile.rows", "profile.drift"), None),
    Gate("2 SCA recall(GT-B 대비)", "CVE 단위 합산 ≥ 44/46 · HIGH/Important 미탐 ≤ 1 · 미탐 전건 단계 특정(origin 별 병기)",
         ("sca.recall_cve", "sca.recall_cve.team", "sca.recall_cve.dev-found", "sca.missed", "sca.missed_high_important",
          "sca.missed_by_stage.scanner", "sca.missed_by_stage.normalize"),
         lambda f: _ratio(f["sca.recall_cve"])[0] * 46 >= 44 * _ratio(f["sca.recall_cve"])[1] and int(f["sca.missed_high_important"]) <= 1),
    Gate("3 SCA known-FP(mssql-jdbc CVE-2025-59250)", "3단계 모두 True",
         ("knownfp.component_present", "knownfp.version_preserved", "knownfp.not_reported", "knownfp.found_version"),
         lambda f: all(f[k] == "True" for k in ("knownfp.component_present", "knownfp.version_preserved", "knownfp.not_reported"))),
    Gate("4 SCA 초과분 분류", "미분류 0", ("sca.extras", "sca.extras.unclassified"), lambda f: int(f["sca.extras.unclassified"]) == 0),
    Gate("5 입력면 교차", "해석 버전 불일치 0 (인벤토리 차 원인은 input-surface.md 표 참조)",
         ("surface.bom_only", "surface.jar_only", "surface.version_differs", "surface.gt_match_bom", "surface.gt_match_jar"),
         lambda f: int(f["surface.version_differs"]) == 0),
    Gate("6 도달성", "false-unreachable = 0 (프레임워크 활성화 케이스 포함)",
         ("reachapp.cases", "reachapp.false_unreachable", "reach.reachable", "reach.unreachable", "reach.unknown"),
         lambda f: int(f["reachapp.false_unreachable"]) == 0),
    Gate("7 GT-A differential(범주 내)", "범주 내 출현·소멸 100%", ("gta.in_category_pass",), _axis7_ok),
    Gate("8 보고서 충실성", "왕복 동일 · id 집합 동일 · 판정 불일치 0 · 결정성",
         ("fidelity.roundtrip_identical", "fidelity.id_set_mismatch", "fidelity.disposition_mismatch", "fidelity.deterministic",
          "fidelity.meta_scanner_status_rows", "fidelity.undecided"),
         lambda f: f["fidelity.roundtrip_identical"] == "True" and int(f["fidelity.id_set_mismatch"]) == 0
                   and int(f["fidelity.disposition_mismatch"]) == 0 and f["fidelity.deterministic"] == "True"),
    Gate("9 측정 사실성", "reconcile 검사 전항 0 — 값은 reconcile-report.md 참조(이 문서를 재생성하는 검증기 자신의 결과라 여기 인용하지 않음)", (), None),
)


def _cell(facts: dict, ids: tuple[str, ...]) -> str:
    return " · ".join(f"{i.split('.', 1)[1]} {facts[i]} <!-- fact:{i} -->" for i in ids)


def render_gate(facts: dict) -> str:
    L = ["# 게이트 (생성 문서 — spec §5 상수 vs facts*.json, tools/verify/gate.py)", "",
         "판정 열은 생성기 출력이다(정오표 (g)). 게이트 미통과는 캠페인 실패가 아니라 백로그 P1 등록 사유(spec §5).", "",
         "| 축 | 기준(spec §5) | 측정값 | 판정 |", "|---|---|---|---|"]
    passed, failed, recorded, unmeasured = [], [], [], []
    for g in GATES:
        missing = [i for i in g.facts if i not in facts]
        if missing:
            L.append(f"| {g.axis} | {g.criterion} | 정본 없음 | 미측정(정본 없음: {', '.join(missing)}) |")
            unmeasured.append(g.axis); continue
        value = _cell(facts, g.facts) if g.facts else "reconcile-report.md 참조"
        if g.verdict is None:
            v = "기록"; recorded.append(g.axis)
        elif g.verdict(facts):
            v = "✓"; passed.append(g.axis)
        else:
            v = "✗ → 백로그 P1"; failed.append(g.axis)
        L.append(f"| {g.axis} | {g.criterion} | {value} | {v} |")
    L += ["", "## 요약",
          f"- 통과: {', '.join(passed) or '없음'}", f"- 미통과(백로그 P1): {', '.join(failed) or '없음'}",
          f"- 기록만: {', '.join(recorded) or '없음'}", f"- 미측정: {', '.join(unmeasured) or '없음'}", ""]
    return "\n".join(L)
