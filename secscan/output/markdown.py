"""typed Finding → 사람이 읽는 Markdown 보고서.

정확도 우선: 도달 가능한 finding 을 맨 위로 올리고, 도달 불가는 낮은 우선순위로
분리해 노이즈를 가른다. 단, 정적 분석 사각지대를 반드시 명시한다(spec §5.7/§13).
결정적(시간 등 비결정 요소는 meta 로 주입).
"""

from __future__ import annotations

from ..models import REACHABLE, UNKNOWN, UNREACHABLE, Finding, severity_rank

_REACH_RANK = {REACHABLE: 2, UNKNOWN: 1, UNREACHABLE: 0}
_REACH_LABEL = {REACHABLE: "도달 가능", UNREACHABLE: "도달 불가", UNKNOWN: "도달성 미상"}

_BLIND_SPOT_NOTE = (
    "> ⚠️ **정적 분석 사각지대**: 도달성 판정은 리플렉션·DI(Spring proxy)·역직렬화·"
    "동적 디스패치·애노테이션 라우팅을 놓칠 수 있습니다. '도달 불가'는 *우선순위 강등* "
    "근거일 뿐 안전 보증이 아닙니다. 억제는 사람이 증거를 확인해 확정하세요(자동 억제 없음)."
)


def _sort_key(f: Finding):
    return (_REACH_RANK.get(f.reachability.status, 1), severity_rank(f.severity))


def _line(f: Finding) -> list[str]:
    comp = f"{f.component.package}@{f.component.version}" if f.component else f.rule_id
    reach = _REACH_LABEL.get(f.reachability.status, f.reachability.status)
    out = [f"### [{f.severity.upper()}] {f.rule_id} — {comp}"]
    detail = f"- 도달성: **{reach}**"
    if f.reachability.source:
        detail += f" ({f.reachability.source})"
    if f.reachability.evidence:
        detail += f" — `{f.reachability.evidence}`"
    out.append(detail)
    if f.advisory and f.advisory.fixed_versions:
        out.append(f"- 수정: `{', '.join(f.advisory.fixed_versions)}` 이상으로 업그레이드")
    meta = []
    if f.cwe:
        meta.append(" ".join(f.cwe))
    if f.consensus:
        meta.append(f"탐지: {'+'.join(f.consensus.tools)} (합의 {f.consensus.score})")
    if meta:
        out.append(f"- {' · '.join(meta)}")
    out.append("")
    return out


def to_markdown(findings: list[Finding], *, target: str | None = None, meta: dict | None = None) -> str:
    findings = sorted(findings, key=_sort_key, reverse=True)

    n = len(findings)
    by_sev: dict[str, int] = {}
    by_reach: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_reach[f.reachability.status] = by_reach.get(f.reachability.status, 0) + 1

    L: list[str] = ["# 보안 점검 보고서 — secscan", ""]
    if target:
        L.append(f"- 대상: `{target}`")
    if meta and meta.get("scanners"):
        L.append(f"- 스캐너: {', '.join(meta['scanners'])}")
    L.append("")

    # 요약
    L.append("## 요약")
    sev_order = ["critical", "high", "medium", "low", "unknown"]
    sev_str = ", ".join(f"{s} {by_sev[s]}" for s in sev_order if by_sev.get(s))
    L.append(f"- 총 **{n}건** — {sev_str or '없음'}")
    L.append(
        f"- 도달성: 도달 가능 **{by_reach.get(REACHABLE, 0)}** · "
        f"도달 불가 **{by_reach.get(UNREACHABLE, 0)}** · "
        f"미상 **{by_reach.get(UNKNOWN, 0)}**"
    )
    if by_reach.get(UNREACHABLE):
        L.append(
            f"- ℹ️ 도달 불가 {by_reach[UNREACHABLE]}건은 우선순위가 낮습니다(노이즈 후보)."
        )
    L.append("")
    L.append(_BLIND_SPOT_NOTE)
    L.append("")

    # 우선 조치 (도달 가능)
    priority = [f for f in findings if f.reachability.status == REACHABLE]
    rest = [f for f in findings if f.reachability.status != REACHABLE]

    L.append("## 우선 조치 — 도달 가능")
    if priority:
        for f in priority:
            L.extend(_line(f))
    else:
        L.append("_도달 가능으로 판정된 취약점 없음._")
        L.append("")

    L.append("## 낮은 우선순위 — 도달 불가 / 미상")
    if rest:
        for f in rest:
            L.extend(_line(f))
    else:
        L.append("_해당 없음._")
        L.append("")

    return "\n".join(L)
