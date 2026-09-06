"""파생 규칙(spec §5.2). 입력은 Finding + KbEntry 뿐. disposition/tier 는 읽기만 한다(재계산 금지)."""
from __future__ import annotations

from ..models import ACTIONABLE, DEMOTED, REVIEW, SUPPRESSED, Finding, severity_rank
from ..output._status import status_rows
from .models import OWNER_AUTO, OWNER_AUTO_LOW, OWNER_HUMAN, OWNER_NONE, OWNER_SUPPRESSED, Derived, KbEntry

DISP_KO = {ACTIONABLE: "조치대상", REVIEW: "검토후보", DEMOTED: "강등(낮은 우선순위)", SUPPRESSED: "억제됨", None: "미판정"}
SEV_KO = {"critical": "심각", "high": "위험", "medium": "보통", "low": "낮음", "unknown": "미상"}
_PRIO = {REVIEW: "P3", DEMOTED: "P4", SUPPRESSED: "P5", None: "P3"}


def priority(f: Finding) -> str:
    if f.disposition == ACTIONABLE:
        return "P1" if f.severity in ("critical", "high") else "P2"
    return _PRIO[f.disposition]


def owner(f: Finding, kb: KbEntry) -> str:
    d = f.disposition
    if d == ACTIONABLE:
        return OWNER_HUMAN if kb.ctx else OWNER_AUTO
    if d == REVIEW or d is None:
        return OWNER_HUMAN
    if d == DEMOTED:
        return OWNER_AUTO_LOW if kb.action == "upgrade" else OWNER_NONE
    return OWNER_SUPPRESSED


def basis(f: Finding) -> str:
    verdict = DISP_KO[f.disposition]
    if f.category == "sast":
        core = f"SAST · 룰 신뢰도 {f.confidence} → tier {f.tier or '-'} → {verdict}"
    elif f.category == "sca":
        r = f.reachability
        core = f"SCA · 도달성 {r.status}({r.source or '-'}, evidence {'있음' if r.evidence else '없음'}) → {verdict}"
    else:
        core = f"Secret · 억제 {'있음' if f.suppression else '없음'} → {verdict}"
    if f.suppression:
        core = f"억제({f.suppression.basis or f.suppression.state}, 만료 {f.suppression.expiry or '없음'}) → " + core
    return core


def where(f: Finding) -> str:
    if f.location and f.location.file:
        return f"{f.location.file}:{f.location.start_line}" if f.location.start_line else f.location.file
    if f.component:
        return f"{f.component.package}@{f.component.version}"
    return f.rule_id


def _where_key(f: Finding):
    if f.location and f.location.file:
        return (0, f.location.file, f.location.start_line or 0, "")
    if f.component:
        return (1, f.component.package, 0, f.component.version)
    return (2, f.rule_id, 0, "")


def done_text(f: Finding, kb: KbEntry) -> str:
    pkg = f.component.package if f.component else ""
    return kb.done.replace("{id}", f.id).replace("{package}", pkg)


def _group_key(f: Finding, kb: KbEntry):
    if f.category == "sca" and f.component:
        return ("sca", f.component.package, kb.done)  # done 에 target 버전이 들어 있어 같은 target 끼리만 묶인다
    if f.location and f.location.file:
        return ("loc", f.location.file, f.rule_id)
    return None


def _sort_key(f: Finding, prio: str):
    return (prio, -severity_rank(f.severity), _where_key(f), f.id)


def derive_all(findings: list[Finding], kbs: dict[str, KbEntry], deppaths: dict[str, str] | None = None) -> dict[str, Derived]:
    deppaths = deppaths or {}
    prio = {f.id: priority(f) for f in findings}
    ordered = sorted(findings, key=lambda f: _sort_key(f, prio[f.id]))
    members: dict = {}
    for f in ordered:
        k = _group_key(f, kbs[f.id])
        if k is not None:
            members.setdefault(k, []).append(f.id)
    numbered: dict = {}
    out: dict[str, Derived] = {}
    for f in ordered:
        kb = kbs[f.id]
        k = _group_key(f, kb)
        group, done = "", done_text(f, kb)
        if k is not None and len(members[k]) > 1:
            if k not in numbered:
                numbered[k] = f"G-{len(numbered) + 1}"
            group = numbered[k]
            done += " (대표)" if members[k][0] == f.id else f" — {group} 대표와 함께 해소"
        out[f.id] = Derived(prio[f.id], owner(f, kb), basis(f), group, done, where(f), deppaths.get(f.id, ""))
    return out


def sort_for_report(findings: list[Finding], derived: dict[str, Derived]) -> list[Finding]:
    return sorted(findings, key=lambda f: _sort_key(f, derived[f.id].priority))


def needs_question(f: Finding, d: Derived) -> bool:
    if d.owner == OWNER_HUMAN:
        return True
    return f.category == "sca" and f.disposition == DEMOTED and not f.reachability.evidence


def counts(findings: list[Finding], derived: dict[str, Derived]) -> dict:
    return {
        "total": len(findings),
        "actionable": sum(f.disposition == ACTIONABLE for f in findings),
        "auto": sum(derived[f.id].owner == OWNER_AUTO for f in findings),
        "human": sum(derived[f.id].owner == OWNER_HUMAN and f.disposition == ACTIONABLE for f in findings),
        "review": sum(f.disposition == REVIEW for f in findings),
        "demoted": sum(f.disposition == DEMOTED for f in findings),
        "auto_low": sum(derived[f.id].owner == OWNER_AUTO_LOW for f in findings),
        "suppressed": sum(f.disposition == SUPPRESSED for f in findings),
    }


def conclusion(c: dict, meta: dict) -> str:
    st = status_rows(meta)
    ok = sum(s["status"] == "ok" for s in st)
    return (f"총 {c['total']}건. 즉시 조치 대상 {c['actionable']}건(자동 수정 {c['auto']}, 사람 확인 후 {c['human']}). "
            f"검토 후보 {c['review']}건. 도달 불가 강등 {c['demoted']}건(업그레이드 가능 {c['auto_low']}). 억제됨 {c['suppressed']}건. "
            f"스캐너 {ok}종 정상 / {len(st) - ok}종 실패. 제외 {meta.get('excluded_count', 0)}건.")
