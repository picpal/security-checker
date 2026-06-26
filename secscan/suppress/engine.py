"""억제 적용/기록/제안 (spec §12).

- record_suppression: 필수 필드(provenance/evidence/expiry/scope) 검증. 사람이 확정.
- apply_suppressions: scope(dedup_key) 정확 매칭 + 무효화(만료/버전변경/도달성변화).
- propose_suppressions: 후보만 반환(적용·기록 안 함). Claude 제안 경로.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from ..models import REACHABLE, Finding, Suppression


def record_suppression(*, scope, reason, provenance, evidence, expiry, basis="",
                       state="suppressed") -> Suppression:
    """사람이 확정하는 억제 1건. 필수 근거가 비면 거부한다."""
    missing = [n for n, v in
               (("scope", scope), ("provenance", provenance), ("evidence", evidence), ("expiry", expiry))
               if not v]
    if missing:
        raise ValueError(f"억제에는 필수 필드가 있어야 합니다: {', '.join(missing)}")
    return Suppression(
        state=state, reason=reason, provenance=provenance,
        evidence=evidence, expiry=expiry, scope=scope, basis=basis,
    )


@dataclass
class SuppressOutcome:
    findings: list[Finding]
    applied: int
    invalidated: list[str]  # 재검토 큐 (만료/도달성변화로 무효화된 scope)


def _expired(s: Suppression, today: str | None) -> bool:
    return bool(s.expiry and today and s.expiry < today)


def apply_suppressions(findings, suppressions, *, today: str | None = None) -> SuppressOutcome:
    by_scope = {s.scope: s for s in suppressions}
    out: list[Finding] = []
    applied = 0
    invalidated: list[str] = []

    for f in findings:
        s = by_scope.get(f.dedup_key)  # 버전 바뀌면 dedup_key 달라져 자동 미매칭(stale)
        if s is None:
            out.append(f)
            continue
        # 무효화 1: 만료
        if _expired(s, today):
            invalidated.append(f.dedup_key)
            out.append(f)
            continue
        # 무효화 2: 도달성 근거가 깨짐 (unreachable 로 억제했는데 이제 reachable)
        if s.basis == "unreachable" and f.reachability.status == REACHABLE:
            invalidated.append(f.dedup_key)
            out.append(f)
            continue
        out.append(replace(f, suppression=s))
        applied += 1

    return SuppressOutcome(out, applied, invalidated)


def propose_suppressions(findings) -> list[dict]:
    """억제 후보를 제안만 한다(적용/기록하지 않음). 도달 불가 SCA 가 1순위 후보.

    반환은 사람이 검토/확정할 초안. provenance/expiry 는 사람이 채운다.
    """
    candidates = []
    for f in findings:
        if f.category == "sca" and f.reachability.status == "unreachable":
            candidates.append({
                "scope": f.dedup_key,
                "reason": f"{f.advisory.id if f.advisory else f.rule_id}: 도달 불가",
                "evidence": f.reachability.evidence or "도달성 분석상 취약 API 미호출",
                "basis": "unreachable",
                "_note": "provenance·expiry 를 사람이 채워 확정하세요(자동 억제 아님)",
            })
    return candidates
