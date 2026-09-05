"""판정 단계 H (spec §7.4) — 억제 다음, 출력 앞의 결정적 단계.

"조치 대상인가"를 한 곳에서 계산해 Finding 에 저장한다. exit code·markdown·SARIF·xlsx 는
`disposition`/`tier` 필드만 읽는다(재계산 금지). compliance 매핑도 여기서 채운다(위치 통일).
규칙(순서 중요): 억제 → SAST tier → SCA 도달성 → 그 외(secret) actionable.
"""

from __future__ import annotations

from dataclasses import replace

from .compliance import enrich_compliance
from .models import ACTIONABLE, DEMOTED, REVIEW, SUPPRESSED, UNREACHABLE, Finding, sast_tier


def _disposition(f: Finding, tier: str | None) -> str:
    if f.suppression is not None:
        return SUPPRESSED
    if f.category == "sast":
        return ACTIONABLE if tier == "actionable" else REVIEW
    if f.category == "sca":
        return ACTIONABLE if f.reachability.status != UNREACHABLE else DEMOTED
    return ACTIONABLE  # secret 등: 도달성 개념 없음, 항상 조치


def decide_one(f: Finding) -> Finding:
    tier = sast_tier(f)
    return replace(f, tier=tier, disposition=_disposition(f, tier))


def decide(findings: list[Finding]) -> list[Finding]:
    return [decide_one(f) for f in enrich_compliance(findings)]
