"""도달성 적용 엔진 — 4중 안전장치를 순서대로 적용(spec §10.1).

provider 는 실제 dep-scan 실행체로, 주입 가능해 결정적 테스트가 된다.
provider(target, timeout) -> ReachabilityResult, 타임아웃 시 TimeoutError.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from ..models import Finding, Reachability


@dataclass
class Budget:
    max_loc: int = 50_000  # 크기 인지 임계 (M1 에서 실측 튜닝)
    timeout: float = 600.0
    allow_large: bool = False  # 임계 초과 시 진행 허용(확인 대체)


@dataclass
class ReachabilityResult:
    verdicts: dict  # "package@version" -> "reachable" | "unreachable"
    evidence: dict = field(default_factory=dict)
    status: str = "ok"  # ok | skipped | timeout | error


@dataclass
class EnrichOutcome:
    findings: list[Finding]
    ran: bool  # provider 결과를 실제 적용했나
    reason: str  # ok | cache | env | size | timeout | error | <provider status>


def _component_key(f: Finding) -> str | None:
    if f.component:
        return f"{f.component.package}@{f.component.version}"
    return None


def enrich_reachability(
    findings: list[Finding],
    target,
    *,
    provider,
    env_ok=lambda: True,
    count_loc=lambda t: 0,
    budget: Budget | None = None,
    cache: dict | None = None,
    code_hash=None,
) -> EnrichOutcome:
    budget = budget or Budget()

    # 안전장치 4: doctor 사전 점검 (런타임/메모리)
    if not env_ok():
        return EnrichOutcome(findings, False, "env")

    # 안전장치 1: 크기 인지 자동
    if count_loc(target) > budget.max_loc and not budget.allow_large:
        return EnrichOutcome(findings, False, "size")

    # 안전장치 2: 캐싱 (코드 해시)
    key = code_hash(target) if (cache is not None and code_hash) else None
    reason = "ok"
    if key is not None and key in cache:
        result = cache[key]
        reason = "cache"
    else:
        # 안전장치 3: 예산 + 폴백 (타임아웃/에러 → 도달성만 스킵, 탐지 유지)
        # provider 는 어떤 컴포넌트를 판정할지 알아야 하므로 findings 를 받는다.
        try:
            result = provider(target, budget.timeout, findings)
        except TimeoutError:
            return EnrichOutcome(findings, False, "timeout")
        except Exception:
            return EnrichOutcome(findings, False, "error")
        if result is None or result.status != "ok":
            return EnrichOutcome(findings, False, result.status if result else "error")
        if key is not None:
            cache[key] = result

    # 판정 적용 (없는 컴포넌트는 unknown 유지)
    enriched = []
    for f in findings:
        k = _component_key(f)
        verdict = result.verdicts.get(k) if k else None
        if verdict:
            enriched.append(
                replace(
                    f,
                    reachability=Reachability(
                        status=verdict,
                        evidence=result.evidence.get(k),
                        source="dep-scan",
                    ),
                )
            )
        else:
            enriched.append(f)
    return EnrichOutcome(enriched, True, reason)
