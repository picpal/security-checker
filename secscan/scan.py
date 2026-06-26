"""스캔 파이프라인 — 어댑터 병렬 실행 → 정규화/병합 → 도달성 주입 → 결과 집계.

결정적 코드. 도달성 provider 와 환경 점검은 주입 가능(테스트/오프라인 폴백).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .adapters.base import OK, RawResult
from .models import Finding
from .normalize import to_findings
from .orchestrator import scan as orchestrate
from .reachability.engine import Budget, enrich_reachability


@dataclass
class ScanResult:
    findings: list[Finding]
    raw_results: list[RawResult]
    reachability_ran: bool = False
    reachability_reason: str = "off"
    partial_failures: list[RawResult] = field(default_factory=list)


def run_scan(
    target,
    profile,
    *,
    adapters,
    reachability_provider=None,
    env_ok=lambda: True,
    count_loc=lambda t: 0,
    budget: Budget | None = None,
    cache: dict | None = None,
    code_hash=None,
    max_workers: int | None = None,
) -> ScanResult:
    raws = orchestrate(adapters, target, max_workers=max_workers)
    findings = to_findings(raws)

    ran, reason = False, "off"
    if profile.reachability and reachability_provider is not None:
        outcome = enrich_reachability(
            findings, target,
            provider=reachability_provider,
            env_ok=env_ok, count_loc=count_loc,
            budget=budget, cache=cache, code_hash=code_hash,
        )
        findings, ran, reason = outcome.findings, outcome.ran, outcome.reason

    partial = [r for r in raws if r.status != OK]
    return ScanResult(findings, raws, ran, reason, partial)
