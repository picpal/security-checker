"""스캔 파이프라인 — 어댑터 병렬 실행 → 정규화/병합 → 도달성 주입 → 결과 집계.

결정적 코드. 도달성 provider 와 환경 점검은 주입 가능(테스트/오프라인 폴백).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .adapters.base import OK, RawResult
from .exclude import DEFAULT_EXCLUDES, exclude_findings, filter_gitignored
from .models import Finding
from .normalize import to_findings
from .orchestrator import scan as orchestrate
from .reachability.engine import Budget, enrich_reachability
from .secret.verify import verify_secrets_in_findings
from .suppress.engine import apply_suppressions
from .suppress.store import apply_baseline


@dataclass
class ScanResult:
    findings: list[Finding]
    raw_results: list[RawResult]
    reachability_ran: bool = False
    reachability_reason: str = "off"
    partial_failures: list[RawResult] = field(default_factory=list)
    secret_policy: str = "off"
    secret_verified_count: int = 0
    suppressed_count: int = 0
    invalidated: list[str] = field(default_factory=list)
    excluded_count: int = 0  # 기본제외+gitignore 로 걸러진 finding 수


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
    secret_policy: str = "off",
    secret_runner=None,
    suppressions=None,
    baseline_keys=None,
    today: str | None = None,
    exclude=None,
    use_default_excludes: bool = True,
    respect_gitignore: bool = True,
) -> ScanResult:
    raws = orchestrate(adapters, target, max_workers=max_workers)
    findings = to_findings(raws)

    # 경로 제외: 기본(build/target/.git/...) + 사용자 지정. 그 후 .gitignore 존중.
    before = len(findings)
    patterns = set(exclude or [])
    if use_default_excludes:
        patterns |= set(DEFAULT_EXCLUDES)
    if patterns:
        findings = exclude_findings(findings, patterns)
    if respect_gitignore:
        findings, _ = filter_gitignored(target, findings)
    excluded_count = before - len(findings)

    ran, reason = False, "off"
    if profile.reachability and reachability_provider is not None:
        outcome = enrich_reachability(
            findings, target,
            provider=reachability_provider,
            env_ok=env_ok, count_loc=count_loc,
            budget=budget, cache=cache, code_hash=code_hash,
        )
        findings, ran, reason = outcome.findings, outcome.ran, outcome.reason

    # 시크릿 검증 (opt-in, network 정책). runner 가 없으면 off 처럼 동작.
    verified_count = 0
    if secret_runner is not None:
        v = verify_secrets_in_findings(findings, target, policy=secret_policy, runner=secret_runner)
        findings, verified_count = v.findings, v.verified_count

    # 억제 (사람이 확정한 것만). baseline → 명시 억제 순. 무효화는 invalidated 로 보고.
    invalidated: list[str] = []
    if baseline_keys:
        findings = apply_baseline(findings, baseline_keys)
    if suppressions:
        s_out = apply_suppressions(findings, suppressions, today=today)
        findings, invalidated = s_out.findings, s_out.invalidated
    suppressed_count = sum(1 for f in findings if f.suppression is not None)

    partial = [r for r in raws if r.status != OK]
    return ScanResult(findings, raws, ran, reason, partial, secret_policy,
                      verified_count, suppressed_count, invalidated, excluded_count)
