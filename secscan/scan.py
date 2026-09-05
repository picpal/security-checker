"""스캔 파이프라인 — 어댑터 병렬 실행 → 정규화/병합 → 도달성 주입 → 결과 집계.

결정적 코드. 도달성 provider 와 환경 점검은 주입 가능(테스트/오프라인 폴백).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .adapters.base import OK, RawResult
from .disposition import decide
from .exclude import DEFAULT_EXCLUDES, exclude_findings, filter_gitignored
from .models import Finding, ScannerStatus
from .normalize import normalize_each, to_findings
from .normalize.merge import merge_consensus
from .orchestrator import scan as orchestrate
from .output.order import sort_findings
from .reachability.engine import Budget, enrich_reachability
from .secret.verify import verify_secrets_in_findings
from .suppress.engine import apply_suppressions
from .suppress.store import apply_baseline


@dataclass
class TraceSink:
    """단계별 attrition 기록(spec §4.2). run_scan 에 주입하지 않으면 아무 비용도 없다."""
    raw: list[dict] = field(default_factory=list)
    stages: list[dict] = field(default_factory=list)

    def record_raw(self, tool: str, status: str, nbytes: int) -> None:
        self.raw.append({"tool": tool, "status": status, "bytes": nbytes})

    def record(self, stage: str, findings) -> None:
        keys = sorted(f.dedup_key for f in findings)
        self.stages.append({"stage": stage, "count": len(keys), "keys": keys})

    def to_dict(self) -> dict:
        return {"raw": list(self.raw), "stages": list(self.stages)}


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
    scanner_status: list[ScannerStatus] = field(default_factory=list)


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
    trace: TraceSink | None = None,
) -> ScanResult:
    raws = orchestrate(adapters, target, max_workers=max_workers)
    if trace is not None:
        for r in raws:
            trace.record_raw(r.tool, r.status, len(r.payload or ""))
        per_tool = normalize_each(raws)
        for tool in sorted(per_tool):
            trace.record(f"normalize:{tool}", per_tool[tool])
        findings = merge_consensus([f for fs in per_tool.values() for f in fs])
        trace.record("merge", findings)
    else:
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
    if trace is not None:
        trace.record("exclude", findings)

    ran, reason = False, "off"
    if profile.reachability and reachability_provider is not None:
        outcome = enrich_reachability(
            findings, target,
            provider=reachability_provider,
            env_ok=env_ok, count_loc=count_loc,
            budget=budget, cache=cache, code_hash=code_hash,
        )
        findings, ran, reason = outcome.findings, outcome.ran, outcome.reason
        if trace is not None:
            trace.record("reachability", findings)

    # 시크릿 검증 (opt-in, network 정책). runner 가 없으면 off 처럼 동작.
    verified_count = 0
    if secret_runner is not None:
        v = verify_secrets_in_findings(findings, target, policy=secret_policy, runner=secret_runner)
        findings, verified_count = v.findings, v.verified_count
        if trace is not None:
            trace.record("secret_verify", findings)

    # 억제 (사람이 확정한 것만). baseline → 명시 억제 순. 무효화는 invalidated 로 보고.
    invalidated: list[str] = []
    if baseline_keys:
        findings = apply_baseline(findings, baseline_keys)
        if trace is not None:
            trace.record("baseline", findings)
    if suppressions:
        s_out = apply_suppressions(findings, suppressions, today=today)
        findings, invalidated = s_out.findings, s_out.invalidated
        if trace is not None:
            trace.record("suppress", findings)
    # 판정 H(spec §7.4): 억제 다음, 출력 앞. compliance 도 여기서 채운다.
    findings = decide(findings)
    if trace is not None:
        trace.record("disposition", findings)
    findings = sort_findings(findings)
    suppressed_count = sum(1 for f in findings if f.suppression is not None)

    partial = [r for r in raws if r.status != OK]
    if trace is not None:
        trace.record("final", findings)
    status = sorted((ScannerStatus(r.tool, r.status, r.version, r.duration_s, r.error) for r in raws),
                    key=lambda s: s.name)
    return ScanResult(findings, raws, ran, reason, partial, secret_policy,
                      verified_count, suppressed_count, invalidated, excluded_count, status)
