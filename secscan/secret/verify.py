"""시크릿 유효성 검증 정책 + 적용 (spec §8).

정책 해석은 순수하고, 적용은 runner(네트워크) 주입형이라 결정적으로 테스트된다.
안전 불변식: policy 가 'verify' 가 아니면 runner 를 절대 호출하지 않는다(= 전송 없음).
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from ..models import CRITICAL, Finding


def resolve_secret_policy(verify_secrets: bool, network_off: bool) -> str:
    """플래그 → 정책. network_off 가 verify 를 항상 이긴다(안전 우선)."""
    if network_off:
        return "never"
    if verify_secrets:
        return "verify"
    return "off"


@dataclass
class VerifyOutcome:
    findings: list[Finding]
    verified_count: int
    ran: bool
    policy: str


def verify_secrets_in_findings(findings, target, *, policy: str, runner) -> VerifyOutcome:
    secrets = [f for f in findings if f.category == "secret"]
    # off/never 또는 검증할 시크릿 없음 → runner 미호출(네트워크 전송 없음)
    if policy != "verify" or not secrets:
        return VerifyOutcome(findings, 0, False, policy)

    verified_files = runner(target)  # 라이브 시크릿이 있는 파일 집합 (네트워크)
    out: list[Finding] = []
    n = 0
    for f in findings:
        if f.category != "secret":
            out.append(f)
            continue
        live = bool(f.location and f.location.file in verified_files)
        if live:
            n += 1
            out.append(replace(f, verified=True, severity=CRITICAL))
        else:
            out.append(replace(f, verified=False))
    return VerifyOutcome(out, n, True, policy)
