"""정확도 측정 — 도달성이 FP(노이즈)를 실제로 줄이는지 정량화 (spec §10.3).

- reachability_stats: on/off 비교. off=모든 탐지가 actionable, on=도달 가능/미상만
  actionable, 도달 불가는 강등. noise_reduction = 강등 비율.
- score_ground_truth: 픽스처 expected.json 대비 도달성 판정 정확도.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import REACHABLE, UNKNOWN, UNREACHABLE, Finding


@dataclass
class ReachabilityStats:
    total: int
    reachable: int
    unreachable: int
    unknown: int

    @property
    def actionable_off(self) -> int:
        # 도달성 없으면 모든 탐지가 조치 대상
        return self.total

    @property
    def actionable_on(self) -> int:
        # 도달 불가는 강등(우선순위 낮음) → reachable + unknown 만 조치 대상
        return self.reachable + self.unknown

    @property
    def noise_reduction(self) -> float:
        if self.total == 0:
            return 0.0
        return (self.actionable_off - self.actionable_on) / self.total


def reachability_stats(findings: list[Finding]) -> ReachabilityStats:
    r = sum(1 for f in findings if f.reachability.status == REACHABLE)
    u = sum(1 for f in findings if f.reachability.status == UNREACHABLE)
    k = sum(1 for f in findings if f.reachability.status == UNKNOWN)
    return ReachabilityStats(total=len(findings), reachable=r, unreachable=u, unknown=k)


@dataclass
class GroundTruthScore:
    reachable_correct: int = 0
    reachable_total: int = 0
    unreachable_correct: int = 0
    unreachable_total: int = 0
    mistakes: list[str] = field(default_factory=list)

    @property
    def accuracy(self) -> float:
        total = self.reachable_total + self.unreachable_total
        correct = self.reachable_correct + self.unreachable_correct
        return correct / total if total else 0.0


def _find(findings, pkg_substr, cve):
    for f in findings:
        if not f.component or not f.advisory:
            continue
        ids = (f.advisory.id, *f.advisory.aliases)
        if pkg_substr in f.component.package and cve in ids:
            return f
    return None


def score_ground_truth(findings: list[Finding], ground_truth: dict) -> GroundTruthScore:
    score = GroundTruthScore()
    for exp in ground_truth.get("reachable", []):
        score.reachable_total += 1
        f = _find(findings, exp["package"], exp["cve"])
        if f and f.reachability.status == REACHABLE:
            score.reachable_correct += 1
        else:
            got = f.reachability.status if f else "missing"
            score.mistakes.append(f"{exp['package']} {exp['cve']}: 기대 reachable, 실제 {got}")
    for exp in ground_truth.get("unreachable", []):
        score.unreachable_total += 1
        f = _find(findings, exp["package"], exp["cve"])
        if f and f.reachability.status == UNREACHABLE:
            score.unreachable_correct += 1
        else:
            got = f.reachability.status if f else "missing"
            score.mistakes.append(f"{exp['package']} {exp['cve']}: 기대 unreachable, 실제 {got}")
    return score
