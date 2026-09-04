"""정확도 측정 — 도달성이 FP(노이즈)를 실제로 줄이는지 정량화 (spec §10.3).

- reachability_stats: on/off 비교. off=모든 탐지가 actionable, on=도달 가능/미상만
  actionable, 도달 불가는 강등. noise_reduction = 강등 비율.
- score_ground_truth: 픽스처 expected.json 대비 도달성 판정 정확도.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

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


# --- V0: 정답지 매니페스트 (spec §3.4) ---

_EXPECTED = frozenset({"present", "absent"})


@dataclass(frozen=True)
class GtEntry:
    """SCA 정답지 항목 = advisory × 패키지 × 설치버전."""
    advisory: str
    package: str  # "group:artifact"
    installed: str
    expected: str = "present"  # present | absent
    origin: str = "team"  # team | dev-found
    row: int | None = None
    aliases: tuple[str, ...] = ()
    fixed: tuple[str, ...] = ()
    severity_team: str | None = None
    cvss_max: float | None = None
    cvss_source: str | None = None
    published: str | None = None  # ISO 날짜, 초과분 분류용
    human_verdict: str | None = None  # reachable | unreachable | None
    reason_class: str | None = None  # config-gated | impl-absent | api-unused
    reason: str | None = None
    note: str | None = None

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.advisory, self.package, self.installed)


@dataclass
class GtManifest:
    kind: str  # sca | source
    snapshot: str | None
    scan_date: str | None
    entries: tuple[GtEntry, ...]  # kind == "sca" 일 때만 채움
    raw_entries: list[dict]  # 원본(소스 정답지는 이걸 그대로 사용)

    def present(self) -> list[GtEntry]:
        return [e for e in self.entries if e.expected == "present"]

    def absent(self) -> list[GtEntry]:
        return [e for e in self.entries if e.expected == "absent"]

    def packages(self) -> set[str]:
        return {e.package for e in self.entries}

    def cves(self) -> set[str]:
        return {e.advisory for e in self.present()}


def _entry_from_dict(d: dict) -> GtEntry:
    exp = d.get("expected", "present")
    if exp not in _EXPECTED:
        raise ValueError(f"expected 는 present|absent — {d.get('advisory')}: {exp}")
    return GtEntry(
        advisory=d["advisory"], package=d["package"], installed=d["installed"],
        expected=exp, origin=d.get("origin", "team"), row=d.get("row"),
        aliases=tuple(d.get("aliases") or ()), fixed=tuple(d.get("fixed") or ()),
        severity_team=d.get("severity_team"), cvss_max=d.get("cvss_max"),
        cvss_source=d.get("cvss_source"), published=d.get("published"),
        human_verdict=d.get("human_verdict"), reason_class=d.get("reason_class"),
        reason=d.get("reason"), note=d.get("note"),
    )


def load_gt_manifest(path) -> GtManifest:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    kind = data.get("kind", "sca")
    raw = list(data.get("entries", []))
    entries: tuple[GtEntry, ...] = ()
    if kind == "sca":
        parsed = [_entry_from_dict(d) for d in raw]
        seen: set[tuple[str, str, str]] = set()
        for e in parsed:
            if e.key in seen:
                raise ValueError(f"중복 항목: {e.key}")
            seen.add(e.key)
        entries = tuple(parsed)
    return GtManifest(kind=kind, snapshot=data.get("snapshot"),
                      scan_date=data.get("scan_date"), entries=entries, raw_entries=raw)
