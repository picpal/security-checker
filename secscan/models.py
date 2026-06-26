"""typed finding 모델 — 내부 canonical (spec §6).

SARIF 가 아니라 이 모델이 1급 시민이다. SCA(component/advisory 중심)와
SAST/secret(location 중심)을 한 모델로 담고, dedup·도달성·합의·억제 메타를
자연스럽게 싣는다. SARIF 는 출력 단계에서만 emit 한다(spec 원칙 3).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

# --- severity 정규화 ---
CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"
UNKNOWN = "unknown"

_SEV_RANK = {UNKNOWN: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4}


def normalize_severity(raw: str | None) -> str:
    if not raw:
        return UNKNOWN
    r = raw.strip().lower()
    return r if r in _SEV_RANK else UNKNOWN


def severity_rank(s: str) -> int:
    return _SEV_RANK.get(s, 0)


def max_severity(a: str, b: str) -> str:
    return a if severity_rank(a) >= severity_rank(b) else b


# --- reachability 상태 ---
REACHABLE = "reachable"
UNREACHABLE = "unreachable"
# UNKNOWN 재사용


@dataclass
class Component:
    """SCA 컴포넌트형 finding 의 대상."""

    ecosystem: str  # "maven"
    package: str  # "org.apache.commons:commons-text"
    version: str  # "1.9"


@dataclass
class Advisory:
    id: str  # canonical (가능하면 CVE)
    aliases: tuple[str, ...] = ()
    fixed_versions: tuple[str, ...] = ()


@dataclass
class Location:
    """SAST/secret 위치형 finding 의 대상."""

    file: str
    start_line: int | None = None
    end_line: int | None = None
    snippet_ref: str | None = None


@dataclass
class Reachability:
    status: str = UNKNOWN  # reachable | unreachable | unknown
    evidence: str | None = None  # 콜패스 요약 등
    source: str | None = None  # dep-scan | claude


@dataclass
class Consensus:
    tools: tuple[str, ...] = ()  # 같은 finding 을 지목한 도구들
    score: int = 0


@dataclass
class Finding:
    category: str  # sca | sast | secret
    severity: str = UNKNOWN
    title: str = ""
    tool: str = ""  # 원천 도구 (병합 후엔 consensus.tools 가 권위)
    rule_id: str = ""  # SCA: advisory id, SAST: 룰 id
    cwe: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()
    component: Component | None = None  # SCA
    advisory: Advisory | None = None  # SCA
    location: Location | None = None  # SAST/secret
    reachability: Reachability = field(default_factory=Reachability)
    consensus: Consensus | None = None
    references: tuple[str, ...] = ()
    verified: bool | None = None  # secret 전용: None=미검증, True=라이브 확인, False=검증했으나 비활성

    @property
    def dedup_key(self) -> str:
        """도구 독립적 키 — 같은 취약점이면 도구가 달라도 같은 키로 합쳐진다."""
        if self.category == "sca" and self.component and self.advisory:
            return "|".join([
                "sca", self.component.ecosystem, self.component.package,
                self.component.version, self.advisory.id,
            ])
        if self.location:
            return "|".join([
                self.category, self.location.file,
                str(self.location.start_line or ""), self.rule_id,
            ])
        return "|".join([self.category, self.tool, self.rule_id, self.title])

    @property
    def id(self) -> str:
        return hashlib.sha1(self.dedup_key.encode()).hexdigest()[:12]
