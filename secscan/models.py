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


# --- confidence 정규화 (semgrep 등 SAST 메타는 대문자 HIGH/MEDIUM/LOW) ---
_CONF = frozenset({"high", "medium", "low"})
_CONF_RANK = {"unknown": 0, "low": 1, "medium": 2, "high": 3}


def normalize_confidence(raw: str | None) -> str:
    if not raw:
        return "unknown"
    r = raw.strip().lower()
    return r if r in _CONF else "unknown"


def min_confidence(a: str, b: str) -> str:
    """병합 시 보수적 집계 — 더 낮은(불확실한) confidence 를 택한다."""
    return a if _CONF_RANK.get(a, 0) <= _CONF_RANK.get(b, 0) else b


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


@dataclass(frozen=True)
class KisaWeakness:
    """KISA 소프트웨어 보안약점(49개 중 1개). code 는 내부 식별자(공식 번호 아님)."""

    code: str  # 내부 ID 예: "IV-01" (카테고리약자-순번)
    category: str  # 7대 분류 예: "입력데이터 검증 및 표현"
    name: str  # 약점명 예: "SQL 삽입"


@dataclass(frozen=True)
class Compliance:
    """CWE 에서 파생한 컴플라이언스 뷰(KISA·PCI). 결정적 매핑 — 판정이 아니라 분류."""

    kisa: tuple[KisaWeakness, ...] = ()
    pci: tuple[str, ...] = ()  # PCI-DSS v4.0.1 §6.2.4 공격유형 라벨


@dataclass
class Suppression:
    """억제 엔트리 (spec §12). 자동 생성 금지 — 사람이 증거를 확인해 확정한다."""

    state: str  # suppressed | baseline | under_review
    reason: str
    provenance: str  # 누가/언제/왜
    evidence: str  # 도달 불가 콜패스 등 근거
    expiry: str | None  # ISO "YYYY-MM-DD" (만료되면 재표면)
    scope: str  # 대상 finding 의 dedup_key (정확 매칭 → 버전 바뀌면 자동 무효)
    basis: str = ""  # "unreachable" 등 — 도달성 변화 시 무효화 판단용


@dataclass
class Finding:
    category: str  # sca | sast | secret
    severity: str = UNKNOWN
    title: str = ""
    tool: str = ""  # 원천 도구 (병합 후엔 consensus.tools 가 권위)
    rule_id: str = ""  # SCA: advisory id, SAST: 룰 id
    cwe: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()
    confidence: str = "unknown"  # SAST 신뢰도(semgrep 메타) — high/medium/low/unknown
    component: Component | None = None  # SCA
    advisory: Advisory | None = None  # SCA
    location: Location | None = None  # SAST/secret
    source: str = ""  # finding 출처 파일(SCA 매니페스트 등) — 경로 기반 제외용
    reachability: Reachability = field(default_factory=Reachability)
    consensus: Consensus | None = None
    references: tuple[str, ...] = ()
    verified: bool | None = None  # secret 전용: None=미검증, True=라이브 확인, False=검증했으나 비활성
    suppression: "Suppression | None" = None  # 사람이 확정한 억제 (자동 금지)
    compliance: "Compliance | None" = None  # CWE 에서 파생한 KISA/PCI 매핑 (결정적)

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
        # 보안용이 아니라 안정적 식별자(dedup 키 해시)용. usedforsecurity=False 로 의도 명시.
        return hashlib.sha1(self.dedup_key.encode(), usedforsecurity=False).hexdigest()[:12]


def sast_tier(f: Finding) -> str | None:
    """SAST finding 의 신뢰도 등급. SCA·secret 은 None(기존 우선순위 로직 유지).

    confidence(high/medium) + severity(critical/high/medium) 둘 다일 때만 actionable.
    missing/unknown confidence 는 review — 검증 안 된 룰을 우선 버킷에 넣지 않는다(원칙1).
    """
    if f.category != "sast":
        return None
    if f.confidence in ("high", "medium") and f.severity in (CRITICAL, HIGH, MEDIUM):
        return "actionable"
    return "review"
