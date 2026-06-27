"""프로파일 — "요청한 수준·범위"의 선언적 정의(spec §8).

quick: 초고속(SCA만, 도달성 생략) / accurate-sca: Trivy+osv+도달성 /
standard: 풀스캔(현재 accurate-sca 와 동일, M2/M3 에서 secret·SAST 추가).
"""

from __future__ import annotations

from dataclasses import dataclass

from .adapters.bom_sca import BomScaAdapter
from .adapters.gitleaks import GitleaksAdapter
from .adapters.osv import OsvAdapter
from .adapters.semgrep import SemgrepAdapter
from .adapters.spotbugs import SpotBugsAdapter
from .adapters.trivy import TrivyAdapter


@dataclass(frozen=True)
class Profile:
    name: str
    adapter_names: tuple[str, ...]
    reachability: bool


# 정확/풀스캔 프로파일은 BOM 기반 SCA(bom-sca)로 전이 의존성을 해석한다(recall).
# quick 은 속도 우선이라 fs trivy(빌드/BOM 없이) 사용.
PROFILES: dict[str, Profile] = {
    "quick": Profile("quick", ("trivy", "gitleaks"), False),
    "accurate-sca": Profile("accurate-sca", ("bom-sca",), True),
    "standard": Profile("standard", ("semgrep", "bom-sca", "gitleaks"), True),
    "deep": Profile("deep", ("semgrep", "bom-sca", "gitleaks", "spotbugs"), True),
}

_ADAPTER_CLASSES = {
    "trivy": TrivyAdapter,
    "bom-sca": BomScaAdapter,
    "osv-scanner": OsvAdapter,
    "gitleaks": GitleaksAdapter,
    "semgrep": SemgrepAdapter,
    "spotbugs": SpotBugsAdapter,
}


def get_profile(name: str) -> Profile:
    if name not in PROFILES:
        raise KeyError(f"unknown profile: {name} (가능: {', '.join(PROFILES)})")
    return PROFILES[name]


def build_adapters(profile: Profile) -> list:
    return [_ADAPTER_CLASSES[n]() for n in profile.adapter_names]
