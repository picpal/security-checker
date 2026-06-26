"""프로파일 — "요청한 수준·범위"의 선언적 정의(spec §8).

quick: 초고속(SCA만, 도달성 생략) / accurate-sca: Trivy+osv+도달성 /
standard: 풀스캔(현재 accurate-sca 와 동일, M2/M3 에서 secret·SAST 추가).
"""

from __future__ import annotations

from dataclasses import dataclass

from .adapters.gitleaks import GitleaksAdapter
from .adapters.osv import OsvAdapter
from .adapters.trivy import TrivyAdapter


@dataclass(frozen=True)
class Profile:
    name: str
    adapter_names: tuple[str, ...]
    reachability: bool


PROFILES: dict[str, Profile] = {
    "quick": Profile("quick", ("trivy", "gitleaks"), False),
    "accurate-sca": Profile("accurate-sca", ("trivy", "osv-scanner"), True),
    "standard": Profile("standard", ("trivy", "osv-scanner", "gitleaks"), True),
}

_ADAPTER_CLASSES = {
    "trivy": TrivyAdapter,
    "osv-scanner": OsvAdapter,
    "gitleaks": GitleaksAdapter,
}


def get_profile(name: str) -> Profile:
    if name not in PROFILES:
        raise KeyError(f"unknown profile: {name} (가능: {', '.join(PROFILES)})")
    return PROFILES[name]


def build_adapters(profile: Profile) -> list:
    return [_ADAPTER_CLASSES[n]() for n in profile.adapter_names]
