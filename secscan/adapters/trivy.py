"""Trivy 어댑터 — SCA 탐지 허브. `trivy fs` 로 Maven/Gradle 의존성 취약점.

Trivy 는 취약점이 있어도 기본 exit 0 (--exit-code 미지정 시) → ok_exit_codes={0}.
"""

from __future__ import annotations

from .base import CommandAdapter


class TrivyAdapter(CommandAdapter):
    name = "trivy"
    fmt = "json"
    ok_exit_codes = frozenset({0})

    def build_argv(self, target, options: dict) -> list[str]:
        return [
            "trivy", "fs",
            "--scanners", "vuln",
            "--format", "json",
            "--quiet",
            str(target),
        ]
