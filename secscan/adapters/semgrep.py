"""Semgrep CE 어댑터 — SAST.

p/java + p/security-audit 룰셋(레지스트리, 네트워크) 으로 소스 스캔. JSON 출력.
semgrep 은 finding 이 있어도 기본 exit 0 (--error 미지정) → ok_exit_codes={0}.
"""

from __future__ import annotations

from pathlib import Path

from .base import CommandAdapter

# 커스텀 룰 디렉토리(D, 패키지 동봉). 설치 위치 무관하게 __file__ 기준 해석.
_RULES_DIR = str(Path(__file__).resolve().parent.parent / "rules")


class SemgrepAdapter(CommandAdapter):
    name = "semgrep"
    fmt = "json"
    ok_exit_codes = frozenset({0})

    def build_argv(self, target, options: dict) -> list[str]:
        return [
            "semgrep",
            "--config", "p/java",
            "--config", "p/security-audit",
            "--config", "p/owasp-top-ten",
            "--config", "p/cwe-top-25",
            "--config", _RULES_DIR,  # 커스텀 룰 (D) — 기본 팩과 함께 항상 로드
            "--json",
            "--quiet",
            "--disable-version-check",
            str(target),
        ]
