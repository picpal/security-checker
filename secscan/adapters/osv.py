"""osv-scanner 어댑터 — OSV.dev advisory 커버리지 보강(FN 감소).

핵심 함정: osv-scanner 는 **취약점 발견 시 exit 1** 을 반환한다(에러 아님).
따라서 ok_exit_codes={0,1}. 그보다 큰 코드(127/128 등)만 실패로 본다.
"""

from __future__ import annotations

from .base import CommandAdapter


class OsvAdapter(CommandAdapter):
    name = "osv-scanner"
    fmt = "json"
    ok_exit_codes = frozenset({0, 1})  # 1 = 취약점 발견 = 성공

    def build_argv(self, target, options: dict) -> list[str]:
        # osv-scanner v2: `scan source -r <dir>` (구 `osv-scanner <dir>` 대체)
        return [
            "osv-scanner", "scan", "source",
            "--format", "json",
            "-r",
            str(target),
        ]
