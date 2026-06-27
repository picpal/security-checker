"""BOM 기반 SCA 어댑터 — cdxgen BOM 을 trivy sbom 으로 스캔.

가장 중요한 recall 복구 경로: 락파일 없는 gradle 에서도 전이 의존 CVE 를 잡는다.
trivy sbom 출력은 `trivy fs` 와 동일 스키마라 tool="trivy" 로 두면 parse_trivy 가
그대로 정규화한다. cdxgen/trivy 실패는 status 로 격리(부분 실패).
"""

from __future__ import annotations

import subprocess

from ..sbom import ensure_bom as _ensure_bom
from .base import FAILED, OK, SKIPPED, TIMEOUT, RawResult, _subprocess_runner


class BomScaAdapter:
    name = "trivy"  # parse_trivy 가 정규화 (BOM 스캔 결과도 동일 스키마)
    fmt = "json"
    default_timeout = 900.0

    def build_argv(self, bom_path) -> list[str]:
        return ["trivy", "sbom", "--format", "json", "--quiet", str(bom_path)]

    def run(self, target, options=None, *, ensure_bom=_ensure_bom,
            run=_subprocess_runner, timeout=None) -> RawResult:
        t = timeout or self.default_timeout
        try:
            bom = ensure_bom(target, timeout=t)
        except Exception as e:
            return RawResult(self.name, SKIPPED, self.fmt, error=f"BOM 생성 격리: {e}")
        if not bom:
            return RawResult(self.name, SKIPPED, self.fmt,
                             error="cdxgen BOM 생성 실패 — SCA 건너뜀(부분)")

        argv = self.build_argv(bom)
        try:
            proc = run(argv, t)
        except (subprocess.TimeoutExpired, TimeoutError):
            return RawResult(self.name, TIMEOUT, self.fmt, error=f"{t:.0f}s 초과")
        except FileNotFoundError:
            return RawResult(self.name, SKIPPED, self.fmt, error="trivy 미설치")
        if proc.returncode == 0:
            return RawResult(self.name, OK, self.fmt, payload=proc.stdout or "",
                             exit_code=0, stderr=proc.stderr or "")
        return RawResult(self.name, FAILED, self.fmt, payload=proc.stdout or "",
                         exit_code=proc.returncode, stderr=proc.stderr or "",
                         error=f"exit {proc.returncode}")
