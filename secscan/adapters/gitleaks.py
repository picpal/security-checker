"""Gitleaks 어댑터 — secret 탐지.

gitleaks 는 리포트를 stdout 이 아니라 파일로 쓴다(--report-path). 임시 파일에 쓰고
읽어 payload 로 돌려준다. 시크릿 발견 시 exit 1 → ok_exit_codes={0,1}.
오케스트레이터에는 동일한 run(target) 인터페이스를 노출한다.
"""

from __future__ import annotations

import os
import subprocess
import tempfile

from .base import FAILED, OK, SKIPPED, TIMEOUT, RawResult, _subprocess_runner


class GitleaksAdapter:
    name = "gitleaks"
    fmt = "json"
    ok_exit_codes = frozenset({0, 1})  # 1 = 시크릿 발견 = 성공
    default_timeout = 300.0

    def build_argv(self, target, report_path) -> list[str]:
        return [
            "gitleaks", "dir", str(target),
            "--report-format", "json",
            "--report-path", str(report_path),
            "--no-banner",
            "--exit-code", "1",
        ]

    def run(self, target, options=None, *, run=_subprocess_runner, timeout=None) -> RawResult:
        t = timeout or self.default_timeout
        with tempfile.TemporaryDirectory() as td:
            report = os.path.join(td, "gitleaks.json")
            argv = self.build_argv(target, report)
            try:
                proc = run(argv, timeout=t)
            except (subprocess.TimeoutExpired, TimeoutError):
                return RawResult(self.name, TIMEOUT, self.fmt, error=f"{t:.0f}s 초과")
            except FileNotFoundError:
                return RawResult(self.name, SKIPPED, self.fmt, error=f"{self.name} 미설치")
            except OSError as e:
                return RawResult(self.name, FAILED, self.fmt, error=str(e))

            payload = ""
            if os.path.exists(report):
                with open(report) as f:
                    payload = f.read()

            status = OK if proc.returncode in self.ok_exit_codes else FAILED
            err = "" if status == OK else f"exit {proc.returncode}"
            return RawResult(
                self.name, status, self.fmt,
                payload=payload, exit_code=proc.returncode,
                stderr=proc.stderr or "", error=err,
            )
