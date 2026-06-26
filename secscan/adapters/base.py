"""어댑터 공통 — RawResult 모델 + 실행/상태 해석 로직.

부수효과(subprocess)는 주입 가능한 runner 로 분리해 결정적 테스트가 가능하다.
타임아웃·미설치는 예외를 status 로 변환해 부분 실패를 1급으로 보고한다(spec §11).
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

# status 상수 (spec §5.1)
OK = "ok"
FAILED = "failed"
TIMEOUT = "timeout"
SKIPPED = "skipped"


@dataclass
class RawResult:
    tool: str
    status: str
    format: str = "json"  # json | sarif | text
    payload: str = ""  # 스캐너 원시 출력(보통 stdout)
    version: str | None = None
    exit_code: int | None = None
    stderr: str = ""
    error: str = ""  # 사람이 읽을 실패/스킵 사유


def _subprocess_runner(argv: list[str], timeout: float):
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)


class CommandAdapter:
    """CLI 스캐너 1개를 감싸는 베이스. 서브클래스는 build_argv 와 메타만 정의한다."""

    name: str = ""
    fmt: str = "json"
    ok_exit_codes: frozenset[int] = frozenset({0})
    default_timeout: float = 600.0  # per-adapter 자원 거버넌스(spec §11)

    def build_argv(self, target, options: dict) -> list[str]:
        raise NotImplementedError

    def run(self, target, options=None, *, run=_subprocess_runner, timeout=None) -> RawResult:
        argv = self.build_argv(target, options or {})
        t = timeout or self.default_timeout
        try:
            proc = run(argv, timeout=t)
        except (subprocess.TimeoutExpired, TimeoutError):
            return RawResult(self.name, TIMEOUT, self.fmt, error=f"{t:.0f}s 초과")
        except FileNotFoundError:
            return RawResult(self.name, SKIPPED, self.fmt, error=f"{self.name} 미설치")
        except OSError as e:  # 권한·실행 불가 등
            return RawResult(self.name, FAILED, self.fmt, error=str(e))

        if proc.returncode in self.ok_exit_codes:
            return RawResult(
                self.name, OK, self.fmt,
                payload=proc.stdout or "", exit_code=proc.returncode,
                stderr=proc.stderr or "",
            )
        return RawResult(
            self.name, FAILED, self.fmt,
            payload=proc.stdout or "", exit_code=proc.returncode,
            stderr=proc.stderr or "", error=f"exit {proc.returncode}",
        )
