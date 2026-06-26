"""SpotBugs + FindSecBugs 어댑터 — 바이트코드 SAST (deep, experimental).

바이트코드 분석이라 **컴파일된 클래스가 필요**하다. 클래스가 없으면 빌드를 시도하고,
빌드가 실패하면 크래시 없이 status=skipped(partial)로 격리한다(spec §13: 빌드 의존 함정).
전체를 try 로 감싸 어떤 실패도 deep 만 건너뛰고 다른 스캐너 결과는 보존한다.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

from .base import FAILED, OK, SKIPPED, TIMEOUT, RawResult, _subprocess_runner


def _default_find_classes(target) -> str | None:
    for sub in ("target/classes", "build/classes/java/main", "build/classes"):
        p = Path(target) / sub
        if p.exists() and any(p.rglob("*.class")):
            return str(p)
    return None


def _default_build(target) -> bool:
    t = Path(target)
    try:
        if (t / "pom.xml").exists():
            r = subprocess.run(["mvn", "-q", "-DskipTests", "compile"],
                               cwd=str(t), capture_output=True, text=True, timeout=600)
            return r.returncode == 0
        if (t / "build.gradle").exists() or (t / "build.gradle.kts").exists():
            r = subprocess.run(["gradle", "compileJava", "-q"],
                               cwd=str(t), capture_output=True, text=True, timeout=600)
            return r.returncode == 0
    except Exception:
        return False
    return False


def _findsecbugs_jar() -> str | None:
    p = Path.home() / ".local" / "share" / "secscan" / "findsecbugs-plugin.jar"
    return str(p) if p.exists() else None


class SpotBugsAdapter:
    name = "spotbugs"
    fmt = "sarif"
    default_timeout = 900.0

    def build_argv(self, classes, out) -> list[str]:
        argv = ["spotbugs", "-textui"]
        jar = _findsecbugs_jar()
        if jar:
            argv += ["-pluginList", jar]
        argv += ["-sarif", "-output", str(out), "-effort:max", "-low", str(classes)]
        return argv

    def run(self, target, options=None, *, find_classes=_default_find_classes,
            build=_default_build, run=_subprocess_runner, timeout=None) -> RawResult:
        t = timeout or self.default_timeout
        try:
            classes = find_classes(target)
            if classes is None:
                try:
                    built = build(target)
                except Exception as e:
                    return RawResult(self.name, SKIPPED, self.fmt, error=f"빌드 실패(격리): {e}")
                if not built:
                    return RawResult(self.name, SKIPPED, self.fmt,
                                     error="빌드 실패/불가 — deep 바이트코드 분석 건너뜀")
                classes = find_classes(target)
                if classes is None:
                    return RawResult(self.name, SKIPPED, self.fmt, error="컴파일된 클래스 없음")

            with tempfile.TemporaryDirectory() as td:
                out = os.path.join(td, "spotbugs.sarif")
                argv = self.build_argv(classes, out)
                try:
                    proc = run(argv, t)
                except (subprocess.TimeoutExpired, TimeoutError):
                    return RawResult(self.name, TIMEOUT, self.fmt, error=f"{t:.0f}s 초과")
                except FileNotFoundError:
                    return RawResult(self.name, SKIPPED, self.fmt, error="spotbugs 미설치")
                if os.path.exists(out):
                    with open(out) as f:
                        payload = f.read()
                    return RawResult(self.name, OK, self.fmt, payload=payload,
                                     exit_code=getattr(proc, "returncode", None))
                return RawResult(self.name, FAILED, self.fmt,
                                 error=f"SARIF 출력 없음 (exit {getattr(proc, 'returncode', '?')})")
        except Exception as e:  # 무엇이 터지든 deep 만 격리
            return RawResult(self.name, SKIPPED, self.fmt, error=f"deep 분석 격리: {e}")
