"""스냅샷 격리 — message-gate 커밋을 새 디렉토리에 꺼내고 크리덴셜 없는 환경을 만든다(spec §4.1).

빌드(cdxgen/gradle/spotbugs)는 임의 코드 실행이므로 "read-only" 가 아니라 "격리 실행"이다.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

_CRED_RE = re.compile(r"(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API_KEY|^AWS_|^GITHUB_|^GH_)", re.IGNORECASE)


def prepare_snapshot(repo: Path, sha: str, scratch_root: Path, *, run=subprocess.run) -> Path:
    dest = Path(scratch_root) / sha / "repo"
    if dest.exists():
        # 재사용 전 검증: 이전 실행이 clone 만 하고 checkout 에 실패했을 수 있으므로
        # 실제 HEAD 가 요청한 sha 와 일치하는지 확인한다(짧은/긴 sha 양쪽 허용).
        r = run(["git", "-C", str(dest), "rev-parse", "HEAD"], capture_output=True, text=True)
        head = (getattr(r, "stdout", "") or "").strip()
        matches = (
            getattr(r, "returncode", 1) == 0
            and bool(head)
            and (head.startswith(sha) or sha.startswith(head))
        )
        if not matches:
            raise RuntimeError(
                f"재사용하려는 스냅샷의 HEAD({head!r})가 요청한 sha({sha!r})와 다릅니다: {dest} "
                "(이전 checkout 이 실패했을 수 있음 — 디렉토리를 지우고 다시 시도하세요)"
            )
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    r = run(["git", "clone", "--local", "--no-checkout", str(repo), str(dest)],
            capture_output=True, text=True)
    if getattr(r, "returncode", 1) != 0:
        raise RuntimeError(f"git clone 실패: {getattr(r, 'stderr', '')}")
    r = run(["git", "-C", str(dest), "checkout", "--detach", sha], capture_output=True, text=True)
    if getattr(r, "returncode", 1) != 0:
        # 부분 클론을 남기면 다음 호출이 검증 없이 조용히 재사용할 수 있으므로 반드시 정리한다.
        shutil.rmtree(dest, ignore_errors=True)
        raise RuntimeError(f"git checkout {sha} 실패: {getattr(r, 'stderr', '')}")
    return dest


def isolated_env(scratch_root: Path, sha: str, base: dict | None = None) -> dict:
    src = dict(os.environ if base is None else base)
    env = {k: v for k, v in src.items() if not _CRED_RE.search(k)}
    env["GRADLE_USER_HOME"] = str(Path(scratch_root) / sha / "gradle-home")
    env["GRADLE_OPTS"] = "-Dorg.gradle.daemon=false"
    env["SECSCAN_VERIFY_ISOLATED"] = "1"
    return env


def apply_isolated_env(scratch_root: Path, sha: str) -> dict:
    """isolated_env 를 계산해 실제 프로세스의 os.environ 에 적용한다.

    os.environ.update(isolated_env(...)) 만으로는 필터링된(제거된) 키가 이미 os.environ 에
    남아있는 경우 지워지지 않는다 — clear() 후 재적용해야 크리덴셜이 실제로 없어진다.
    이후 이 프로세스가 spawn 하는 모든 subprocess(git/cdxgen/gradle/semgrep/trivy/spotbugs)가
    이 환경을 상속한다.
    """
    env = isolated_env(scratch_root, sha)
    os.environ.clear()
    os.environ.update(env)
    return env
