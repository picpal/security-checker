"""스냅샷 격리 — message-gate 커밋을 새 디렉토리에 꺼내고 크리덴셜 없는 환경을 만든다(spec §4.1).

빌드(cdxgen/gradle/spotbugs)는 임의 코드 실행이므로 "read-only" 가 아니라 "격리 실행"이다.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

_CRED_RE = re.compile(r"(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API_KEY|^AWS_|^GITHUB_|^GH_)", re.IGNORECASE)


def prepare_snapshot(repo: Path, sha: str, scratch_root: Path, *, run=subprocess.run) -> Path:
    dest = Path(scratch_root) / sha / "repo"
    if dest.exists():
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    r = run(["git", "clone", "--local", "--no-checkout", str(repo), str(dest)],
            capture_output=True, text=True)
    if getattr(r, "returncode", 1) != 0:
        raise RuntimeError(f"git clone 실패: {getattr(r, 'stderr', '')}")
    r = run(["git", "-C", str(dest), "checkout", "--detach", sha], capture_output=True, text=True)
    if getattr(r, "returncode", 1) != 0:
        raise RuntimeError(f"git checkout {sha} 실패: {getattr(r, 'stderr', '')}")
    return dest


def isolated_env(scratch_root: Path, sha: str, base: dict | None = None) -> dict:
    src = dict(os.environ if base is None else base)
    env = {k: v for k, v in src.items() if not _CRED_RE.search(k)}
    env["GRADLE_USER_HOME"] = str(Path(scratch_root) / sha / "gradle-home")
    env["GRADLE_OPTS"] = "-Dorg.gradle.daemon=false"
    env["SECSCAN_VERIFY_ISOLATED"] = "1"
    return env
