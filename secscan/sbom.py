"""CycloneDX SBOM 생성 (cdxgen) — gradle/maven 전이 의존성 해석의 핵심.

락파일 없는 gradle 도 cdxgen 이 빌드도구를 호출해 전체 의존 그래프를 BOM 으로 만든다.
그 BOM 을 trivy sbom 으로 스캔하면 fs 정적 파싱이 놓치는 전이 CVE 를 잡는다(recall).

ensure_bom 은 코드 해시별 캐시 + 프로세스 내 락으로 동시 어댑터가 cdxgen 을 한 번만
실행하게 한다.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
import threading
from pathlib import Path


def bom_cache_path(target) -> Path:
    h = hashlib.sha1(str(Path(target).resolve()).encode(), usedforsecurity=False).hexdigest()[:16]
    return Path(tempfile.gettempdir()) / "secscan-bom" / h / "bom.json"


def _cdxgen_runner(argv, timeout):
    env = {**os.environ, "FETCH_LICENSE": "false"}
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env)


def generate_sbom(target, out_path, *, run=_cdxgen_runner, timeout: float = 900.0):
    """cdxgen 으로 BOM 생성. 성공+파일존재면 경로, 아니면 None."""
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    argv = ["cdxgen", "-t", "java", "-o", str(out), str(target)]
    try:
        run(argv, timeout)
    except Exception:
        return None
    if out.exists() and out.stat().st_size > 0:
        return out
    return None


_locks_guard = threading.Lock()
_locks: dict[str, threading.Lock] = {}


def ensure_bom(target, *, timeout: float = 900.0, run=_cdxgen_runner):
    """BOM 을 한 번만 생성(코드 해시 캐시 + 락). 이미 있으면 재사용."""
    path = bom_cache_path(target)
    with _locks_guard:
        lock = _locks.setdefault(str(path), threading.Lock())
    with lock:
        if path.exists() and path.stat().st_size > 0:
            return path
        return generate_sbom(target, path, run=run, timeout=timeout)
