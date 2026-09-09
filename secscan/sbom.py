"""CycloneDX SBOM 생성 (cdxgen) — gradle/maven 전이 의존성 해석의 핵심.

락파일 없는 gradle 도 cdxgen 이 빌드도구를 호출해 전체 의존 그래프를 BOM 으로 만든다.
그 BOM 을 trivy sbom 으로 스캔하면 fs 정적 파싱이 놓치는 전이 CVE 를 잡는다(recall).

ensure_bom 은 "대상 경로 + 의존성 매니페스트 내용" 해시 캐시 + 프로세스 내 락으로
동시 어댑터가 cdxgen 을 한 번만 실행하게 한다. 매니페스트가 바뀌면 캐시 경로가 바뀌어
BOM 이 반드시 재생성된다(2026-09-09 실측 결함: 경로만으로 키를 잡아 의존성을 올려도
옛 BOM 이 영원히 재사용됐다 — 원칙 1 정확도 우선 위반).
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
import threading
from fnmatch import fnmatch
from pathlib import Path

from .exclude import DEFAULT_EXCLUDES, path_excluded

# BOM 의 입력 = 의존성을 선언하는 파일. gradle 은 build/settings 외에 `apply from` 으로
# 끌어쓰는 dependencies.gradle 류도 의존성을 선언하므로 *.gradle 전체를 본다
# (cli.py::_SRC_GLOBS 와 같은 표기). *.lockfile 은 gradle 의존성 잠금(gradle.lockfile,
# buildscript-gradle.lockfile), *.versions.toml 은 버전 카탈로그.
_MANIFEST_GLOBS = (
    "pom.xml",
    "*.gradle", "*.gradle.kts",
    "gradle.properties",
    "*.versions.toml",
    "*.lockfile",
)


def _is_manifest(name: str) -> bool:
    return any(fnmatch(name, g) for g in _MANIFEST_GLOBS)


def iter_manifests(target, *, excludes=DEFAULT_EXCLUDES):
    """대상 안의 의존성 매니페스트를 결정적 순서로 나열.

    exclude.py 의 기본 제외를 디렉토리 단계에서 가지치기한다 — node_modules/build/.git
    안의 pom.xml 이 캐시 키를 오염시키면 빌드마다 키가 흔들려 캐시가 무의미해진다.
    """
    root = Path(target)
    for dirpath, dirnames, filenames in os.walk(root):
        rel = Path(dirpath).relative_to(root)
        dirnames[:] = sorted(d for d in dirnames if not path_excluded(str(rel / d), excludes))
        for name in sorted(filenames):
            if _is_manifest(name):
                yield Path(dirpath) / name


def manifest_fingerprint(target, *, excludes=DEFAULT_EXCLUDES) -> str:
    """의존성 매니페스트의 (상대경로, 내용) 해시. 캐시 키(식별자)용 — 보안 해시 아님.

    mtime 은 쓰지 않는다: git checkout/clone 이 mtime 을 바꿔 내용이 같아도 캐시가
    매번 무효화된다(재생성 비용이 커서 캐시가 사실상 사라짐).
    """
    root = Path(target)
    h = hashlib.sha1(usedforsecurity=False)
    for p in iter_manifests(root, excludes=excludes):
        h.update(str(p.relative_to(root)).encode())  # 매니페스트 추가/삭제/이동도 반영
        h.update(b"\0")
        try:
            h.update(hashlib.sha1(p.read_bytes(), usedforsecurity=False).digest())
        except OSError:
            h.update(b"<unreadable>")
        h.update(b"\n")
    return h.hexdigest()[:16]


def bom_cache_path(target, *, excludes=DEFAULT_EXCLUDES) -> Path:
    """대상 경로 해시 / 매니페스트 내용 해시 / bom.json.

    경로 해시로 서로 다른 대상을 분리하고, 매니페스트 해시로 의존성 변경을 감지한다.
    바뀌면 새 경로(재생성), 그대로면 같은 경로(캐시 유지).
    """
    t = Path(target).resolve()
    h = hashlib.sha1(str(t).encode(), usedforsecurity=False).hexdigest()[:16]
    return (Path(tempfile.gettempdir()) / "secscan-bom" / h
            / manifest_fingerprint(t, excludes=excludes) / "bom.json")


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
    """BOM 을 한 번만 생성(경로+매니페스트 해시 캐시 + 락). 매니페스트가 그대로면 재사용."""
    path = bom_cache_path(target)
    with _locks_guard:
        lock = _locks.setdefault(str(path), threading.Lock())
    with lock:
        if path.exists() and path.stat().st_size > 0:
            return path
        return generate_sbom(target, path, run=run, timeout=timeout)
