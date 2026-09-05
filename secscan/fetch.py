"""git url → 로컬 얕은 클론 (결정적).

슬래시 커맨드가 자연어로 `rm -rf <파생 경로>` 를 계산하지 않도록, URL 파싱·슬러그
생성·삭제 범위 검증을 전부 여기서 처리한다(원칙 2: 결정적/LLM 경계). Claude 는
`secscan fetch|clean` 을 호출만 하고 경로를 창작하지 않는다.

클론 위치는 `.secscan/repos/<slug>` — `.secscan/` 는 이미 .gitignore 되어 있고
exclude.py 기본 제외 목록에도 있어, security-checker 자신을 점검해도 클론한 남의
코드가 findings 에 섞이지 않는다.

재클론 정책은 "지우고 다시 받기" — 보고서가 항상 "지금 시점의 기본 브랜치" 기준임을
보장한다(얕은 클론이라 비용이 낮다).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

# 프로젝트 루트 기준 기본 클론 루트
DEFAULT_BASE = Path(".secscan/repos")

CLONE_TIMEOUT = 600.0

_SCHEME = re.compile(r"^(?:https?|ssh|git)://", re.IGNORECASE)
_SCP = re.compile(r"^[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+:")
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")


class FetchError(Exception):
    """클론/정리 실패. 사람이 읽을 사유를 담는다."""


@dataclass(frozen=True)
class Clone:
    slug: str
    path: Path
    url: str
    sha: str | None  # rev-parse 실패 시 None (부분 실패는 정상 — 원칙 5)


@dataclass(frozen=True)
class ClonedRepo:
    slug: str
    path: Path
    size_bytes: int


def _subprocess_runner(argv: list[str], timeout: float):
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)


def is_git_url(s: str) -> bool:
    """원격 URL 이면 True, 로컬 경로면 False.

    스킴(https/ssh/git) 또는 scp 형식(user@host:path)만 URL 로 본다. 애매한 형태
    (`github.com/a/b`)를 추측하지 않아야 `/security-check` 인자 해석이 예측 가능하다.
    """
    return bool(_SCHEME.match(s) or _SCP.match(s))


def _split_url(url: str) -> tuple[str, list[str]]:
    """URL → (host, path 조각들). userinfo/포트/.git 접미사는 떨어뜨린다."""
    if _SCHEME.match(url):
        parts = urlsplit(url)
        host = parts.hostname or ""
        path = parts.path
    else:  # scp 형식: user@host:path
        left, _, path = url.partition(":")
        host = left.rpartition("@")[2]

    if path.endswith(".git"):
        path = path[: -len(".git")]
    segments = [seg for seg in path.split("/") if seg]
    return host, segments


def _sanitize(part: str) -> str:
    """디렉터리 이름 1조각으로 안전하게. 상위 탐색 조각은 무해화한다."""
    cleaned = _UNSAFE.sub("-", part)
    if cleaned.strip(".") == "":  # "." / ".." / "..." 등
        cleaned = "_" * len(cleaned)
    return cleaned


def slug_for(url: str) -> str:
    """git url → 디렉터리 이름 1개.

    호스트를 포함해 사내 미러와 원본이 섞이지 않게 하고, https/ssh 는 같은 슬러그로
    모아 한 repo 가 두 번 클론되지 않게 한다.
    """
    host, segments = _split_url(url)
    if not host or not segments:
        raise FetchError(f"repo 경로를 찾을 수 없는 URL 입니다: {url}")
    return "__".join(_sanitize(p) for p in [host, *segments])


def clone_path(url: str, base: Path | str = DEFAULT_BASE) -> Path:
    return Path(base) / slug_for(url)


def _assert_inside(path: Path, base: Path) -> Path:
    """path 가 base 의 진짜 하위인지 확인. 심볼릭 링크 탈출까지 막는다."""
    b = Path(base).resolve()
    p = Path(path).resolve()
    if p == b or b not in p.parents:
        raise FetchError(f"삭제 범위를 벗어난 경로입니다: {path} (허용: {base} 하위)")
    return p


def _rmtree(path: Path, base: Path) -> None:
    shutil.rmtree(_assert_inside(path, base))


def fetch(url: str, base: Path | str = DEFAULT_BASE, *, run=_subprocess_runner) -> Clone:
    """git url 을 base 아래로 얕은 클론. 이미 있으면 지우고 다시 받는다."""
    if not is_git_url(url):
        raise FetchError(f"git URL 이 아닙니다: {url} (로컬 경로는 --target 으로 바로 쓰세요)")

    base = Path(base)
    dest = clone_path(url, base)
    if dest.exists() or dest.is_symlink():
        _rmtree(dest, base)
    base.mkdir(parents=True, exist_ok=True)

    argv = ["git", "clone", "--depth", "1", url, str(dest)]
    try:
        proc = run(argv, timeout=CLONE_TIMEOUT)
    except (subprocess.TimeoutExpired, TimeoutError):
        raise FetchError(f"클론이 {CLONE_TIMEOUT:.0f}s 를 초과했습니다: {url}") from None
    except FileNotFoundError:
        raise FetchError("git 이 설치되어 있지 않습니다.") from None
    except OSError as e:
        raise FetchError(f"클론 실패: {e}") from None

    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()
        reason = detail[-1] if detail else f"exit {proc.returncode}"
        raise FetchError(f"클론 실패({proc.returncode}): {reason}")

    return Clone(slug=dest.name, path=dest, url=url, sha=_head_sha(dest, run=run))


def _head_sha(dest: Path, *, run=_subprocess_runner) -> str | None:
    """보고서에 못 박을 커밋 SHA. 실패해도 클론 자체는 유효하므로 None 을 돌려준다."""
    try:
        proc = run(["git", "-C", str(dest), "rev-parse", "HEAD"], timeout=30.0)
    except (subprocess.TimeoutExpired, TimeoutError, OSError):
        return None
    if proc.returncode != 0:
        return None
    return (proc.stdout or "").strip() or None


def _dir_size(path: Path) -> int:
    total = 0
    for root, _dirs, files in os.walk(path, followlinks=False):
        for name in files:
            fp = Path(root) / name
            try:
                total += fp.lstat().st_size
            except OSError:
                pass
    return total


def list_clones(base: Path | str = DEFAULT_BASE) -> list[ClonedRepo]:
    base = Path(base)
    if not base.is_dir():
        return []
    out = []
    for child in sorted(base.iterdir()):
        if child.is_dir() and not child.is_symlink():
            out.append(ClonedRepo(child.name, child, _dir_size(child)))
    return out


def clean(base: Path | str = DEFAULT_BASE, slug: str | None = None) -> list[Path]:
    """클론 정리. slug 를 주면 그것만, 없으면 전부. base 자체는 남긴다."""
    base = Path(base)
    if slug is None:
        removed = []
        for repo in list_clones(base):
            _rmtree(repo.path, base)
            removed.append(repo.path)
        return removed

    target = base / slug
    _assert_inside(target, base)  # 존재 여부보다 범위 검증이 먼저
    if not (target.exists() or target.is_symlink()):
        raise FetchError(f"그런 클론이 없습니다: {slug}")
    _rmtree(target, base)
    return [target]
