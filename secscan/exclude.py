"""경로 기반 finding 제외 — 모든 스캐너에 공통 적용되는 사후 필터.

스캐너마다 exclude 플래그가 제각각(osv 는 빈약)이라, 정규화된 finding 의 경로로
한 번에 거른다. 매칭은 절대/상대 경로 모두에 직관적으로 동작하도록:
- fnmatch 전체 경로 / '*/<pat>' / 경로 세그먼트 일치 / 세그먼트별 fnmatch
"""

from __future__ import annotations

import subprocess
from fnmatch import fnmatch
from pathlib import Path, PurePath

# 스캔에서 기본 제외할 디렉토리(빌드 산출물·VCS·벤더·IDE). 실프로젝트에서 build/ 등을
# 안 빼면 테스트 리포트·산출물이 노이즈로 쏟아진다(message-gate 에서 36/50 이 build/).
DEFAULT_EXCLUDES = frozenset({
    "build", "target", ".git", ".gradle", "node_modules", "dist",
    ".venv", "venv", "__pycache__", ".idea", ".scannerwork", "out",
    ".eggs", ".pytest_cache", ".secscan",
})


def _finding_path(f) -> str:
    if f.location and f.location.file:
        return f.location.file
    return f.source or ""


def path_excluded(path: str, patterns) -> bool:
    if not path or not patterns:
        return False
    parts = PurePath(path).parts
    for pat in patterns:
        if fnmatch(path, pat):
            return True
        if fnmatch(path, f"*/{pat}"):
            return True
        if pat in parts:  # 'fixtures' 같은 맨이름
            return True
        if any(fnmatch(part, pat) for part in parts):
            return True
    return False


def exclude_findings(findings, patterns):
    if not patterns:
        return findings
    return [f for f in findings if not path_excluded(_finding_path(f), patterns)]


def _abs(target, p: str) -> Path:
    pp = Path(p)
    return pp if pp.is_absolute() else Path(target) / p


def _git_check_ignore(target, abs_paths: list[str]) -> set[str]:
    """git check-ignore 로 무시되는 경로 집합을 반환(없거나 git 아니면 빈 집합)."""
    try:
        r = subprocess.run(
            ["git", "-C", str(target), "check-ignore", "--stdin"],
            input="\n".join(abs_paths), capture_output=True, text=True, timeout=30,
        )
    except Exception:
        return set()
    return {line.strip() for line in r.stdout.splitlines() if line.strip()}


def filter_gitignored(target, findings, *, checker=_git_check_ignore):
    """.gitignore 로 무시되는 파일의 finding 을 제거한다(기본 동작)."""
    abs_paths = [str(_abs(target, _finding_path(f))) if _finding_path(f) else "" for f in findings]
    candidates = [ap for ap in abs_paths if ap]
    if not candidates:
        return findings, 0
    ignored = checker(target, list(dict.fromkeys(candidates)))
    if not ignored:
        return findings, 0
    kept = [f for f, ap in zip(findings, abs_paths) if ap not in ignored]
    return kept, len(findings) - len(kept)
