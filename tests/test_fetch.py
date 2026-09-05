"""git url → 로컬 클론(결정적). 슬러그 생성·삭제 범위 가드가 핵심."""

import subprocess
from pathlib import Path

import pytest

from secscan.fetch import (
    FetchError,
    clean,
    clone_path,
    fetch,
    is_git_url,
    list_clones,
    slug_for,
)


# --- is_git_url: 로컬 경로와 원격 URL 구분 (순수) ---

@pytest.mark.parametrize("s", [
    "https://github.com/owner/repo.git",
    "https://github.com/owner/repo",
    "http://internal.example/g/r.git",
    "ssh://git@github.com/owner/repo.git",
    "git://example.com/r.git",
    "git@github.com:owner/repo.git",
])
def test_is_git_url_true(s):
    assert is_git_url(s) is True


@pytest.mark.parametrize("s", [
    "/Users/me/myapp",
    "./myapp",
    "myapp",
    "../sibling",
    "~/projects/app",
])
def test_is_git_url_false_for_local_paths(s):
    assert is_git_url(s) is False


# --- slug_for: 호스트까지 포함해 충돌 방지 (순수) ---

def test_slug_includes_host_and_full_path():
    assert slug_for("https://github.com/owner/repo.git") == "github.com__owner__repo"


def test_slug_same_repo_over_https_and_ssh_collapses():
    """같은 repo 를 https 로 받든 ssh 로 받든 한 디렉터리를 쓴다."""
    a = slug_for("https://github.com/owner/repo.git")
    b = slug_for("git@github.com:owner/repo.git")
    assert a == b


def test_slug_distinguishes_same_repo_name_on_different_hosts():
    """사내 gitlab 미러와 github 원본이 섞이지 않아야 한다."""
    a = slug_for("https://github.com/acme/app.git")
    b = slug_for("https://gitlab.internal/acme/app.git")
    assert a != b


def test_slug_distinguishes_owners():
    assert slug_for("https://github.com/a/app") != slug_for("https://github.com/b/app")


def test_slug_keeps_nested_gitlab_subgroups():
    s = slug_for("https://gitlab.com/group/subgroup/repo.git")
    assert s == "gitlab.com__group__subgroup__repo"


def test_slug_strips_port_and_userinfo():
    s = slug_for("ssh://git@code.example.com:2222/team/svc.git")
    assert s == "code.example.com__team__svc"


def test_slug_never_contains_separator_or_traversal():
    s = slug_for("https://github.com/../../etc/passwd.git")
    assert "/" not in s
    assert ".." not in s


def test_slug_rejects_url_without_repo_path():
    with pytest.raises(FetchError):
        slug_for("https://github.com/")


# --- clone_path: 항상 base 아래 ---

def test_clone_path_is_under_base(tmp_path):
    p = clone_path("https://github.com/owner/repo.git", tmp_path)
    assert p.parent == tmp_path
    assert p.name == "github.com__owner__repo"


# --- fetch: 얕은 클론 + SHA, 기존 클론은 지우고 재클론 (A안) ---

class FakeGit:
    """git 호출을 기록하고 정해진 결과를 돌려주는 스텁."""

    def __init__(self, sha="abc1234", clone_rc=0, make_dir=True):
        self.calls: list[list[str]] = []
        self.sha = sha
        self.clone_rc = clone_rc
        self.make_dir = make_dir

    def __call__(self, argv, timeout=None):
        self.calls.append(list(argv))
        if argv[:2] == ["git", "clone"]:
            if self.clone_rc == 0 and self.make_dir:
                Path(argv[-1]).mkdir(parents=True, exist_ok=True)
            return subprocess.CompletedProcess(argv, self.clone_rc, "", "fatal: nope")
        if "rev-parse" in argv:
            return subprocess.CompletedProcess(argv, 0, self.sha + "\n", "")
        return subprocess.CompletedProcess(argv, 0, "", "")


def test_fetch_uses_shallow_clone(tmp_path):
    git = FakeGit()
    fetch("https://github.com/owner/repo.git", tmp_path, run=git)
    clone_argv = git.calls[0]
    assert clone_argv[:2] == ["git", "clone"]
    assert "--depth" in clone_argv and "1" in clone_argv


def test_fetch_returns_path_and_commit_sha(tmp_path):
    git = FakeGit(sha="deadbeef")
    c = fetch("https://github.com/owner/repo.git", tmp_path, run=git)
    assert c.path == tmp_path / "github.com__owner__repo"
    assert c.sha == "deadbeef"
    assert c.slug == "github.com__owner__repo"


def test_fetch_reclones_over_existing_dir(tmp_path):
    """A안: 이미 있으면 지우고 다시 받는다 — 어제 코드를 오늘 결과로 착각 금지."""
    dest = tmp_path / "github.com__owner__repo"
    dest.mkdir(parents=True)
    (dest / "stale.txt").write_text("old")

    git = FakeGit()
    fetch("https://github.com/owner/repo.git", tmp_path, run=git)
    assert not (dest / "stale.txt").exists()


def test_fetch_raises_on_clone_failure(tmp_path):
    git = FakeGit(clone_rc=128, make_dir=False)
    with pytest.raises(FetchError) as e:
        fetch("https://github.com/owner/repo.git", tmp_path, run=git)
    assert "fatal" in str(e.value) or "128" in str(e.value)


def test_fetch_tolerates_missing_sha(tmp_path):
    """SHA 조회가 실패해도 클론 자체는 유효 — 부분 실패는 정상(원칙 5)."""

    class NoSha(FakeGit):
        def __call__(self, argv, timeout=None):
            if "rev-parse" in argv:
                self.calls.append(list(argv))
                return subprocess.CompletedProcess(argv, 128, "", "err")
            return super().__call__(argv, timeout=timeout)

    c = fetch("https://github.com/owner/repo.git", tmp_path, run=NoSha())
    assert c.sha is None
    assert c.path.exists()


def test_fetch_rejects_local_path(tmp_path):
    with pytest.raises(FetchError):
        fetch("/Users/me/myapp", tmp_path, run=FakeGit())


# --- list_clones / clean ---

def test_list_clones_reports_slug_and_size(tmp_path):
    d = tmp_path / "github.com__owner__repo"
    d.mkdir(parents=True)
    (d / "f.txt").write_text("x" * 100)

    clones = list_clones(tmp_path)
    assert [c.slug for c in clones] == ["github.com__owner__repo"]
    assert clones[0].size_bytes >= 100


def test_list_clones_empty_when_base_missing(tmp_path):
    assert list_clones(tmp_path / "nope") == []


def test_clean_all_removes_every_clone_but_keeps_base(tmp_path):
    for name in ("github.com__a__app", "github.com__b__app"):
        (tmp_path / name).mkdir(parents=True)

    removed = clean(tmp_path)
    assert len(removed) == 2
    assert tmp_path.exists()
    assert list_clones(tmp_path) == []


def test_clean_one_slug_leaves_others(tmp_path):
    keep = tmp_path / "github.com__b__app"
    (tmp_path / "github.com__a__app").mkdir(parents=True)
    keep.mkdir(parents=True)

    clean(tmp_path, slug="github.com__a__app")
    assert keep.exists()
    assert [c.slug for c in list_clones(tmp_path)] == ["github.com__b__app"]


def test_clean_unknown_slug_raises(tmp_path):
    with pytest.raises(FetchError):
        clean(tmp_path, slug="nope")


# --- 삭제 범위 가드: base 밖은 절대 못 지운다 ---

@pytest.mark.parametrize("slug", ["..", "../..", "../sibling", "/etc"])
def test_clean_refuses_to_escape_base(tmp_path, slug):
    base = tmp_path / "repos"
    base.mkdir()
    victim = tmp_path / "sibling"
    victim.mkdir()
    (victim / "important.txt").write_text("do not delete")

    with pytest.raises(FetchError):
        clean(base, slug=slug)
    assert (victim / "important.txt").exists()


def test_clean_refuses_symlink_escaping_base(tmp_path):
    """base 안의 심볼릭 링크를 타고 밖을 지우면 안 된다."""
    base = tmp_path / "repos"
    base.mkdir()
    victim = tmp_path / "sibling"
    victim.mkdir()
    (victim / "important.txt").write_text("do not delete")
    (base / "sneaky").symlink_to(victim, target_is_directory=True)

    with pytest.raises(FetchError):
        clean(base, slug="sneaky")
    assert (victim / "important.txt").exists()
