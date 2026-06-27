"""경로 기반 finding 제외 — 이질적 스캐너 공통 사후 필터(--exclude)."""

from secscan.exclude import (
    DEFAULT_EXCLUDES,
    exclude_findings,
    filter_gitignored,
    path_excluded,
)
from secscan.models import Advisory, Component, Finding, Location


def _loc(file):
    return Finding(category="sast", severity="high", rule_id="r",
                   location=Location(file, start_line=1))


def _sca(source):
    return Finding(category="sca", severity="high", source=source,
                   component=Component("maven", "p", "1"), advisory=Advisory("CVE-1"))


def test_path_excluded_bare_dir_name():
    assert path_excluded("fixtures/secret-app/x.properties", ["fixtures"])
    assert not path_excluded("secscan/cli.py", ["fixtures"])


def test_path_excluded_glob():
    assert path_excluded("a/secret-app/x", ["*/secret-app/*"])
    assert path_excluded("fixtures/y", ["fixtures/*"])


def test_path_excluded_absolute_path():
    assert path_excluded("/Users/me/proj/fixtures/p/pom.xml", ["fixtures"])


def test_path_excluded_empty_patterns_or_path():
    assert not path_excluded("a/b", [])
    assert not path_excluded("", ["fixtures"])


def test_exclude_findings_drops_location_and_sca_sources():
    fs = [_loc("fixtures/a.java"), _loc("src/main/B.java"),
          _sca("fixtures/vuln/pom.xml"), _sca("pom.xml")]
    out = exclude_findings(fs, ["fixtures"])
    assert len(out) == 2
    paths = [(f.location.file if f.location else f.source) for f in out]
    assert all("fixtures" not in p for p in paths)


def test_exclude_findings_empty_patterns_keeps_all():
    fs = [_loc("a"), _sca("b")]
    assert exclude_findings(fs, []) == fs


def test_default_excludes_cover_build_and_vcs():
    assert {"build", "target", ".git", ".gradle", "node_modules"} <= DEFAULT_EXCLUDES


def test_default_excludes_kill_build_artifacts():
    fs = [_loc("build/reports/tests/x/index.html"),
          _loc("src/main/java/A.java"),
          _sca("build/tmp/.cache/jacoco/pom.xml")]
    out = exclude_findings(fs, DEFAULT_EXCLUDES)
    assert len(out) == 1
    assert out[0].location.file == "src/main/java/A.java"


# --- .gitignore 존중 (git check-ignore 주입) ---

def test_filter_gitignored_drops_ignored_paths():
    fs = [_loc("/repo/.discord-token"), _loc("/repo/src/A.java")]

    def fake_checker(target, abs_paths):
        return {"/repo/.discord-token"}  # 이것만 gitignore됨

    kept, dropped = filter_gitignored("/repo", fs, checker=fake_checker)
    assert dropped == 1
    assert [f.location.file for f in kept] == ["/repo/src/A.java"]


def test_filter_gitignored_no_repo_keeps_all():
    fs = [_loc("/repo/a"), _loc("/repo/b")]
    kept, dropped = filter_gitignored("/repo", fs, checker=lambda t, p: set())
    assert dropped == 0
    assert len(kept) == 2
