"""경로 기반 finding 제외 — 이질적 스캐너 공통 사후 필터(--exclude)."""

from secscan.exclude import exclude_findings, path_excluded
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
