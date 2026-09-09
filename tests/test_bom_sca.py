"""M-recall: cdxgen BOM 기반 SCA — gradle/maven 전이 의존 해석으로 recall 복구.

핵심: 락파일 없는 gradle 도 cdxgen 이 전체 의존 그래프를 BOM 으로 해석 → trivy sbom
이 전이 CVE 를 검출. (message-gate 스파이크: fs-trivy 0 → BOM 34건)
"""

import json
import os
import re
from pathlib import Path

import pytest

from secscan import sbom as sbom_mod
from secscan.adapters.base import OK, SKIPPED
from secscan.adapters.bom_sca import BomScaAdapter
from secscan.sbom import (
    bom_cache_path, dynamic_versions, ensure_bom, generate_sbom, is_dynamic_version,
)


class FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_bom_cache_path_is_deterministic_and_distinct():
    assert bom_cache_path("/a/b") == bom_cache_path("/a/b")
    assert bom_cache_path("/a/b") != bom_cache_path("/a/c")


def test_generate_sbom_none_when_cdxgen_fails(tmp_path):
    out = tmp_path / "bom.json"
    assert generate_sbom("/x", out, run=lambda argv, timeout: FakeProc(1)) is None


def test_generate_sbom_none_when_no_file_written(tmp_path):
    out = tmp_path / "bom.json"
    # cdxgen "성공"했다지만 파일이 없으면 None
    assert generate_sbom("/x", out, run=lambda argv, timeout: FakeProc(0)) is None


def test_generate_sbom_returns_path_when_written(tmp_path):
    out = tmp_path / "bom.json"

    def fake(argv, timeout):
        # cdxgen 이 -o 경로에 BOM 을 쓰는 것을 시뮬레이션
        o = argv[argv.index("-o") + 1]
        open(o, "w").write('{"components":[]}')
        return FakeProc(0)

    assert generate_sbom("/x", out, run=fake) == out


def test_bom_sca_argv_uses_trivy_sbom():
    argv = BomScaAdapter().build_argv("/tmp/bom.json")
    assert argv[:2] == ["trivy", "sbom"]
    assert "/tmp/bom.json" in argv
    assert argv[argv.index("--format") + 1] == "json"


def test_bom_sca_skips_when_bom_unavailable():
    a = BomScaAdapter()
    r = a.run("/p", ensure_bom=lambda target, timeout, refresh=False: None,
              run=lambda argv, timeout: FakeProc(0))
    assert r.status == SKIPPED
    assert r.tool == "trivy"


def test_bom_sca_runs_trivy_on_bom_and_reuses_trivy_schema():
    a = BomScaAdapter()
    r = a.run("/p",
              ensure_bom=lambda target, timeout, refresh=False: "/tmp/bom.json",
              run=lambda argv, timeout: FakeProc(0, stdout='{"Results":[]}'))
    assert r.status == OK
    assert r.tool == "trivy"  # parse_trivy 가 정규화
    assert r.payload == '{"Results":[]}'


def test_bom_sca_isolates_cdxgen_exception():
    def boom(target, timeout, refresh=False):
        raise RuntimeError("cdxgen exploded")

    r = BomScaAdapter().run("/p", ensure_bom=boom, run=lambda argv, timeout: FakeProc(0))
    assert r.status == SKIPPED  # 크래시 없이 격리


# --- BOM 캐시 무효화 (2026-09-09 실측 결함 회귀) ---
# 캐시 키가 대상 경로뿐이라, 의존성을 올려도 옛 BOM 이 영원히 재사용됐다.
# 반대 방향(새로 추가된 취약 의존성을 "깨끗함"으로 보고)이 더 위험 — 원칙 1(정확도 우선) 위반.

_DEP = "dependencies {{ implementation 'org.apache.tomcat.embed:tomcat-embed-core:{v}' }}\n"


def _isolate_cache(monkeypatch, tmp_path):
    """bom_cache_path 가 쓰는 tmpdir 를 테스트 전용으로 격리."""
    root = tmp_path / "cache-root"
    root.mkdir()
    monkeypatch.setattr(sbom_mod.tempfile, "gettempdir", lambda: str(root))
    return root


def _proj(tmp_path, name="proj", version="10.1.55"):
    p = tmp_path / name
    p.mkdir()
    (p / "build.gradle").write_text(_DEP.format(v=version))
    return p


def _fake_cdxgen(calls):
    """cdxgen 시뮬레이션 — 스캔 시점의 매니페스트를 실제로 읽어 BOM 을 만든다."""
    def run(argv, timeout):
        out = argv[argv.index("-o") + 1]
        src = Path(argv[-1]) / "build.gradle"
        v = re.search(r"tomcat-embed-core:([\d.]+)", src.read_text()).group(1)
        Path(out).write_text(json.dumps({"components": [{"name": "tomcat-embed-core", "version": v}]}))
        calls.append(v)
        return FakeProc(0)
    return run


def test_bom_cache_path_changes_when_manifest_content_changes(tmp_path, monkeypatch):
    _isolate_cache(monkeypatch, tmp_path)
    proj = _proj(tmp_path)
    before = bom_cache_path(proj)
    (proj / "build.gradle").write_text(_DEP.format(v="10.1.59"))
    assert bom_cache_path(proj) != before


def test_bom_cache_path_stable_when_manifest_unchanged(tmp_path, monkeypatch):
    """재생성 비용이 크므로 내용이 같으면 캐시가 계속 유효해야 한다.
    mtime 은 git checkout/clone 이 바꾸므로 키에 들어가면 안 된다."""
    _isolate_cache(monkeypatch, tmp_path)
    proj = _proj(tmp_path)
    before = bom_cache_path(proj)
    (proj / "build.gradle").write_text(_DEP.format(v="10.1.55"))  # 같은 내용 재기록
    os.utime(proj / "build.gradle", (0, 0))                        # mtime 만 변경
    assert bom_cache_path(proj) == before


def test_bom_cache_path_distinct_for_identical_manifests_in_different_targets(tmp_path, monkeypatch):
    _isolate_cache(monkeypatch, tmp_path)
    a = _proj(tmp_path, "a")
    b = _proj(tmp_path, "b")
    assert bom_cache_path(a) != bom_cache_path(b)


@pytest.mark.parametrize("rel", [
    "pom.xml", "build.gradle.kts", "settings.gradle", "settings.gradle.kts",
    "gradle.properties", "gradle/libs.versions.toml", "gradle.lockfile",
    "sub/module/pom.xml", "sub/module/build.gradle",
])
def test_bom_cache_path_changes_for_every_supported_manifest(tmp_path, monkeypatch, rel):
    _isolate_cache(monkeypatch, tmp_path)
    proj = _proj(tmp_path)
    before = bom_cache_path(proj)
    f = proj / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("junit:junit:4.13.1\n")
    assert bom_cache_path(proj) != before


def test_bom_cache_path_ignores_excluded_dirs(tmp_path, monkeypatch):
    """exclude.py 의 기본 제외를 존중 — node_modules/build/.git 안의 매니페스트가
    캐시 키를 오염시키면 안 된다(빌드마다 키가 흔들려 캐시가 무의미해진다)."""
    _isolate_cache(monkeypatch, tmp_path)
    proj = _proj(tmp_path)
    before = bom_cache_path(proj)
    for d in ("node_modules/x", "build/tmp", ".git/modules/m", "target/classes", ".gradle/caches"):
        p = proj / d
        p.mkdir(parents=True, exist_ok=True)
        (p / "pom.xml").write_text("<project><version>9.9.9</version></project>")
    assert bom_cache_path(proj) == before


def test_ensure_bom_reuses_cache_when_manifests_unchanged(tmp_path, monkeypatch):
    _isolate_cache(monkeypatch, tmp_path)
    proj = _proj(tmp_path)
    calls = []
    run = _fake_cdxgen(calls)
    assert ensure_bom(proj, run=run) is not None
    assert ensure_bom(proj, run=run) is not None
    assert calls == ["10.1.55"]  # cdxgen 은 한 번만


def test_ensure_bom_regenerates_after_dependency_version_bump(tmp_path, monkeypatch):
    """실측 회귀(2026-09-09 work-note): tomcat-embed-core 10.1.55→10.1.59 로 올리고
    재스캔했는데 3일 전 BOM 이 재사용돼 옛 버전 CVE 4건이 그대로 보고됐다."""
    _isolate_cache(monkeypatch, tmp_path)
    proj = _proj(tmp_path, version="10.1.55")
    calls = []
    run = _fake_cdxgen(calls)

    before = ensure_bom(proj, run=run)
    assert json.loads(before.read_text())["components"][0]["version"] == "10.1.55"

    (proj / "build.gradle").write_text(_DEP.format(v="10.1.59"))  # 조치: 버전 상향
    after = ensure_bom(proj, run=run)

    assert calls == ["10.1.55", "10.1.59"]  # 재스캔 시 cdxgen 재실행
    assert json.loads(after.read_text())["components"][0]["version"] == "10.1.59"


# --- 동적 버전·SNAPSHOT 탐지 + 캐시 우회 (b420b8b 잔여 한계) ---
# 매니페스트가 그대로인데 해석 결과가 달라지는 경로: 동적 버전(2.+/latest.release/범위),
# SNAPSHOT, 원격 parent pom. 내용 해시로는 못 잡으므로 캐시를 우회해야 한다.


@pytest.mark.parametrize("v", [
    "2.+", "1.2.+", "+",                       # gradle 동적 버전
    "latest.release", "latest.integration",    # gradle 최신 지시자
    "LATEST", "RELEASE",                       # maven 레거시 키워드
    "[1.0,2.0)", "(,1.0]", "]1.0,2.0[",        # 버전 범위(maven/gradle)
    "1.0-SNAPSHOT", "2.0.0-snapshot",          # SNAPSHOT
])
def test_is_dynamic_version_true(v):
    assert is_dynamic_version(v)


@pytest.mark.parametrize("v", [
    "1.2.3", "3.3.4", "1.9",
    "4.3.30.RELEASE",   # 스프링 구 표기 = 고정 버전. maven 키워드 RELEASE 와 구분해야 한다
    "2.0.0.LATEST",     # 마찬가지로 고정 버전
    "1.0.0+build.5",    # semver 빌드 메타데이터 — 끝이 '+' 가 아니다
    "[1.0]",            # 정확히 한 버전으로 고정하는 범위
    "", "${commonsVersion}",
])
def test_is_dynamic_version_false(v):
    assert not is_dynamic_version(v)


def _pom(body: str) -> str:
    return f'<project xmlns="http://maven.apache.org/POM/4.0.0">{body}</project>'


def test_dynamic_versions_detects_maven_dependency_range(tmp_path):
    p = tmp_path / "m"
    p.mkdir()
    (p / "pom.xml").write_text(_pom("""
      <groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version>
      <dependencies>
        <dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId>
          <version>[1.9,2.0)</version></dependency>
        <dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId>
          <version>33.0.0-jre</version></dependency>
      </dependencies>"""))
    found = dynamic_versions(p)
    assert [(d.coordinate, d.version) for d in found] == [("org.apache.commons:commons-text", "[1.9,2.0)")]


def test_dynamic_versions_ignores_maven_project_own_snapshot_version(tmp_path):
    """FP 방어: 개발 중 maven 프로젝트는 거의 모두 자기 버전이 SNAPSHOT 이다.
    이걸 잡으면 사실상 모든 프로젝트가 캐시를 못 쓴다 — 의존성 버전만 본다."""
    p = tmp_path / "m"
    p.mkdir()
    (p / "pom.xml").write_text(_pom("""
      <groupId>com.example</groupId><artifactId>app</artifactId><version>0.0.1-SNAPSHOT</version>
      <dependencies>
        <dependency><groupId>g</groupId><artifactId>a</artifactId><version>1.0.0</version></dependency>
      </dependencies>"""))
    assert dynamic_versions(p) == []


def test_dynamic_versions_detects_remote_parent_snapshot(tmp_path):
    """원격 parent pom 이 SNAPSHOT 이면 매니페스트가 그대로여도 그래프가 바뀐다."""
    p = tmp_path / "m"
    p.mkdir()
    (p / "pom.xml").write_text(_pom("""
      <parent><groupId>com.corp</groupId><artifactId>platform</artifactId>
        <version>2.3.0-SNAPSHOT</version></parent>
      <artifactId>app</artifactId>"""))
    assert [d.version for d in dynamic_versions(p)] == ["2.3.0-SNAPSHOT"]


def test_dynamic_versions_resolves_maven_property_reference(tmp_path):
    p = tmp_path / "m"
    p.mkdir()
    (p / "pom.xml").write_text(_pom("""
      <artifactId>app</artifactId><version>1.0.0</version>
      <properties><commons.version>1.+</commons.version></properties>
      <dependencies>
        <dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId>
          <version>${commons.version}</version></dependency>
      </dependencies>"""))
    assert [d.version for d in dynamic_versions(p)] == ["1.+"]


def test_dynamic_versions_detects_maven_dependency_management(tmp_path):
    p = tmp_path / "m"
    p.mkdir()
    (p / "pom.xml").write_text(_pom("""
      <artifactId>app</artifactId><version>1.0.0</version>
      <dependencyManagement><dependencies>
        <dependency><groupId>g</groupId><artifactId>bom</artifactId>
          <version>1.0-SNAPSHOT</version><type>pom</type><scope>import</scope></dependency>
      </dependencies></dependencyManagement>"""))
    assert [d.version for d in dynamic_versions(p)] == ["1.0-SNAPSHOT"]


@pytest.mark.parametrize("line,expected", [
    ("    implementation 'org.apache.commons:commons-text:2.+'", "2.+"),
    ('    implementation "com.corp:lib:1.0-SNAPSHOT"', "1.0-SNAPSHOT"),
    ("    api 'g:a:latest.release'", "latest.release"),
    ("    implementation 'org.apache.commons:commons-text:1.9'", None),
])
def test_dynamic_versions_gradle_coordinate_strings(tmp_path, line, expected):
    p = tmp_path / "g"
    p.mkdir()
    (p / "build.gradle").write_text(f"dependencies {{\n{line}\n}}\n")
    got = [d.version for d in dynamic_versions(p)]
    assert got == ([expected] if expected else [])


def test_dynamic_versions_gradle_kts_and_version_catalog(tmp_path):
    p = tmp_path / "g"
    (p / "gradle").mkdir(parents=True)
    (p / "build.gradle.kts").write_text('dependencies { implementation("com.corp:lib:2.1-SNAPSHOT") }\n')
    (p / "gradle" / "libs.versions.toml").write_text('[versions]\ncommons = "1.+"\nguava = "33.0.0-jre"\n')
    assert sorted(d.version for d in dynamic_versions(p)) == ["1.+", "2.1-SNAPSHOT"]


def test_dynamic_versions_gradle_properties_ignores_project_version(tmp_path):
    """gradle.properties 의 `version=` 은 프로젝트 자기 버전(관례) — 의존성이 아니다."""
    p = tmp_path / "g"
    p.mkdir()
    (p / "gradle.properties").write_text("version=0.0.1-SNAPSHOT\ncorpLibVersion=3.2-SNAPSHOT\n")
    assert [(d.coordinate, d.version) for d in dynamic_versions(p)] == [("corpLibVersion", "3.2-SNAPSHOT")]


def test_dynamic_versions_respects_excludes(tmp_path):
    p = tmp_path / "g"
    p.mkdir()
    (p / "build.gradle").write_text("dependencies { implementation 'g:a:1.0' }\n")
    nested = p / "node_modules" / "pkg"
    nested.mkdir(parents=True)
    (nested / "pom.xml").write_text(_pom("<dependencies><dependency><groupId>x</groupId>"
                                         "<artifactId>y</artifactId><version>1.+</version></dependency></dependencies>"))
    assert dynamic_versions(p) == []


def test_dynamic_versions_isolates_unparsable_manifest(tmp_path):
    """부분 실패는 정상(원칙 5) — 깨진 pom 하나가 탐지 전체를 죽이면 안 된다."""
    p = tmp_path / "g"
    p.mkdir()
    (p / "pom.xml").write_text("<project><this is not xml")
    (p / "build.gradle").write_text("dependencies { implementation 'g:a:2.+' }\n")
    assert [d.version for d in dynamic_versions(p)] == ["2.+"]


def test_ensure_bom_refresh_regenerates_even_when_cache_hits(tmp_path, monkeypatch):
    _isolate_cache(monkeypatch, tmp_path)
    proj = _proj(tmp_path)
    calls = []
    run = _fake_cdxgen(calls)
    ensure_bom(proj, run=run)
    ensure_bom(proj, run=run, refresh=True)
    assert calls == ["10.1.55", "10.1.55"]  # 캐시가 있어도 다시 만든다


def test_ensure_bom_refresh_writes_result_into_cache(tmp_path, monkeypatch):
    """우회해도 결과는 캐시에 남아 다음 스캔이 이득을 본다."""
    _isolate_cache(monkeypatch, tmp_path)
    proj = _proj(tmp_path)
    calls = []
    run = _fake_cdxgen(calls)
    refreshed = ensure_bom(proj, run=run, refresh=True)
    assert refreshed == bom_cache_path(proj) and refreshed.exists()
    assert ensure_bom(proj, run=run) == refreshed
    assert calls == ["10.1.55"]  # 두 번째는 캐시 적중


def test_bom_sca_adapter_passes_refresh_to_ensure_bom():
    seen = {}

    def fake_ensure(target, *, timeout, refresh=False):
        seen["refresh"] = refresh
        return "/tmp/bom.json"

    BomScaAdapter(refresh=True).run("/p", ensure_bom=fake_ensure,
                                    run=lambda argv, timeout: FakeProc(0, stdout='{"Results":[]}'))
    assert seen["refresh"] is True


def test_bom_sca_adapter_defaults_to_cached_bom():
    seen = {}

    def fake_ensure(target, *, timeout, refresh=False):
        seen["refresh"] = refresh
        return "/tmp/bom.json"

    BomScaAdapter().run("/p", ensure_bom=fake_ensure,
                        run=lambda argv, timeout: FakeProc(0, stdout='{"Results":[]}'))
    assert seen["refresh"] is False


def test_dynamic_versions_ignores_local_parent_pom(tmp_path):
    """FP 방어: 멀티모듈 maven 은 자식 pom 의 <parent> 가 로컬 집합체(SNAPSHOT)를 가리킨다.
    로컬 parent 는 이미 지문에 포함되므로 동적 소스가 아니다 — 원격 parent 만 잡는다."""
    root = tmp_path / "m"
    (root / "mod").mkdir(parents=True)
    (root / "pom.xml").write_text(_pom("""
      <groupId>com.example</groupId><artifactId>agg</artifactId><version>1.0-SNAPSHOT</version>
      <modules><module>mod</module></modules>"""))
    (root / "mod" / "pom.xml").write_text(_pom("""
      <parent><groupId>com.example</groupId><artifactId>agg</artifactId>
        <version>1.0-SNAPSHOT</version></parent>
      <artifactId>mod</artifactId>"""))
    assert dynamic_versions(root) == []


def test_ensure_bom_refresh_does_not_pass_off_stale_bom_when_cdxgen_fails(tmp_path, monkeypatch):
    """우회 재생성이 실패하면 옛 BOM 을 성공으로 오인하면 안 된다 — 부분 실패로 보고(원칙 1·5).
    단 기존 캐시 파일을 지우지는 않는다(비파괴)."""
    _isolate_cache(monkeypatch, tmp_path)
    proj = _proj(tmp_path)
    cached = ensure_bom(proj, run=_fake_cdxgen([]))
    assert cached.exists()

    assert ensure_bom(proj, run=lambda argv, timeout: FakeProc(1), refresh=True) is None
    assert cached.exists()  # 기존 캐시는 그대로 둔다
