"""M-recall: cdxgen BOM 기반 SCA — gradle/maven 전이 의존 해석으로 recall 복구.

핵심: 락파일 없는 gradle 도 cdxgen 이 전체 의존 그래프를 BOM 으로 해석 → trivy sbom
이 전이 CVE 를 검출. (message-gate 스파이크: fs-trivy 0 → BOM 34건)
"""

import json
import os
import re
import time
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
    r = a.run("/p", ensure_bom=lambda target, timeout, **_: None,
              run=lambda argv, timeout: FakeProc(0))
    assert r.status == SKIPPED
    assert r.tool == "trivy"


def test_bom_sca_runs_trivy_on_bom_and_reuses_trivy_schema():
    a = BomScaAdapter()
    r = a.run("/p",
              ensure_bom=lambda target, timeout, **_: "/tmp/bom.json",
              run=lambda argv, timeout: FakeProc(0, stdout='{"Results":[]}'))
    assert r.status == OK
    assert r.tool == "trivy"  # parse_trivy 가 정규화
    assert r.payload == '{"Results":[]}'


def test_bom_sca_isolates_cdxgen_exception():
    def boom(target, timeout, **_):
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
    """부분 실패는 정상(원칙 5) — 깨진 pom 하나가 탐지 전체를 죽이면 안 된다.
    (깨진 파일 자체는 "모른다"로 보고된다 — test_dynamic_versions_flags_unparsable_manifest)"""
    p = tmp_path / "g"
    p.mkdir()
    (p / "pom.xml").write_text("<project><this is not xml")
    (p / "build.gradle").write_text("dependencies { implementation 'g:a:2.+' }\n")
    assert "2.+" in [d.version for d in dynamic_versions(p)]


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

    def fake_ensure(target, *, timeout, refresh=False, **_):
        seen["refresh"] = refresh
        return "/tmp/bom.json"

    BomScaAdapter(refresh=True).run("/p", ensure_bom=fake_ensure,
                                    run=lambda argv, timeout: FakeProc(0, stdout='{"Results":[]}'))
    assert seen["refresh"] is True


def test_bom_sca_adapter_defaults_to_cached_bom():
    seen = {}

    def fake_ensure(target, *, timeout, refresh=False, **_):
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


# --- codex 리뷰 P1 3건: 해석 못 한 버전 표현을 "고정"으로 본 fail-open 수정 ---
# 뿌리가 하나다 — 로컬에서 해석 가능한 것은 해석해 고정 판정하고, 끝내 해석 못 한 것만
# 동적으로 간주한다(fail-closed). 순서가 뒤바뀌면 캐시가 사라진다(FP).

def _module_repo(tmp_path, parent_dep_version="1.9", parent_props="", child_body=""):
    """집합체 pom + 모듈 pom. 모듈만 target 으로 스캔하면 부모는 트리 밖이다."""
    repo = tmp_path / "repo"
    (repo / "mod").mkdir(parents=True)
    (repo / "pom.xml").write_text(_pom(f"""
      <groupId>com.example</groupId><artifactId>agg</artifactId><version>1.0-SNAPSHOT</version>
      <properties>{parent_props}</properties>
      <modules><module>mod</module></modules>
      <dependencyManagement><dependencies>
        <dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId>
          <version>{parent_dep_version}</version></dependency>
      </dependencies></dependencyManagement>"""))
    (repo / "mod" / "pom.xml").write_text(_pom(f"""
      <parent><groupId>com.example</groupId><artifactId>agg</artifactId>
        <version>1.0-SNAPSHOT</version></parent>
      <artifactId>mod</artifactId>{child_body}"""))
    return repo


def test_bom_cache_path_changes_when_out_of_tree_parent_pom_changes(tmp_path, monkeypatch):
    """[P1-1] 모듈만 스캔해도 빌드는 ../pom.xml 을 실제로 읽는다.
    그 부모가 바뀌면(관리 버전 상향) 캐시가 무효화돼야 한다."""
    _isolate_cache(monkeypatch, tmp_path)
    repo = _module_repo(tmp_path, parent_dep_version="1.9")
    before = bom_cache_path(repo / "mod")
    (repo / "pom.xml").write_text((repo / "pom.xml").read_text().replace("1.9", "1.10"))
    assert bom_cache_path(repo / "mod") != before


def test_dynamic_versions_ignores_out_of_tree_local_parent(tmp_path):
    """[P1-1 FP 방어] 지문에 들어간 로컬 parent 는 SNAPSHOT 이어도 동적 소스가 아니다."""
    repo = _module_repo(tmp_path)
    assert dynamic_versions(repo / "mod") == []


def test_dynamic_versions_flags_property_defined_only_by_remote_parent(tmp_path):
    """[P1-2] 원격 부모가 정의한 프로퍼티는 로컬에서 못 푼다 → 보수적으로 동적."""
    p = tmp_path / "m"
    p.mkdir()
    (p / "pom.xml").write_text(_pom("""
      <parent><groupId>com.corp</groupId><artifactId>platform</artifactId>
        <version>2.0.0</version><relativePath/></parent>
      <artifactId>app</artifactId>
      <dependencies>
        <dependency><groupId>com.corp</groupId><artifactId>lib</artifactId>
          <version>${lib.version}</version></dependency>
      </dependencies>"""))
    assert [d.version for d in dynamic_versions(p)] == ["${lib.version}"]


def test_dynamic_versions_resolves_property_through_local_parent_chain(tmp_path):
    """[P1-2] 로컬 부모의 프로퍼티는 해석된다 — 값이 동적이면 잡고(여기), 고정이면 놔둔다."""
    repo = _module_repo(
        tmp_path, parent_props="<lib.version>1.+</lib.version>",
        child_body="""<dependencies><dependency><groupId>com.corp</groupId>
          <artifactId>lib</artifactId><version>${lib.version}</version></dependency></dependencies>""")
    assert [d.version for d in dynamic_versions(repo)] == ["1.+"]


def test_dynamic_versions_ignores_fixed_property_from_local_parent(tmp_path):
    """[P1-2 FP 방어] 멀티모듈의 표준 패턴 — 부모가 버전을 모아두고 자식이 참조."""
    repo = _module_repo(
        tmp_path, parent_props="<lib.version>1.2.3</lib.version>",
        child_body="""<dependencies><dependency><groupId>com.corp</groupId>
          <artifactId>lib</artifactId><version>${lib.version}</version></dependency></dependencies>""")
    assert dynamic_versions(repo) == []


@pytest.mark.parametrize("expr", ["${project.version}", "${pom.version}", "${revision}"])
def test_dynamic_versions_ignores_self_referential_version_property(tmp_path, expr):
    """[P1-2 FP 방어] 리액터 내부 모듈 참조 — 자기 버전이라 원격 변동 요인이 아니다."""
    p = tmp_path / "m"
    p.mkdir()
    (p / "pom.xml").write_text(_pom(f"""
      <groupId>com.example</groupId><artifactId>app</artifactId><version>0.0.1-SNAPSHOT</version>
      <dependencies><dependency><groupId>com.example</groupId><artifactId>other</artifactId>
        <version>{expr}</version></dependency></dependencies>"""))
    assert dynamic_versions(p) == []


def test_dynamic_versions_ignores_managed_dependency_without_version(tmp_path):
    """[FP 방어] 스프링부트의 기본형 — 버전 미기재(BOM 관리)는 판단 대상이 아니다."""
    p = tmp_path / "m"
    p.mkdir()
    (p / "pom.xml").write_text(_pom("""
      <artifactId>app</artifactId><version>1.0.0</version>
      <dependencies><dependency><groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId></dependency></dependencies>"""))
    assert dynamic_versions(p) == []


def test_dynamic_versions_flags_unresolvable_gradle_interpolation(tmp_path):
    """[P1-3] 어디에도 정의가 없는 보간 변수 → 보수적으로 동적."""
    p = tmp_path / "g"
    p.mkdir()
    (p / "build.gradle").write_text('dependencies { implementation "g:a:$mysteryVersion" }\n')
    assert [d.version for d in dynamic_versions(p)] == ["$mysteryVersion"]


def test_dynamic_versions_flags_gradle_variable_bound_to_dynamic_value(tmp_path):
    """[P1-3] def v = "2.+" 를 풀어서 동적으로 판정한다."""
    p = tmp_path / "g"
    p.mkdir()
    (p / "build.gradle").write_text('def v = "2.+"\ndependencies { implementation "g:a:$v" }\n')
    assert [d.version for d in dynamic_versions(p)] == ["2.+"]  # 풀렸으면 해석값으로 보고


@pytest.mark.parametrize("script", [
    'def v = "1.2.3"\ndependencies { implementation "g:a:$v" }\n',
    'val v = "1.2.3"\ndependencies { implementation("g:a:${v}") }\n',
    'ext { commonsVersion = \'1.2.3\' }\ndependencies { implementation "g:a:$commonsVersion" }\n',
])
def test_dynamic_versions_resolves_local_gradle_variable(tmp_path, script):
    """[P1-3 FP 방어] 로컬에서 풀리는 보간은 고정으로 판정한다."""
    p = tmp_path / "g"
    p.mkdir()
    (p / "build.gradle").write_text(script)
    assert dynamic_versions(p) == []


def test_dynamic_versions_resolves_variable_from_gradle_properties(tmp_path):
    """[P1-3 FP 방어] gradle.properties 의 값은 빌드 스크립트에서 프로퍼티로 보인다."""
    p = tmp_path / "g"
    p.mkdir()
    (p / "gradle.properties").write_text("commonsVersion=1.9\n")
    (p / "build.gradle").write_text('dependencies { implementation "g:a:$commonsVersion" }\n')
    assert dynamic_versions(p) == []


def test_dynamic_versions_resolves_variable_defined_in_root_script(tmp_path):
    """[P1-3 FP 방어] 멀티모듈 gradle — 루트에서 정의하고 모듈에서 쓴다."""
    p = tmp_path / "g"
    (p / "mod").mkdir(parents=True)
    (p / "build.gradle").write_text("ext { corpVersion = '1.0.0' }\n")
    (p / "mod" / "build.gradle").write_text('dependencies { implementation "c:lib:$corpVersion" }\n')
    assert dynamic_versions(p) == []


def test_dynamic_versions_treats_version_catalog_reference_as_resolved(tmp_path):
    """[P1-3 FP 방어] libs.* 는 카탈로그 참조 — 카탈로그 파일 자체가 지문에 있고,
    동적 항목이면 카탈로그 스캔이 따로 잡는다."""
    p = tmp_path / "g"
    (p / "gradle").mkdir(parents=True)
    (p / "gradle" / "libs.versions.toml").write_text('[versions]\ncommonsText = "1.9"\n')
    (p / "build.gradle.kts").write_text(
        'dependencies { implementation("g:a:${libs.versions.commonsText.get()}") }\n')
    assert dynamic_versions(p) == []


def _gradle_multimodule(tmp_path, root_ext="1.12.0"):
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "settings.gradle").write_text("rootProject.name='mm'\ninclude 'app'\n")
    (repo / "build.gradle").write_text(f"ext {{ commonsVersion = '{root_ext}' }}\n")
    (repo / "gradle.properties").write_text("guavaVersion=33.0.0-jre\n")
    (repo / "app" / "build.gradle").write_text(
        'dependencies {\n'
        '  implementation "org.apache.commons:commons-text:$commonsVersion"\n'
        '  implementation "com.google.guava:guava:${rootProject.ext.guavaVersion}"\n'
        '}\n')
    return repo


def test_dynamic_versions_resolves_variables_from_gradle_build_root(tmp_path):
    """[P1-3 FP 방어] 서브프로젝트만 스캔해도 빌드 루트(settings.gradle)의 ext·
    gradle.properties 는 gradle 이 실제로 읽는다 — 해석 가능하므로 고정이다."""
    repo = _gradle_multimodule(tmp_path)
    assert dynamic_versions(repo / "app") == []


def test_bom_cache_path_changes_when_gradle_build_root_changes(tmp_path, monkeypatch):
    """서브프로젝트를 스캔해도 빌드 루트가 바뀌면 캐시가 무효화돼야 한다(P1-1 의 gradle 대응)."""
    _isolate_cache(monkeypatch, tmp_path)
    repo = _gradle_multimodule(tmp_path, root_ext="1.12.0")
    before = bom_cache_path(repo / "app")
    (repo / "build.gradle").write_text("ext { commonsVersion = '1.13.0' }\n")
    assert bom_cache_path(repo / "app") != before


def test_dynamic_versions_flags_dynamic_value_from_gradle_build_root(tmp_path):
    """루트가 동적 값을 주면 서브프로젝트 스캔에서도 잡힌다."""
    repo = _gradle_multimodule(tmp_path, root_ext="1.+")
    assert [d.version for d in dynamic_versions(repo / "app")] == ["1.+"]


# --- codex 라운드2 P1 4건 ---

def test_dynamic_versions_flags_interpolation_containing_quotes(tmp_path):
    """[P1-A] `${property('x')}` — 보간 안의 따옴표에서 좌표 정규식이 잘렸다."""
    p = tmp_path / "g"
    p.mkdir()
    (p / "build.gradle").write_text(
        'dependencies { implementation "g:a:${property(\'libVersion\')}" }\n')
    assert [d.version for d in dynamic_versions(p)] == ["${property('libVersion')}"]


def test_dynamic_versions_flags_parent_when_local_pom_coordinates_differ(tmp_path):
    """[P1-B] ../pom.xml 이 있어도 좌표가 다르면 maven 은 그 파일을 무시하고 원격에서 받는다."""
    repo = tmp_path / "repo"
    (repo / "mod").mkdir(parents=True)
    (repo / "pom.xml").write_text(_pom("""
      <groupId>com.other</groupId><artifactId>unrelated</artifactId><version>9.9.9</version>"""))
    (repo / "mod" / "pom.xml").write_text(_pom("""
      <parent><groupId>com.corp</groupId><artifactId>platform</artifactId>
        <version>2.3.0-SNAPSHOT</version></parent>
      <artifactId>app</artifactId>"""))
    assert [d.version for d in dynamic_versions(repo / "mod")] == ["2.3.0-SNAPSHOT"]


def test_dynamic_versions_flags_ambiguous_symbol_from_maven_profiles(tmp_path):
    """[P1-C] 상호배타 profile 이 같은 프로퍼티를 다르게 정의 — 활성 profile 이 바뀌면
    매니페스트 불변인데 그래프가 바뀐다. 개별 후보가 다 고정이라도 모호하면 우회."""
    p = tmp_path / "m"
    p.mkdir()
    (p / "pom.xml").write_text(_pom("""
      <artifactId>app</artifactId><version>1.0.0</version>
      <profiles>
        <profile><id>a</id><properties><lib.version>1.0.0</lib.version></properties></profile>
        <profile><id>b</id><properties><lib.version>2.0.0</lib.version></properties></profile>
      </profiles>
      <dependencies><dependency><groupId>com.corp</groupId><artifactId>lib</artifactId>
        <version>${lib.version}</version></dependency></dependencies>"""))
    assert [d.version for d in dynamic_versions(p)] == ["${lib.version}"]


def test_dynamic_versions_flags_ambiguous_gradle_symbol(tmp_path):
    """[P1-C] 형제 모듈이 같은 이름을 다르게 정의하고, 정의가 없는 모듈이 그걸 쓴다 →
    어느 값인지 정적으로 확정 불가 → 우회."""
    p = tmp_path / "g"
    for m in ("a", "b", "c"):
        (p / m).mkdir(parents=True)
    (p / "settings.gradle").write_text("include 'a','b','c'\n")
    (p / "a" / "build.gradle").write_text("ext { libVersion = '1.0.0' }\n")
    (p / "b" / "build.gradle").write_text("ext { libVersion = '2.0.0' }\n")
    (p / "c" / "build.gradle").write_text('dependencies { implementation "c:lib:$libVersion" }\n')
    got = dynamic_versions(p)
    assert [(d.version, d.kind) for d in got] == [("$libVersion", "ambiguous")]


def test_dynamic_versions_prefers_own_script_definition(tmp_path):
    """[P1-C FP 방어] 모듈이 자기 ext 를 정의하면 gradle 은 그 값을 쓴다 — 모호가 아니다."""
    p = tmp_path / "g"
    (p / "mod").mkdir(parents=True)
    (p / "settings.gradle").write_text("include 'mod'\n")
    (p / "build.gradle").write_text("ext { libVersion = '1.0.0' }\n")
    (p / "mod" / "build.gradle").write_text(
        "ext { libVersion = '2.0.0' }\ndependencies { implementation \"c:lib:$libVersion\" }\n")
    assert dynamic_versions(p) == []


def test_bom_cache_path_changes_when_nested_shared_build_script_changes(tmp_path, monkeypatch):
    """[P1-D] 빌드 루트가 apply from 으로 읽는 중첩 스크립트도 지문에 들어가야 한다."""
    _isolate_cache(monkeypatch, tmp_path)
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "gradle" / "scripts").mkdir(parents=True)
    (repo / "settings.gradle").write_text("include 'app'\n")
    (repo / "build.gradle").write_text("apply from: 'gradle/scripts/dependencies.gradle'\n")
    (repo / "gradle" / "scripts" / "dependencies.gradle").write_text("ext { libVersion = '1.0.0' }\n")
    (repo / "app" / "build.gradle").write_text('dependencies { implementation "c:lib:$libVersion" }\n')
    before = bom_cache_path(repo / "app")
    (repo / "gradle" / "scripts" / "dependencies.gradle").write_text("ext { libVersion = '2.0.0' }\n")
    assert bom_cache_path(repo / "app") != before


def test_dynamic_versions_resolves_symbol_from_nested_shared_script(tmp_path):
    """[P1-D FP 방어] 그 중첩 스크립트의 심볼은 해석돼야 한다(우회 남발 금지)."""
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "gradle" / "scripts").mkdir(parents=True)
    (repo / "settings.gradle").write_text("include 'app'\n")
    (repo / "build.gradle").write_text("apply from: 'gradle/scripts/dependencies.gradle'\n")
    (repo / "gradle" / "scripts" / "dependencies.gradle").write_text("ext { libVersion = '1.0.0' }\n")
    (repo / "app" / "build.gradle").write_text('dependencies { implementation "c:lib:$libVersion" }\n')
    assert dynamic_versions(repo / "app") == []


def test_dynamic_versions_flags_unfollowable_applied_script(tmp_path):
    """[구조적] 따라갈 수 없는 applied script(원격 URL)는 불확실 신호 → 우회."""
    p = tmp_path / "g"
    p.mkdir()
    (p / "build.gradle").write_text(
        "apply from: 'https://corp.example.com/shared/versions.gradle'\n"
        "dependencies { implementation 'c:lib:1.0.0' }\n")
    got = dynamic_versions(p)
    assert len(got) == 1 and "versions.gradle" in got[0].coordinate


def test_dynamic_versions_flags_unparsable_manifest(tmp_path):
    """[구조적] 파싱 실패는 "고정"이 아니라 "모른다" — 조용히 넘기면 스테일이 된다(원칙 5)."""
    p = tmp_path / "m"
    p.mkdir()
    (p / "pom.xml").write_text("<project><this is not xml")
    got = dynamic_versions(p)
    assert len(got) == 1 and got[0].file == "pom.xml"


def test_ensure_bom_regenerates_when_cache_is_older_than_max_age(tmp_path, monkeypatch):
    """[구조적] BOM TTL — 정적 분석이 못 보는 변화(원격 재배포·환경 경유 값)의 하한선."""
    _isolate_cache(monkeypatch, tmp_path)
    proj = _proj(tmp_path)
    calls = []
    run = _fake_cdxgen(calls)
    path = ensure_bom(proj, run=run)
    old = time.time() - 25 * 3600
    os.utime(path, (old, old))
    ensure_bom(proj, run=run, max_age_s=24 * 3600)
    assert calls == ["10.1.55", "10.1.55"]


def test_ensure_bom_keeps_fresh_cache_within_max_age(tmp_path, monkeypatch):
    _isolate_cache(monkeypatch, tmp_path)
    proj = _proj(tmp_path)
    calls = []
    run = _fake_cdxgen(calls)
    ensure_bom(proj, run=run)
    ensure_bom(proj, run=run, max_age_s=24 * 3600)
    assert calls == ["10.1.55"]


# --- codex 라운드3 ---

def _inherit_repo(tmp_path, agg_parent, child_parent):
    repo = tmp_path / "repo"
    (repo / "mod").mkdir(parents=True)
    (repo / "pom.xml").write_text(_pom(f"{agg_parent}<artifactId>agg</artifactId>"))
    (repo / "mod" / "pom.xml").write_text(_pom(f"{child_parent}<artifactId>mod</artifactId>"))
    return repo


def test_dynamic_versions_flags_parent_when_inherited_effective_gav_differs(tmp_path):
    """[R3 P1-2] 후보 pom 이 groupId/version 을 상속으로 생략해도 **실효 좌표**로 대조해야 한다.
    실효 GAV 가 다르면 maven 은 상대경로를 거부하고 원격에서 받는다."""
    repo = _inherit_repo(
        tmp_path,
        agg_parent="""<parent><groupId>com.corp</groupId><artifactId>base</artifactId>
            <version>5.0.0</version><relativePath/></parent>""",   # 실효 = com.corp:agg:5.0.0
        child_parent="""<parent><groupId>com.example</groupId><artifactId>agg</artifactId>
            <version>1.0-SNAPSHOT</version></parent>""")           # 선언 = com.example:agg:1.0-SNAPSHOT
    assert [d.version for d in dynamic_versions(repo / "mod")] == ["1.0-SNAPSHOT"]


def test_dynamic_versions_ignores_parent_when_inherited_effective_gav_matches(tmp_path):
    """[R3 P1-2 FP 방어] 상속으로 생략했어도 실효 좌표가 맞으면 로컬 parent 다.
    지난번 이 필드를 대조에서 뺐던 이유가 이 케이스 — 멀티모듈을 깨면 안 된다."""
    repo = _inherit_repo(
        tmp_path,
        agg_parent="""<parent><groupId>com.corp</groupId><artifactId>base</artifactId>
            <version>5.0.0</version><relativePath/></parent>""",
        child_parent="""<parent><groupId>com.corp</groupId><artifactId>agg</artifactId>
            <version>5.0.0</version></parent>""")
    assert dynamic_versions(repo / "mod") == []


def test_dynamic_versions_flags_parent_when_candidate_gav_unresolvable(tmp_path):
    """[R3 P1-2] 실효 좌표를 못 구하면 로컬이라 단정하지 않는다(fail-closed)."""
    repo = _inherit_repo(
        tmp_path, agg_parent="",  # groupId·version 도 parent 도 없다 → 실효 좌표 미상
        child_parent="""<parent><groupId>com.example</groupId><artifactId>agg</artifactId>
            <version>1.0-SNAPSHOT</version></parent>""")
    assert [d.version for d in dynamic_versions(repo / "mod")] == ["1.0-SNAPSHOT"]


def test_dynamic_versions_resolves_root_scoped_apply_from_in_subproject(tmp_path):
    """[R3 P2] 서브프로젝트의 `apply from: "$rootDir/..."` 는 빌드 루트 기준으로 풀어야 한다.
    지문에 이미 있는 스크립트를 external-script 로 몰면 매 스캔 재생성을 강제한다(성능 오탐)."""
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "gradle" / "scripts").mkdir(parents=True)
    (repo / "settings.gradle").write_text("include 'app'\n")
    (repo / "build.gradle").write_text("// root\n")
    (repo / "gradle" / "scripts" / "deps.gradle").write_text("ext { libVersion = '1.0.0' }\n")
    (repo / "app" / "build.gradle").write_text(
        'apply from: "$rootDir/gradle/scripts/deps.gradle"\n'
        'dependencies { implementation "c:lib:$libVersion" }\n')
    assert dynamic_versions(repo / "app") == []
    assert dynamic_versions(repo) == []


# --- gradle 명명인자 표기 (이월분) ---
# 판별 축: "한 논리 줄에서, 식별자로 시작하는 호출의 **콜론 명명인자**에 group|module + name +
# version 이 함께 있을 것". `version:` 단독은 절대 신호로 쓰지 않는다 — 프로젝트 자기 버전·
# publishing DSL 과 구분이 안 되기 때문(그래서 지난 라운드에 보류했던 표기다).

def _gradle(tmp_path, script, name="build.gradle"):
    p = tmp_path / "g"
    p.mkdir(exist_ok=True)
    (p / name).write_text(script)
    return p


@pytest.mark.parametrize("script,expected", [
    # 1) 리터럴 동적 버전
    ("dependencies {\n  implementation group: 'org.x', name: 'y', version: '2.+'\n}\n", "2.+"),
    # 2) 괄호 + 보간
    ('def v = "3.+"\ndependencies {\n  implementation(group: \'org.x\', name: \'y\', version: "$v")\n}\n', "3.+"),
    # 3) 여러 줄로 이어진 인자 목록
    ("dependencies {\n  implementation group: 'org.x',\n    name: 'y',\n    version: '1.0-SNAPSHOT'\n}\n",
     "1.0-SNAPSHOT"),
    # 4) 따옴표 없는 식(미해석) → fail-closed
    ("dependencies {\n  implementation group: 'org.x', name: 'y', version: rootProject.ext.libVersion\n}\n",
     "${rootProject.ext.libVersion}"),
    # 5) module: 별칭
    ("dependencies {\n  implementation module: 'org.x', name: 'y', version: 'latest.release'\n}\n",
     "latest.release"),
])
def test_dynamic_versions_detects_gradle_named_arguments(tmp_path, script, expected):
    got = [d.version for d in dynamic_versions(_gradle(tmp_path, script))]
    assert got == [expected]


def test_dynamic_versions_resolves_fixed_named_argument_version(tmp_path):
    """양성 축이 고정 버전까지 잡으면 안 된다."""
    p = _gradle(tmp_path, "dependencies {\n  implementation group: 'org.x', name: 'y', version: '1.9'\n}\n")
    assert dynamic_versions(p) == []


def test_dynamic_versions_resolves_named_argument_variable(tmp_path):
    """따옴표 없는 식도 로컬에서 풀리면 고정이다."""
    p = _gradle(tmp_path, "ext { libVersion = '1.9' }\n"
                          "dependencies {\n  implementation group: 'org.x', name: 'y', version: libVersion\n}\n")
    assert dynamic_versions(p) == []


@pytest.mark.parametrize("script", [
    # 프로젝트 자기 버전 (지난 라운드 보류 사유 그 자체)
    "group = 'com.corp'\nversion = '1.0-SNAPSHOT'\n",
    "version '1.0-SNAPSHOT'\n",
    "ext { version = '2.+' }\n",
    # publishing / pom 블록
    """publishing { publications { mavenJava(MavenPublication) {
        groupId = 'com.corp'
        artifactId = 'app'
        version = '1.0-SNAPSHOT'
    } } }
    """,
    "pom {\n  name = 'app'\n  version = '2.+'\n}\n",
    # 콜론을 쓰는 다른 DSL — 세 키가 다 모이지 않는다
    "task bundle(type: Copy, group: 'build', description: 'x')\n",
    "dependencies { implementation('g:a:1.9') { exclude group: 'org.z', module: 'w' } }\n",
    "artifacts { archives file: jar, name: 'app', type: 'jar' }\n",
    # 플러그인 DSL
    "plugins { id 'org.springframework.boot' version '3.5.16' }\n",
    # 주석 안
    "// implementation group: 'org.x', name: 'y', version: '2.+'\n",
    "/* implementation group: 'org.x', name: 'y', version: '9.+' */\n",
    # 문자열 안 (문서화 목적으로 적어둔 예시)
    "def doc = \"implementation group: 'org.x', name: 'y', version: '2.+'\"\n",
])
def test_dynamic_versions_named_argument_negative_controls(tmp_path, script):
    """음성 대조군 — 하나라도 잡히면 판별 축이 틀린 것이다."""
    assert dynamic_versions(_gradle(tmp_path, script)) == []


# --- 명명인자 파서 경계 처리 (codex) ---

def test_named_arg_detects_open_paren_continuation(tmp_path):
    """[P1] 여는 괄호 뒤 줄바꿈으로 인자가 이어지는 흔한 포맷 — 열린 구분자를 추적해야 한다."""
    p = _gradle(tmp_path, "dependencies {\n  implementation(\n"
                          "      group: 'org.x',\n      name: 'y',\n      version: '2.+'\n  )\n}\n")
    assert [d.version for d in dynamic_versions(p)] == ["2.+"]


@pytest.mark.parametrize("call", [
    "implementation(version: '2.+', group: 'org.x', name: 'y')",   # Groovy 맵은 순서 무의미
    "implementation([group: 'org.x', name: 'y', version: '2.+'])",  # 대괄호 맵
    "implementation([version: '2.+', name: 'y', group: 'org.x'])",
])
def test_named_arg_detects_regardless_of_key_order_or_brackets(tmp_path, call):
    """[P1] 호출을 먼저 인식하고 필수 키 충족은 파싱 후에 검증한다."""
    p = _gradle(tmp_path, f"dependencies {{\n  {call}\n}}\n")
    assert [d.version for d in dynamic_versions(p)] == ["2.+"]


def test_named_arg_splits_calls_on_same_physical_line(tmp_path):
    """[P2] 한 줄에 `;` 로 두 호출이 있으면 args 가 뭉개져 뒤쪽 동적 버전이 버려졌다."""
    p = _gradle(tmp_path, "dependencies {\n"
                          "  implementation group: 'a', name: 'b', version: '1.9'; "
                          "implementation group: 'c', name: 'd', version: '2.+'\n}\n")
    got = [(d.coordinate, d.version) for d in dynamic_versions(p)]
    assert got == [("c:d", "2.+")]


def test_named_arg_ignores_triple_quoted_example_code(tmp_path):
    """[P2] 삼중따옴표 문자열 안의 예시 코드 — 스테일이 아니라 오탐(매 스캔 재생성)이다."""
    p = _gradle(tmp_path, 'def usage = """\n'
                          "implementation group: 'org.x', name: 'y', version: '2.+'\n"
                          '"""\n')
    assert dynamic_versions(p) == []
