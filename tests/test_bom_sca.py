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
from secscan.sbom import bom_cache_path, ensure_bom, generate_sbom


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
    r = a.run("/p", ensure_bom=lambda target, timeout: None,
              run=lambda argv, timeout: FakeProc(0))
    assert r.status == SKIPPED
    assert r.tool == "trivy"


def test_bom_sca_runs_trivy_on_bom_and_reuses_trivy_schema():
    a = BomScaAdapter()
    r = a.run("/p",
              ensure_bom=lambda target, timeout: "/tmp/bom.json",
              run=lambda argv, timeout: FakeProc(0, stdout='{"Results":[]}'))
    assert r.status == OK
    assert r.tool == "trivy"  # parse_trivy 가 정규화
    assert r.payload == '{"Results":[]}'


def test_bom_sca_isolates_cdxgen_exception():
    def boom(target, timeout):
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
