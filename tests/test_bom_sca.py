"""M-recall: cdxgen BOM 기반 SCA — gradle/maven 전이 의존 해석으로 recall 복구.

핵심: 락파일 없는 gradle 도 cdxgen 이 전체 의존 그래프를 BOM 으로 해석 → trivy sbom
이 전이 CVE 를 검출. (message-gate 스파이크: fs-trivy 0 → BOM 34건)
"""

from secscan.adapters.base import OK, SKIPPED
from secscan.adapters.bom_sca import BomScaAdapter
from secscan.sbom import bom_cache_path, generate_sbom


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
