"""M5 deep — SpotBugs+FindSecBugs 바이트코드 어댑터 (experimental).

게이트 핵심 = **빌드 실패 안전 처리**: 컴파일 클래스가 없고 빌드도 실패하면 크래시
없이 status=skipped(partial)로 격리한다. find_classes/build/run 주입으로 결정적 테스트.
"""

from secscan.adapters.base import OK, SKIPPED
from secscan.adapters.spotbugs import SpotBugsAdapter
from secscan.normalize.spotbugs import parse_spotbugs_sarif


class FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_skips_safely_when_no_classes_and_build_fails():
    a = SpotBugsAdapter()
    r = a.run("/proj", find_classes=lambda t: None, build=lambda t: False)
    assert r.status == SKIPPED
    assert r.tool == "spotbugs"
    assert "빌드" in r.error or "build" in r.error.lower()


def test_skips_when_still_no_classes_after_build():
    a = SpotBugsAdapter()
    r = a.run("/proj", find_classes=lambda t: None, build=lambda t: True)
    assert r.status == SKIPPED  # 빌드는 됐다지만 클래스 없음 → 안전 격리


def test_build_failure_does_not_raise():
    a = SpotBugsAdapter()

    def boom_build(t):
        raise RuntimeError("mvn exploded")

    # 빌드 함수가 예외를 던져도 어댑터는 크래시하지 않고 skipped 로 격리
    r = a.run("/proj", find_classes=lambda t: None, build=boom_build)
    assert r.status == SKIPPED


def test_runs_spotbugs_when_classes_present(tmp_path):
    # 클래스가 있으면 spotbugs 를 실행하고 SARIF 산출물을 payload 로 돌려준다
    sarif_out = '{"runs":[{"results":[]}]}'

    def fake_run(argv, timeout):
        # spotbugs 가 -output 파일에 쓰는 것을 시뮬레이션
        out_path = argv[argv.index("-output") + 1]
        open(out_path, "w").write(sarif_out)
        return FakeProc(0)

    a = SpotBugsAdapter()
    r = a.run(str(tmp_path),
              find_classes=lambda t: str(tmp_path),
              build=lambda t: True,
              run=fake_run)
    assert r.status == OK
    assert r.payload == sarif_out


def test_parse_spotbugs_sarif_empty():
    assert parse_spotbugs_sarif('{"runs":[{"results":[]}]}') == []
