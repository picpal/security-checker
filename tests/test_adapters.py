"""M1 스캐너 어댑터 — 실행/상태 해석 (부수효과는 runner 주입으로 결정적 테스트).

가장 중요한 계약:
- osv-scanner 는 취약점 발견 시 exit 1 → 실패가 아니라 성공(payload 유효)이다.
- 타임아웃/미설치는 예외를 던지지 않고 status 로 보고한다(부분 실패는 정상).
"""

from secscan.adapters.base import FAILED, OK, SKIPPED, TIMEOUT
from secscan.adapters.osv import OsvAdapter
from secscan.adapters.trivy import TrivyAdapter


class FakeProc:
    def __init__(self, returncode, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _runner(returncode, stdout="", stderr=""):
    return lambda argv, timeout: FakeProc(returncode, stdout, stderr)


def test_trivy_builds_fs_vuln_json_command():
    argv = TrivyAdapter().build_argv("/proj", {})
    assert argv[0] == "trivy"
    assert "fs" in argv
    assert argv[argv.index("--format") + 1] == "json"
    assert "/proj" in argv


def test_trivy_exit_0_is_ok_with_payload():
    r = TrivyAdapter().run("/proj", run=_runner(0, stdout='{"Results":[]}'))
    assert r.status == OK
    assert r.tool == "trivy"
    assert r.format == "json"
    assert r.payload == '{"Results":[]}'
    assert r.exit_code == 0


def test_osv_builds_v2_scan_source_json_command():
    argv = OsvAdapter().build_argv("/proj", {})
    assert argv[:3] == ["osv-scanner", "scan", "source"]  # v2 CLI
    assert argv[argv.index("--format") + 1] == "json"
    assert "/proj" in argv
    assert ("-r" in argv) or ("--recursive" in argv)


def test_osv_exit_1_means_vulns_found_not_failure():
    r = OsvAdapter().run("/proj", run=_runner(1, stdout='{"results":[]}'))
    assert r.status == OK  # exit 1 = 취약점 발견 = 성공
    assert r.payload == '{"results":[]}'


def test_osv_exit_0_no_vulns_is_ok():
    r = OsvAdapter().run("/proj", run=_runner(0, stdout='{"results":[]}'))
    assert r.status == OK


def test_osv_high_exit_code_is_failure():
    r = OsvAdapter().run("/proj", run=_runner(127, stderr="command not found"))
    assert r.status == FAILED
    assert r.exit_code == 127


def test_adapter_timeout_is_reported_not_raised():
    def boom(argv, timeout):
        raise TimeoutError()

    r = TrivyAdapter().run("/proj", run=boom)
    assert r.status == TIMEOUT


def test_adapter_missing_binary_is_skipped_not_raised():
    def missing(argv, timeout):
        raise FileNotFoundError()

    r = TrivyAdapter().run("/proj", run=missing)
    assert r.status == SKIPPED
