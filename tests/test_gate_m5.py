"""M5 인수(게이트) — 바이트코드 탐지 + 빌드 실패 안전 처리 (experimental)."""

from pathlib import Path

from secscan.adapters.base import SKIPPED
from secscan.adapters.spotbugs import SpotBugsAdapter
from secscan.normalize.spotbugs import parse_spotbugs_sarif

GOLDEN = Path(__file__).parent / "golden" / "spotbugs-sast-app.sarif"


def test_gate_bytecode_detects_command_injection_that_semgrep_ce_missed():
    findings = parse_spotbugs_sarif(GOLDEN.read_text())
    cwes = set()
    for f in findings:
        cwes |= set(f.cwe)
    # CWE-78(command injection)은 Semgrep CE(intraprocedural)가 놓친 것 → 바이트코드가 잡음
    assert "CWE-78" in cwes
    assert "CWE-89" in cwes  # SQL injection 도 탐지
    assert any(f.tool == "spotbugs" and f.location for f in findings)


def test_gate_build_failure_is_isolated_as_partial():
    r = SpotBugsAdapter().run("/x", find_classes=lambda t: None, build=lambda t: False)
    assert r.status == SKIPPED  # 빌드 실패 → 크래시 없이 격리(나머지 스캐너는 계속)


def test_gate_unexpected_error_does_not_crash():
    def boom(t):
        raise RuntimeError("toolchain broke")

    r = SpotBugsAdapter().run("/x", find_classes=lambda t: None, build=boom)
    assert r.status == SKIPPED
