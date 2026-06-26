"""M1 오케스트레이터 — 어댑터 병렬 실행 + 부분 실패 격리(spec §5.2, §11)."""

import threading
import time

from secscan.adapters.base import FAILED, OK, RawResult
from secscan.orchestrator import scan


class FakeAdapter:
    def __init__(self, name, result=None, exc=None):
        self.name = name
        self._result = result
        self._exc = exc

    def run(self, target, **kw):
        if self._exc:
            raise self._exc
        return self._result


def test_scan_collects_results_from_all_adapters():
    a = FakeAdapter("trivy", RawResult("trivy", OK, payload="{}"))
    b = FakeAdapter("osv-scanner", RawResult("osv-scanner", OK, payload="{}"))
    results = scan([a, b], "/proj")
    assert {r.tool for r in results} == {"trivy", "osv-scanner"}


def test_scan_isolates_partial_failure():
    good = FakeAdapter("trivy", RawResult("trivy", OK, payload="ok"))
    bad = FakeAdapter("boom", exc=RuntimeError("crash"))
    results = scan([good, bad], "/proj")
    by = {r.tool: r for r in results}
    assert by["trivy"].status == OK
    assert by["trivy"].payload == "ok"  # 다른 어댑터 결과는 온전
    assert by["boom"].status == FAILED  # 예외가 status 로 격리(전체 안 죽음)


def test_scan_executes_adapters_concurrently():
    peak = 0
    current = 0
    lock = threading.Lock()

    class Slow:
        def __init__(self, name):
            self.name = name

        def run(self, target, **kw):
            nonlocal peak, current
            with lock:
                current += 1
                peak = max(peak, current)
            time.sleep(0.05)
            with lock:
                current -= 1
            return RawResult(self.name, OK)

    scan([Slow("a"), Slow("b"), Slow("c")], "/proj")
    assert peak >= 2  # 동시에 2개 이상 실행


def test_scan_respects_max_workers():
    peak = 0
    current = 0
    lock = threading.Lock()

    class Slow:
        def __init__(self, name):
            self.name = name

        def run(self, target, **kw):
            nonlocal peak, current
            with lock:
                current += 1
                peak = max(peak, current)
            time.sleep(0.03)
            with lock:
                current -= 1
            return RawResult(self.name, OK)

    scan([Slow(str(i)) for i in range(4)], "/proj", max_workers=1)
    assert peak == 1  # 동시성 상한 1 → 순차
