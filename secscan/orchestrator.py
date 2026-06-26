"""오케스트레이터 — 어댑터들을 병렬 실행하고 RawResult 를 모은다.

부분 실패는 정상(spec §11): 한 어댑터가 죽어도 예외를 status 로 격리하고
나머지 결과는 유효하게 돌려준다. max_workers 로 동시성 상한(자원 경합 방지).
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from .adapters.base import FAILED, RawResult


def scan(adapters, target, *, max_workers: int | None = None) -> list[RawResult]:
    if not adapters:
        return []
    workers = max_workers or min(len(adapters), 8)
    results: list[RawResult] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(a.run, target): a for a in adapters}
        for fut in as_completed(futures):
            adapter = futures[fut]
            try:
                results.append(fut.result())
            except Exception as e:  # 어댑터가 자체 격리에 실패한 경우의 backstop
                results.append(
                    RawResult(adapter.name, FAILED, error=f"orchestrator: {e}")
                )
    return results
