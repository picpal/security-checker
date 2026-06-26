"""TruffleHog 검증 runner — `trufflehog filesystem --only-verified --json`.

JSONL(라인당 JSON) 출력에서 Verified=true 인 항목의 파일 경로를 모은다.
검증은 자격증명을 제3자로 전송하므로 정책상 'verify' 일 때만 호출된다(verify.py).
"""

from __future__ import annotations

import json
import subprocess

# AGPL-3.0 주의: 개인 사용 단계라 무관. 사내/상용 확장 시 격리 실행 재검토(spec §17).


def parse_trufflehog_verified_files(jsonl: str) -> set[str]:
    files: set[str] = set()
    for line in jsonl.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not obj.get("Verified"):
            continue
        fs = (((obj.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {})
        f = fs.get("file")
        if f:
            files.add(f)
    return files


def trufflehog_runner(target, *, timeout: float = 300.0, run=None) -> set[str]:
    """trufflehog 를 실행해 라이브(verified) 시크릿이 있는 파일 집합을 반환."""
    argv = ["trufflehog", "filesystem", str(target), "--only-verified", "--json", "--no-update"]
    runner = run or (lambda a, t: subprocess.run(a, capture_output=True, text=True, timeout=t))
    try:
        proc = runner(argv, timeout)
    except Exception:
        return set()
    return parse_trufflehog_verified_files(proc.stdout or "")
