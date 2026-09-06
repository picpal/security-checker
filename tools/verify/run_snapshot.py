"""스냅샷 1개 실스캔 + 증거 동결.

사용: python -m tools.verify.run_snapshot --repo <message-gate> --sha a483b3b1 \
        --profile standard --scratch /tmp/secscan-verify --out docs/verification/evidence/2026-09-05/a483b3b1
네트워크: 의존성 다운로드(cdxgen/gradle)만. 시크릿 검증은 항상 never.
"""

from __future__ import annotations

import argparse
import json
import os
import resource
import time
from datetime import date
from pathlib import Path

from secscan.cli import count_source_loc, reachability_env_ok, source_hash
from secscan.profiles import build_adapters, get_profile
from secscan.reachability.depscan import DepscanUsageProvider
from secscan.reachability.engine import Budget
from secscan.scan import TraceSink, run_scan

from .evidence import tool_versions, write_evidence
from .snapshot import apply_isolated_env, prepare_snapshot


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tools.verify.run_snapshot")
    p.add_argument("--repo", required=True)
    p.add_argument("--sha", required=True)
    p.add_argument("--profile", default="standard")
    p.add_argument("--scratch", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--no-reachability", action="store_true")
    p.add_argument("--allow-large", action="store_true")
    p.add_argument("--xlsx", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    scratch = Path(args.scratch)
    apply_isolated_env(scratch, args.sha)  # os.environ 을 실제로 clear+재적용 — 이후 subprocess 전부 상속
    repo_dir = prepare_snapshot(Path(args.repo), args.sha, scratch)

    profile = get_profile(args.profile)
    adapters = build_adapters(profile)
    provider, env_ok = None, (lambda: True)
    if profile.reachability and not args.no_reachability:
        provider = DepscanUsageProvider(scratch / args.sha / "reach" / source_hash(repo_dir))
        env_ok = reachability_env_ok

    sink = TraceSink()
    t0 = time.perf_counter()
    result = run_scan(
        repo_dir, profile, adapters=adapters, reachability_provider=provider, env_ok=env_ok,
        count_loc=count_source_loc, budget=Budget(allow_large=args.allow_large),
        secret_policy="never", secret_runner=None,
        today=date.today().isoformat(), trace=sink,
    )
    elapsed = time.perf_counter() - t0
    rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    meta = {
        "snapshot": args.sha, "repo": str(args.repo), "profile": args.profile,
        "run_date": date.today().isoformat(), "elapsed_s": round(elapsed, 1),
        "children_max_rss_bytes": rss, "tool_versions": tool_versions(),
        "isolated": {"gradle_user_home": os.environ["GRADLE_USER_HOME"], "secret_policy": "never"},
    }
    written = write_evidence(args.out, result=result, trace=sink, meta=meta, xlsx=args.xlsx, repo_root=repo_dir,
                             target=repo_dir)
    print(json.dumps({"written": [str(p) for p in written], "findings": len(result.findings),
                      "partial": [r.tool for r in result.partial_failures], "elapsed_s": meta["elapsed_s"]},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
