"""secscan CLI — 현재 `doctor` 서브커맨드.

렌더링(render_doctor)은 순수 함수라 테스트가 쉽다. main 은 run_doctor 를
모듈 전역으로 호출하므로 테스트에서 주입/대체할 수 있다.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from datetime import date
from pathlib import Path

from .detect import detect_stack, suggest_profile
from .doctor import MISSING, OK, DoctorReport, run_doctor
from .measure import reachability_stats
from .models import UNREACHABLE
from .output.markdown import to_markdown
from .output.sarif import to_sarif
from .profiles import build_adapters, get_profile
from .reachability.depscan import DepscanUsageProvider
from .reachability.engine import Budget
from .scan import run_scan
from .secret.trufflehog import trufflehog_runner
from .secret.verify import resolve_secret_policy
from .suppress.store import load_baseline, load_suppressions, save_baseline

_KIND_LABEL = {"scanner": "스캐너", "runtime": "런타임", "resource": "자원"}
_KIND_ORDER = ["scanner", "runtime", "resource"]


def _marker(state: str) -> str:
    if state == OK:
        return "✓"
    if state == MISSING:
        return "✗"
    return "⚠"


def render_doctor(report: DoctorReport) -> str:
    lines = ["secscan doctor — 환경 점검", ""]

    by_kind: dict[str, list] = {}
    for s in report.statuses:
        by_kind.setdefault(s.req.kind, []).append(s)

    for kind in _KIND_ORDER:
        group = by_kind.get(kind)
        if not group:
            continue
        lines.append(f"[{_KIND_LABEL.get(kind, kind)}]")
        for s in group:
            mark = _marker(s.state)
            if not s.present:
                detail = f"(미설치) {s.req.purpose}"
            elif s.satisfies:
                detail = s.version or "설치됨"
            else:  # present 하나 문제(outdated/unknown/low): 감지값 + 사유
                parts = [p for p in (s.version, s.note or s.req.purpose) if p]
                detail = " — ".join(parts)
            lines.append(f"  {mark} {s.req.name:<13} {detail}")
            if not s.satisfies and s.req.install_hint:
                lines.append(f"      → {s.req.install_hint}")
        lines.append("")

    problems = [s for s in report.statuses if not s.satisfies]
    total = len(report.statuses)
    okc = total - len(problems)
    if report.ok:
        lines.append(f"요약: {okc}/{total} 정상 — 환경 준비 완료 ✓")
    else:
        blockers = [s for s in problems if not s.req.optional]
        lines.append(
            f"요약: {okc}/{total} 정상, 문제 {len(problems)}개"
            f" (차단 {len(blockers)}개). 위 → 명령으로 설치 후 다시 실행하세요."
        )
    return "\n".join(lines)


def _cmd_doctor() -> int:
    report = run_doctor()
    print(render_doctor(report))
    return 0 if report.ok else 1


# --- scan ---

_SRC_GLOBS = ("*.java", "*.kt", "pom.xml", "*.gradle", "*.gradle.kts")


def count_source_loc(target) -> int:
    total = 0
    for g in ("*.java", "*.kt"):
        for p in Path(target).rglob(g):
            try:
                total += sum(1 for _ in p.open("rb"))
            except OSError:
                pass
    return total


def source_hash(target) -> str:
    # 캐시 키(식별자)용 — 보안 해시 아님. usedforsecurity=False 로 의도 명시.
    h = hashlib.sha1(usedforsecurity=False)
    files = sorted(p for g in _SRC_GLOBS for p in Path(target).rglob(g))
    for p in files:
        try:
            h.update(p.read_bytes())
        except OSError:
            pass
    return h.hexdigest()[:16]


def reachability_env_ok() -> bool:
    return all(shutil.which(t) for t in ("depscan", "java", "node"))


def render_scan_summary(result) -> str:
    stats = reachability_stats(result.findings)
    lines = ["secscan scan — 요약", ""]
    lines.append(
        f"총 **{stats.total}건** — 도달 가능 {stats.reachable} · "
        f"도달 불가 {stats.unreachable} · 미상 {stats.unknown}"
    )
    if result.reachability_ran:
        lines.append(
            f"도달성: 적용됨 — 조치대상 {stats.actionable_off}→{stats.actionable_on} "
            f"(노이즈 {stats.noise_reduction:.0%} 감소)"
        )
    else:
        lines.append(f"도달성: 미적용 ({result.reachability_reason})")
    if result.secret_policy == "verify":
        lines.append(f"시크릿 검증: 적용됨 — 라이브 {result.secret_verified_count}건 확인")
    elif result.secret_policy == "never":
        lines.append("시크릿 검증: 차단됨 (network-off — 자격증명 미전송)")
    if result.suppressed_count:
        lines.append(f"억제됨: {result.suppressed_count}건 (사람 확정 — 보고서 별도 섹션)")
    if result.invalidated:
        lines.append(f"⚠️ 억제 무효화(재검토 필요): {len(result.invalidated)}건 — 만료/버전/도달성 변경")
    if result.partial_failures:
        names = ", ".join(f"{r.tool}({r.status})" for r in result.partial_failures)
        lines.append(f"⚠️ 부분 실패: {names} — 나머지 결과는 유효")
    return "\n".join(lines)


def _has_actionable(findings) -> bool:
    # 도달 불가가 아닌 finding(도달 가능/미상)이 하나라도 있으면 조치 대상
    return any(f.reachability.status != UNREACHABLE for f in findings)


def _cmd_scan(args) -> int:
    try:
        profile = get_profile(args.profile)
    except KeyError as e:
        print(str(e))
        return 2

    adapters = build_adapters(profile)
    provider = None
    env_ok = (lambda: True)
    if profile.reachability and not args.no_reachability:
        reports = Path(args.cache_dir) / source_hash(args.target)
        provider = DepscanUsageProvider(reports)
        env_ok = reachability_env_ok

    policy = resolve_secret_policy(args.verify_secrets, args.network_off)
    # 안전: 'verify' 일 때만 네트워크 runner 를 건넨다. off/never 면 None (전송 불가능).
    secret_runner = trufflehog_runner if policy == "verify" else None

    suppressions = load_suppressions(args.suppressions) if args.suppressions else None
    baseline_keys = load_baseline(args.baseline) if args.baseline else None

    result = run_scan(
        args.target, profile,
        adapters=adapters,
        reachability_provider=provider,
        env_ok=env_ok,
        count_loc=count_source_loc,
        budget=Budget(allow_large=args.allow_large),
        secret_policy=policy,
        secret_runner=secret_runner,
        suppressions=suppressions,
        baseline_keys=baseline_keys,
        today=date.today().isoformat(),
        exclude=args.exclude,
    )

    if args.write_baseline:
        save_baseline(args.write_baseline, result.findings)
        print(f"baseline 저장: {args.write_baseline} ({len(result.findings)}건)\n")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "findings.sarif").write_text(
        json.dumps(to_sarif(result.findings), indent=2, ensure_ascii=False)
    )
    (out / "report.md").write_text(
        to_markdown(result.findings, target=str(args.target),
                    meta={"scanners": [a.name for a in adapters]})
    )

    print(render_scan_summary(result))
    print(f"\n출력: {out / 'report.md'} · {out / 'findings.sarif'}")
    return 1 if _has_actionable(result.findings) else 0


def _cmd_detect(args) -> int:
    stack = detect_stack(args.target)
    profile = suggest_profile(stack, intent=args.intent)
    print(f"스택 감지: build={stack['build_tool']} · 언어={stack['languages']} · 모듈={stack['modules']}")
    if not stack["is_jvm"]:
        print("⚠️ JVM 프로젝트로 보이지 않습니다 — secscan 은 JVM(Java/Kotlin) 타깃입니다.")
        print("   (SCA/SAST/도달성은 거의 적용되지 않고 secret 점검만 의미 있습니다.)")
    print(f"intent={args.intent} → 추천 프로파일: {profile}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="secscan",
        description="JVM(Java/Kotlin) 보안 점검 하이브리드 CLI",
    )
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("doctor", help="환경(스캐너·런타임·메모리) 점검")

    dp = sub.add_parser("detect", help="스택/빌드도구 감지 + 프로파일 추천")
    dp.add_argument("--target", required=True)
    dp.add_argument("--intent", default="full",
                    help="quick | patch | full | deep (자연어 해석 결과)")

    sp = sub.add_parser("scan", help="보안 점검 실행 (SCA + 도달성)")
    sp.add_argument("--target", required=True, help="점검 대상 프로젝트 경로")
    sp.add_argument("--profile", default="accurate-sca",
                    help="quick | accurate-sca | standard (기본: accurate-sca)")
    sp.add_argument("--out", default="out", help="보고서 출력 디렉토리")
    sp.add_argument("--cache-dir", default=".secscan/reach",
                    help="도달성(atom 슬라이스) 캐시 디렉토리")
    sp.add_argument("--no-reachability", action="store_true",
                    help="도달성 분석 생략")
    sp.add_argument("--allow-large", action="store_true",
                    help="대형 코드베이스에서도 도달성 강제 실행(크기 임계 무시)")
    sp.add_argument("--verify-secrets", action="store_true",
                    help="TruffleHog 로 시크릿 라이브 검증 (자격증명을 제3자로 전송 — opt-in)")
    sp.add_argument("--network-off", action="store_true",
                    help="시크릿 검증 강제 차단 (--verify-secrets 보다 우선)")
    sp.add_argument("--exclude", action="append", metavar="GLOB",
                    help="경로 제외(반복 가능). 예: --exclude fixtures --exclude '*/test/*'")
    sp.add_argument("--suppressions", help="사람이 확정한 억제 파일(JSON) 경로")
    sp.add_argument("--baseline", help="baseline 파일(JSON) — 기존 이슈 억제, 신규만 알림")
    sp.add_argument("--write-baseline", help="현재 findings 를 baseline 파일로 저장")

    args = parser.parse_args(argv)
    if args.command == "doctor":
        return _cmd_doctor()
    if args.command == "detect":
        return _cmd_detect(args)
    if args.command == "scan":
        return _cmd_scan(args)

    parser.print_help()
    return 2
