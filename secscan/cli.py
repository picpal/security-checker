"""secscan CLI — 현재 `doctor` 서브커맨드.

렌더링(render_doctor)은 순수 함수라 테스트가 쉽다. main 은 run_doctor 를
모듈 전역으로 호출하므로 테스트에서 주입/대체할 수 있다.
"""

from __future__ import annotations

import argparse

from .doctor import MISSING, OK, DoctorReport, run_doctor

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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="secscan",
        description="JVM(Java/Kotlin) 보안 점검 하이브리드 CLI",
    )
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("doctor", help="환경(스캐너·런타임·메모리) 점검")

    args = parser.parse_args(argv)
    if args.command == "doctor":
        return _cmd_doctor()

    parser.print_help()
    return 2
