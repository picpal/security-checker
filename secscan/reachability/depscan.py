"""dep-scan/atom 기반 도달성 provider.

dep-scan(SemanticReachability)이 생성하는 atom **usage 슬라이스**에서 "소스가 실제
호출하는 외부 타입"을 추출하고, 탐지된 취약 컴포넌트의 패키지가 그 안에 있으면
도달 가능, 없으면 도달 불가로 판정한다.

한계(보고서에 명시): 판정은 **앱 레벨 호출** 기준이다. reflection·DI·전이 의존
내부 호출은 정적 사각지대라 '도달 불가'가 안전 보증은 아니다(spec §5.7/§13).
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from ..models import REACHABLE, UNREACHABLE
from .engine import ReachabilityResult

# 무시할 비-타입 토큰
_NOISE = ("<operator>", "<unresolved", "ANY", "<empty>", "<global>")
_PRIMITIVES = {
    "void", "boolean", "byte", "char", "short", "int", "long", "float", "double",
    "java.lang.String", "java.lang.Object",
}


def _is_type(name: str | None) -> bool:
    if not name or "." not in name:
        return False
    if any(n in name for n in _NOISE):
        return False
    return True


def _class_of_method(resolved: str | None) -> str | None:
    # "fqcn.method:rettype(args)" -> "fqcn"
    if not resolved or "(" not in resolved:
        return None
    head = resolved.split(":", 1)[0]  # drop signature
    if "." not in head:
        return None
    return head.rsplit(".", 1)[0]  # drop method name


def parse_invoked_symbols(usage_slice_json: str) -> set[str]:
    """usage 슬라이스 → 소스가 참조/호출하는 외부 타입 fullname 집합."""
    data = json.loads(usage_slice_json)
    symbols: set[str] = set()
    for sl in data.get("objectSlices", []) or []:
        for u in sl.get("usages", []) or []:
            for key in ("targetObj", "definedBy"):
                o = u.get(key) or {}
                t = o.get("typeFullName")
                if _is_type(t) and t not in _PRIMITIVES:
                    symbols.add(t)
                cls = _class_of_method(o.get("resolvedMethod"))
                if _is_type(cls):
                    symbols.add(cls)
            for call_key in ("invokedCalls", "argToCalls"):
                for c in u.get(call_key, []) or []:
                    cls = _class_of_method(c.get("resolvedMethod"))
                    if _is_type(cls):
                        symbols.add(cls)
    return symbols


def package_prefixes(pkg: str) -> tuple[str, ...]:
    """Maven 좌표(group:artifact) → 후보 Java 패키지 프리픽스."""
    if ":" not in pkg:
        return (pkg,)
    group, artifact = pkg.split(":", 1)
    prefixes = set()
    art = artifact
    for pre in ("commons-",):
        if art.startswith(pre):
            art = art[len(pre):]
    prefixes.add(f"{group}.{art.replace('-', '.')}")
    prefixes.add(f"{group}.{artifact.replace('-', '.')}")
    return tuple(prefixes)


def decide_reachability(findings, invoked: set[str]) -> ReachabilityResult:
    verdicts: dict[str, str] = {}
    evidence: dict[str, str] = {}
    for f in findings:
        if not f.component:
            continue
        key = f"{f.component.package}@{f.component.version}"
        if key in verdicts:
            continue
        prefixes = package_prefixes(f.component.package)
        match = next(
            (s for s in invoked if any(s == p or s.startswith(p + ".") for p in prefixes)),
            None,
        )
        if match:
            verdicts[key] = REACHABLE
            evidence[key] = f"앱 코드가 {match} 사용"
        else:
            verdicts[key] = UNREACHABLE
    return ReachabilityResult(verdicts=verdicts, evidence=evidence, status="ok")


# --- 실행체 (side effect): dep-scan 으로 usage 슬라이스 생성 후 결정 ---

class DepscanUsageProvider:
    """provider(target, timeout, findings) 인터페이스. usage 슬라이스가 있으면 재사용."""

    def __init__(self, reports_dir: str | Path, *, run_if_missing: bool = True):
        self.reports_dir = Path(reports_dir)
        self.run_if_missing = run_if_missing

    def _slice_path(self) -> Path:
        return self.reports_dir / "java-usages.slices.json"

    def _ensure_slice(self, target, timeout) -> str:
        sp = self._slice_path()
        if not sp.exists() and self.run_if_missing:
            self.reports_dir.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                [
                    "depscan", "--src", str(target),
                    "--reports-dir", str(self.reports_dir),
                    "--reachability-analyzer", "SemanticReachability",
                    "-t", "java", "--profile", "research",
                ],
                capture_output=True, text=True, timeout=timeout,
            )
        return sp.read_text()

    def __call__(self, target, timeout, findings) -> ReachabilityResult:
        invoked = parse_invoked_symbols(self._ensure_slice(target, timeout))
        return decide_reachability(findings, invoked)
