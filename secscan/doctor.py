"""M0 doctor — 환경(스캐너·런타임·자원) 진단.

설계: probe 레이어(부수효과, command 실행)와 evaluate 레이어(순수, 판정)를
분리한다. evaluate 는 캔드 RawProbe 만으로 결정적이라 단위 테스트가 쉽다.
"""

from __future__ import annotations

import platform
import re
import shutil
import subprocess
from dataclasses import dataclass

# 상태 상수
OK = "ok"
OUTDATED = "outdated"
MISSING = "missing"
UNKNOWN = "unknown"  # 존재하나 min_version 요구를 확인할 수 없음 (보수적으로 미충족)
LOW = "low"  # 자원(메모리)이 권장치 미달 (경고)


@dataclass(frozen=True)
class Requirement:
    """점검 대상 1개의 명세."""

    name: str
    kind: str  # "scanner" | "runtime" | "resource"
    purpose: str
    install_hint: str
    min_version: tuple[int, ...] | None = None
    version_regex: str | None = None
    version_argv: tuple[str, ...] = ("--version",)
    optional: bool = False
    require_version: bool = False  # True 면 버전 추출 실패 시 미충족(런타임 손상 감지)


@dataclass(frozen=True)
class RawProbe:
    """시스템에서 수집한 raw 사실 (버전 추출 전)."""

    present: bool
    raw_version_output: str = ""


@dataclass(frozen=True)
class ToolStatus:
    req: Requirement
    present: bool
    version: str | None
    satisfies: bool
    state: str
    note: str = ""


@dataclass
class DoctorReport:
    statuses: list[ToolStatus]

    @property
    def ok(self) -> bool:
        return all(s.satisfies for s in self.statuses if not s.req.optional)


def _parse_version(v: str) -> tuple[int, ...]:
    parts = []
    for chunk in v.split("."):
        if chunk.isdigit():
            parts.append(int(chunk))
        else:
            break
    return tuple(parts)


def evaluate(requirements: list[Requirement], probes: dict[str, RawProbe]) -> DoctorReport:
    statuses = []
    for req in requirements:
        probe = probes.get(req.name)
        if probe is None or not probe.present:
            statuses.append(ToolStatus(req, False, None, False, MISSING))
            continue

        version = None
        if req.version_regex:
            m = re.search(req.version_regex, probe.raw_version_output)
            if m:
                version = m.group(1)

        satisfies = True
        state = OK
        if req.require_version and version is None:
            # 버전 출력은 됐는데 패턴 매칭 실패 = 런타임 손상 의심(CA 에러 등). "정상" 위장 금지.
            satisfies = False
            state = UNKNOWN
        elif req.min_version:
            if version is None:
                satisfies = False
                state = UNKNOWN
            elif _parse_version(version) < req.min_version:
                satisfies = False
                state = OUTDATED

        statuses.append(ToolStatus(req, True, version, satisfies, state))
    return DoctorReport(statuses)


# 메모리는 도구가 아니라 자원이라 별도 점검. dep-scan 도달성에만 영향을 주므로
# optional(경고) — 부족해도 탐지는 진행되고 도달성만 폴백된다(spec 10.1 #3).
MEMORY_REQ = Requirement(
    name="memory",
    kind="resource",
    purpose="dep-scan 도달성 분석 (대형 코드베이스일수록 더 필요)",
    install_hint="물리 메모리 증설, 또는 도달성 예산 제한/생략 프로파일 사용",
    optional=True,
)


def memory_status(available_gb: float | None, recommended_gb: float = 8.0) -> ToolStatus:
    if available_gb is None:
        return ToolStatus(MEMORY_REQ, False, None, False, UNKNOWN, note="메모리 측정 실패")
    detected = f"{available_gb:.1f}GB"
    if available_gb >= recommended_gb:
        return ToolStatus(MEMORY_REQ, True, detected, True, OK,
                          note=f"권장 {recommended_gb:.0f}GB 충족")
    return ToolStatus(MEMORY_REQ, True, detected, False, LOW,
                      note=f"권장 {recommended_gb:.0f}GB 미만 — 도달성은 예산 폴백될 수 있음")


# --- 메모리 파서 (순수) ---

def _parse_sysctl_memsize(text: str) -> float | None:
    """macOS `sysctl -n hw.memsize` 출력(바이트)을 GiB로."""
    text = text.strip()
    if text.isdigit():
        return int(text) / (1024**3)
    return None


def _parse_meminfo(text: str) -> float | None:
    """Linux /proc/meminfo 의 MemTotal(kB)을 GiB로."""
    for line in text.splitlines():
        if line.startswith("MemTotal:"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return int(parts[1]) / (1024**2)
    return None


# --- probe 레이어 (부수효과 — 의존성 주입으로 테스트 가능) ---

def _run_version(req: Requirement) -> str:
    """버전 명령을 실행해 stdout+stderr 합본을 돌려준다(java 는 stderr에 출력)."""
    try:
        r = subprocess.run(
            [req.name, *req.version_argv],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return (r.stdout or "") + (r.stderr or "")
    except Exception:
        return ""


def probe_tool(req: Requirement, *, which=shutil.which, run=_run_version) -> RawProbe:
    if which(req.name) is None:
        return RawProbe(present=False)
    return RawProbe(present=True, raw_version_output=run(req))


def probe_memory_gb() -> float | None:
    try:
        if platform.system() == "Darwin":
            out = subprocess.run(
                ["sysctl", "-n", "hw.memsize"],
                capture_output=True, text=True, timeout=5,
            ).stdout
            return _parse_sysctl_memsize(out)
        with open("/proc/meminfo") as f:
            return _parse_meminfo(f.read())
    except Exception:
        return None


# --- M0 기본 점검 대상 (스캐너 4 + 런타임 2). secret/SAST 툴은 해당 마일스톤에서 추가 ---

_SEMVER = r"(\d+\.\d+\.\d+)"

REQUIREMENTS: list[Requirement] = [
    Requirement(
        name="trivy", kind="scanner",
        purpose="SCA(의존성) 탐지 허브 — Maven/Gradle, VEX 소비",
        install_hint="brew install trivy",
        version_regex=r"Version:\s*v?" + _SEMVER,
    ),
    Requirement(
        name="cdxgen", kind="scanner",
        purpose="SBOM 생성(전이 의존성 해석) — BOM 기반 SCA 의 핵심(recall)",
        install_hint="npm install -g @cyclonedx/cdxgen",
        version_regex=_SEMVER,
    ),
    Requirement(
        name="osv-scanner", kind="scanner",
        purpose="SCA advisory 보강(OSV.dev) — 현재 기본 프로파일 미사용(opt)",
        install_hint="brew install osv-scanner",
        version_regex=_SEMVER,
        optional=True,
    ),
    Requirement(
        name="depscan", kind="scanner",
        purpose="JVM 도달성(reachability) 분석 코어 엔진 (OWASP dep-scan)",
        install_hint="pipx install owasp-depscan  (또는 pip install owasp-depscan)",
        version_regex=_SEMVER,
    ),
    Requirement(
        name="atom", kind="scanner",
        purpose="dep-scan 도달성용 콜그래프 슬라이서 (AppThreat atom, Node)",
        install_hint="npm install -g @appthreat/atom",
        version_regex=_SEMVER,
    ),
    Requirement(
        name="java", kind="runtime",
        purpose="dep-scan/atom 런타임 (Java 21 필요)",
        install_hint="brew install openjdk@21",
        min_version=(21,),
        version_regex=r'version "?(\d+(?:\.\d+)*)',
        version_argv=("-version",),
    ),
    Requirement(
        name="node", kind="runtime",
        purpose="atom(도달성) 런타임",
        install_hint="brew install node",
        version_regex=r"v?" + _SEMVER,
    ),
    Requirement(
        name="gitleaks", kind="scanner",
        purpose="시크릿(하드코딩 자격증명) 탐지",
        install_hint="brew install gitleaks",
        version_regex=_SEMVER,
        version_argv=("version",),
    ),
    Requirement(
        name="semgrep", kind="scanner",
        purpose="SAST(소스 패턴, 레지스트리 팩 — 최초 네트워크). taint intraprocedural 한계(§10.2)",
        install_hint="brew install semgrep",
        version_regex=_SEMVER,
        require_version=True,  # 버전 추출 실패 = 런타임 손상(CA 에러 등) 감지
    ),
    Requirement(
        name="trufflehog", kind="scanner",
        purpose="시크릿 유효성 검증 (opt-in, --verify-secrets)",
        install_hint="brew install trufflehog",
        version_regex=_SEMVER,
        optional=True,  # 검증은 기본 off → 없어도 차단 아님
    ),
    Requirement(
        name="spotbugs", kind="scanner",
        purpose="바이트코드 SAST (deep, experimental — 빌드 필요)",
        install_hint="brew install spotbugs (+ FindSecBugs 플러그인 jar)",
        version_regex=_SEMVER,
        version_argv=("-version",),
        optional=True,  # deep 전용 → 없어도 기본 점검 차단 아님
    ),
]


def run_doctor(
    requirements: list[Requirement] = REQUIREMENTS,
    *,
    probe=probe_tool,
    mem=probe_memory_gb,
) -> DoctorReport:
    """probe(부수효과) + evaluate(순수) + 메모리 자원을 조립한 전체 진단."""
    probes = {r.name: probe(r) for r in requirements}
    report = evaluate(requirements, probes)
    report.statuses.append(memory_status(mem()))
    return report
