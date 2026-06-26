"""M0 doctor — 환경(스캐너·런타임·자원) 진단.

설계: probe 레이어(부수효과, command 실행)와 evaluate 레이어(순수, 판정)를
분리한다. evaluate 는 캔드 RawProbe 만으로 결정적이라 단위 테스트가 쉽다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# 상태 상수
OK = "ok"
OUTDATED = "outdated"
MISSING = "missing"
UNKNOWN = "unknown"  # 존재하나 min_version 요구를 확인할 수 없음 (보수적으로 미충족)


@dataclass(frozen=True)
class Requirement:
    """점검 대상 1개의 명세."""

    name: str
    kind: str  # "scanner" | "runtime" | "resource"
    purpose: str
    install_hint: str
    min_version: tuple[int, ...] | None = None
    version_regex: str | None = None
    optional: bool = False


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
        if req.min_version:
            if version is None:
                satisfies = False
                state = UNKNOWN
            elif _parse_version(version) < req.min_version:
                satisfies = False
                state = OUTDATED

        statuses.append(ToolStatus(req, True, version, satisfies, state))
    return DoctorReport(statuses)
