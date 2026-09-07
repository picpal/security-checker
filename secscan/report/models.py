"""보고서 워크북 모델(spec §6). Finding 은 건드리지 않는다 — 파생·해석·결과는 별도 frozen dataclass."""
from __future__ import annotations

from dataclasses import dataclass

ACTIONS = ("upgrade", "externalize-secret", "sanitize-html", "replace-api", "config-change", "code-fix", "confirm-only")

OWNER_AUTO = "자동 수정(LLM)"
OWNER_AUTO_LOW = "자동 수정 가능(LLM, 비차단)"
OWNER_HUMAN = "사람 확인 후"
OWNER_NONE = "조치 불필요(모니터링)"
OWNER_SUPPRESSED = "억제됨"
OWNERS = (OWNER_AUTO, OWNER_AUTO_LOW, OWNER_HUMAN, OWNER_NONE, OWNER_SUPPRESSED)

PRIORITIES = ("P1", "P2", "P3", "P4", "P5")
RESULT_STATUSES = ("fixed", "skipped", "needs_confirmation")


@dataclass(frozen=True)
class KbEntry:
    name: str  # 일반어 문제 이름
    what: str  # 무엇이 문제인가
    why: str  # 왜 위험한가
    how: str  # 해야 할 일
    action: str  # ACTIONS 중 하나
    ctx: bool  # 코드 문맥 확인이 필요한가(True 면 담당 = 사람 확인 후)
    confirm: str = ""  # ctx 일 때 사람에게 던질 질문
    done: str = ""  # 완료 확인 문장({id}·{package} 치환)
    source: str = "composed"  # rules.json | composed


@dataclass(frozen=True)
class Derived:
    priority: str
    owner: str
    basis: str  # 판정 근거 한 줄
    group: str  # "G-n" 또는 ""
    done: str
    where: str  # 상대경로:줄 또는 package@version
    deppath: str = ""  # 의존 경로(Task 6)


@dataclass(frozen=True)
class Interpretation:
    guess: str  # 추정(Claude 해석)
    check: str  # 확인 방법
    cites: tuple[str, ...] = ()  # "경로:줄" 또는 "경로:줄-줄"


@dataclass(frozen=True)
class ResultRow:
    id: str
    status: str  # RESULT_STATUSES
    changed_files: str = ""
    verification: str = ""
    reason: str = ""
    commit: str = ""
