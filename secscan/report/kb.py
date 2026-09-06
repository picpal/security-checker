"""룰 지식베이스(spec §5.1): rules.json 덮어쓰기 > 룰 메타·CWE 표 합성 폴백. 스캔 시점 LLM 생성 없음."""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from ..models import Finding
from .models import ACTIONS, KbEntry

KB_DIR = Path(__file__).parent / "kb"
NO_CWE_WHY = "도구가 CWE 를 주지 않아 위험 설명이 없음(지식베이스 등록 필요)"
_SCA_WHY = "공개된 취약점(CVE)으로 공격 방법이 알려져 있음. 도달성 판정과 근거 유무는 '판정 근거' 열 참조 — evidence 가 없으면 강등 근거가 약함"
_SAST_CONFIRM = "탐지된 값·흐름이 실제로 외부 입력 또는 비밀값에 해당하는가?"
_SAST_DONE = "재스캔 findings.json 에 이 ID 부재 또는 사람 확인 후 억제(사유·증거 기록)"
_SECRET = dict(
    name="노출된 비밀값 형태 문자열",
    what="API 키·비밀번호로 보이는 문자열이 파일에 그대로 적혀 있음",
    why="저장소 접근자 누구나 볼 수 있고, 실제 값이면 그 계정·서비스가 즉시 위험해짐",
    how="실제 값이면 즉시 폐기·교체 후 파일과 이력에서 제거. 테스트용 예시값이면 <YOUR_PASSWORD> 같은 자리표시자로 바꾸고 같은 줄에 `# gitleaks:allow` 표시",
    action="externalize-secret", ctx=True,
    confirm="해당 줄의 값이 실제 계정에서 쓰이는 비밀값인가, 테스트용 예시값인가?",
    done="재스캔 findings.json 에 이 ID 부재",
)
_REQUIRED = ("name", "what", "why", "how", "action", "ctx", "done")
_NUM = re.compile(r"\d+")


def _load(name: str) -> dict:
    return json.loads((KB_DIR / name).read_text(encoding="utf-8"))


@lru_cache(maxsize=None)
def load_rules() -> dict:
    return _load("rules.json")


@lru_cache(maxsize=None)
def load_cwe() -> dict:
    return _load("cwe.json")


@lru_cache(maxsize=None)
def load_bom_props() -> dict:
    return _load("bom_props.json")


def validate_rules(rules: dict) -> list[str]:
    errs: list[str] = []
    for rid, e in rules.items():
        missing = [k for k in _REQUIRED if k not in e]
        if missing:
            errs.append(f"{rid}: 필드 누락 {missing}")
            continue
        if e["action"] not in ACTIONS:
            errs.append(f"{rid}: action 미허용 {e['action']!r}")
        if e["ctx"] and not e.get("confirm"):
            errs.append(f"{rid}: ctx=true 인데 confirm 없음")
    return errs


def _vkey(v: str):
    nums = [int(x) for x in _NUM.findall(v)]
    return (0, nums) if nums else (1, [])  # 파싱 불가 문자열은 뒤로


def target_version(installed: str, fixed: tuple[str, ...]) -> str | None:
    if not fixed:
        return None
    major = installed.split(".")[0]
    same = [v for v in fixed if v.split(".")[0] == major]
    return min(same or fixed, key=_vkey)


def _artifact(package: str) -> str:
    return package.split(":")[-1]


def _bom_prop(package: str, bom_props: dict) -> str | None:
    for prefix in sorted(bom_props, key=len, reverse=True):
        if package.startswith(prefix):
            return bom_props[prefix]
    return None


def _sca_entry(f: Finding, bom_props: dict) -> KbEntry:
    pkg, ver = f.component.package, f.component.version
    target = target_version(ver, f.advisory.fixed_versions if f.advisory else ())
    if target is None:
        how = f"{pkg} 의 수정 버전이 공개되지 않음 — 벤더 공지를 추적하고 노출면을 줄인다"
        done = "수정 버전 공개 후 업그레이드, 재스캔 findings.json 에 이 ID 부재"
    else:
        prop = _bom_prop(pkg, bom_props)
        hint = f". Spring Boot BOM 경유면 빌드 스크립트에 {prop} = '{target}' 지정" if prop else ""
        how = f"{pkg} 를 {target} 이상으로 올림{hint}"
        done = f"재스캔 findings.json 에 이 ID 부재 + {_artifact(pkg)} 설치 버전 ≥ {target}"
    return KbEntry(name=f"{_artifact(pkg)} 알려진 취약점 {f.rule_id}", what=f.title or f.rule_id, why=_SCA_WHY,
                   how=how, action="upgrade", ctx=False, confirm="", done=done, source="composed")


def _sast_entry(f: Finding, cwe: dict) -> KbEntry:
    c = cwe.get(f.cwe[0]) if f.cwe else None
    name = c["name"] if c else f.rule_id.rsplit(".", 1)[-1]
    how = c["fix"] if c else "룰 설명을 확인해 수정"
    if f.references:
        how += "\n참고: " + ", ".join(f.references)
    return KbEntry(name=name, what=f.title or f.rule_id, why=c["why"] if c else NO_CWE_WHY, how=how,
                   action="code-fix", ctx=True, confirm=_SAST_CONFIRM, done=_SAST_DONE, source="composed")


def entry_for(f: Finding, *, rules: dict | None = None, cwe: dict | None = None, bom_props: dict | None = None) -> KbEntry:
    rules = load_rules() if rules is None else rules
    cwe = load_cwe() if cwe is None else cwe
    bom_props = load_bom_props() if bom_props is None else bom_props
    r = rules.get(f.rule_id)
    if r is not None:
        return KbEntry(name=r["name"], what=r["what"], why=r["why"], how=r["how"], action=r["action"], ctx=bool(r["ctx"]),
                       confirm=r.get("confirm", ""), done=r.get("done", ""), source="rules.json")
    if f.category == "sca" and f.component is not None:
        return _sca_entry(f, bom_props)
    if f.category == "secret":
        return KbEntry(**_SECRET, source="composed")
    return _sast_entry(f, cwe)
