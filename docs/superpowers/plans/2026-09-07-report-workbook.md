# 사람·LLM 겸용 점검 보고서 워크북 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `secscan scan` 산출물에 네 독자(경영·보안·개발·수정 LLM)가 읽고 결정할 수 있는 5 시트 워크북 `report.xlsx` 를 추가하고, Claude 해석 파일 인터페이스·검증기와 LLM 결과 반환 검증기를 붙인다.

**Architecture:** `secscan/report/` 패키지 신설(코어 무변경). 룰 지식베이스(JSON, 결정적 합성 폴백) → 파생 규칙(우선순위·담당·근거·그룹·의존 경로) → 시트 빌더(기존 `output/xlsx.py` 의 sanitize·write 재사용). Claude 해석은 `report-request.json` → `interpretations.json` 파일로만 오가며 검증기 통과분만 병합된다. `secscan report` 서브커맨드가 워크북 재생성과 결과 검증을 맡는다.

**Tech Stack:** Python 3.11+ stdlib, openpyxl(extra `xlsx`, 지연 import), pytest.

**Spec:** `docs/superpowers/specs/2026-09-07-report-workbook-design.md` (상위: `2026-06-26-jvm-security-scanner-design.md` §5.6·§5.7, `2026-09-04-verification-campaign-design.md` §4.5)

## Global Constraints

- `dependencies = []` 유지. openpyxl 은 `[project.optional-dependencies] xlsx` 로만, 라이터에서 지연 import. 없으면 CSV 번들 폴백.
- 결정성: 동일 입력(findings.json + bom + interpretations.json) → 동일 워크북. xlsx 저장은 `secscan.output.xlsx.write_xlsx`(created 고정·modified 재기록) 만 사용.
- LLM 비의존 실행: 해석 파일이 없어도 완성 보고서. CLI 는 네트워크·API 키를 요구하지 않는다. `scan` 의 exit code 는 보고서 유무·내용과 무관하게 불변.
- 수치·판정·담당·우선순위는 규칙 파생·템플릿 치환만. 사람도 LLM 도 손으로 쓰지 않는다. 설명 문장은 지식베이스(코드)에 있고 골든 대상이다. 스캔 시점 LLM 생성 없음.
- 자동 억제 금지: 어떤 코드 경로도 suppressions 파일을 쓰거나 고치지 않는다.
- 비밀값 미노출: secret finding 은 `location`(파일·줄) 만 읽는다. request 파일에 코드 스니펫을 넣지 않는다.
- 코어 무변경: `Finding`·`json_io`·`disposition`·`scan.py`·`output/xlsx.py` 를 수정하지 않는다. `secscan/cli.py` 는 서브커맨드 등록·scan 끝의 호출·findings.json meta 에 `run_date` 추가만.
- 경로: 워크북·request 의 파일 경로는 `--target` 기준 상대경로. 절대경로가 들어오면 target 접두를 벗긴다.
- 모든 셀은 `secscan.output.xlsx.sanitize_cell` 을 거친다. UI 문자열은 한국어.
- 추정(Claude) 칸은 항상 사실 칸과 다른 열이며 "확인 방법"·"인용" 이 따라붙는다. 검증기 거부분은 빈 칸 + 0_요약 사유 기록.
- 테스트: `.venv/bin/pytest`. TDD(실패 확인 → 구현 → 통과). 커밋 메시지 마지막 줄 `다음: <할 일>`.
- 픽스처 `fixtures/report/work-note-findings.json`(15건, 상대경로)·`fixtures/report/work-note-bom.cdx.json` 은 읽기만 한다(재생성 금지 — advisory DB 가 바뀌면 값이 달라진다).

---

## File Structure

| 파일 | 책임 |
|---|---|
| `secscan/report/__init__.py` | 패키지 표식(빈 파일) |
| `secscan/report/models.py` | `KbEntry`·`Derived`·`Interpretation`·`ResultRow` frozen dataclass, `ACTIONS`·담당/우선순위/status 상수 |
| `secscan/report/kb.py` | 지식베이스 로드·검증·합성 폴백, `entry_for(finding)`, `target_version()` |
| `secscan/report/kb/rules.json` | 손으로 쓴 룰 설명 12건 |
| `secscan/report/kb/cwe.json` | CWE → 한글 이름·왜 위험·일반 수정 20건 |
| `secscan/report/kb/bom_props.json` | 패키지 접두 → Spring Boot gradle 속성명 14건 |
| `secscan/report/derive.py` | 우선순위·담당·판정 근거·위치·그룹·완료 확인·결론 문단·정렬·확인질문 대상 판정 |
| `secscan/report/deppath.py` | CycloneDX 의존 그래프 → `직접` / `전이 ← A ← B` 문자열 |
| `secscan/report/interpret.py` | request 생성, response 검증(거부 사유 enum), 로드 |
| `secscan/report/workbook.py` | 5 시트 빌더(순수) + `write_report`(xlsx/CSV) |
| `secscan/report/result_check.py` | 결과 반환(JSON/xlsx) ↔ 재스캔 findings.json 대조 |
| `secscan/report/cli.py` | `report` 서브파서, `build_report`, `write_report_bundle`, `cmd_report` |
| `secscan/cli.py` (수정) | 서브파서 등록, scan 끝 `write_report_bundle` 호출, findings.json meta `run_date` |
| `pyproject.toml` (수정) | `[tool.setuptools.package-data] secscan = ["report/kb/*.json"]` |
| `tests/test_report_models.py` … `tests/test_report_result_check.py` | 모듈별 테스트 |
| `tests/golden/report-work-note-sheets.json` | 5 시트 골든(Task 4 생성, Task 7 재생성) |

픽스처 finding id(상대경로 기준, 고정):

| id | 카테고리 | 위치 | disposition/tier |
|---|---|---|---|
| 356e4bbab00c | sast high | backend/src/main/java/com/worknote/admin/BreakGlassFile.java:88 (secscan.rules.hardcoded-credential) | actionable/actionable |
| 3470199a0f48 | sast medium | docs/design-handoff/prototype/icons.jsx:76 (react-dangerouslysetinnerhtml) | actionable/actionable |
| 3db4c52c28e5 · 9744de7de162 · 57f818868bca | sast medium | docs/design-handoff/prototype/tweaks-panel.jsx:182 · :236 · :242 (wildcard-postmessage) | actionable/actionable |
| 58ed62d06bb5 · 6c4480dfa2aa | sast medium | frontend/src/components/RedmineImportPanel.tsx:238 · :239 (react-dangerouslysetinnerhtml) | actionable/actionable |
| 553c0d6307df · f4c0abc746cf · acc9f3f49628 | sast unknown | frontend/pnpm-workspace.yaml:1 (pnpm-block-exotic-sub-dependencies · pnpm-minimum-release-age · pnpm-trust-policy) | review/review |
| 0442ba114c70 · 20f2b757fb2c · e0d713155712 | sca critical | org.apache.tomcat.embed:tomcat-embed-core@10.1.55 (CVE-2026-65182 · 65905 · 68525, fixed 11.0.25/10.1.58/9.0.121) | demoted |
| cae6cff5ca45 | sca medium | org.apache.logging.log4j:log4j-api@2.24.3 (CVE-2026-49844, fixed 2.25.5/2.26.1) | demoted |
| 108d8ee4651c | secret high | docs/qa-e2e-scenarios.md:43 (generic-api-key) | actionable |

---

### Task 1: 모델·패키지 데이터·픽스처 로드

**Files:**
- Create: `secscan/report/__init__.py`, `secscan/report/models.py`
- Modify: `pyproject.toml` (`[tool.setuptools.packages.find]` 아래에 package-data 절 추가)
- Test: `tests/test_report_models.py`

**Interfaces:**
- Produces: `ACTIONS`, `OWNER_AUTO`, `OWNER_AUTO_LOW`, `OWNER_HUMAN`, `OWNER_NONE`, `OWNER_SUPPRESSED`, `PRIORITIES`, `RESULT_STATUSES`, `KbEntry(name, what, why, how, action, ctx, confirm="", done="", source="composed")`, `Derived(priority, owner, basis, group, done, where, deppath="")`, `Interpretation(guess, check, cites=())`, `ResultRow(id, status, changed_files="", verification="", reason="", commit="")`

- [ ] **Step 1: 실패하는 테스트**

```python
# tests/test_report_models.py
"""보고서 모델(spec §6) — 상수 닫힌 집합, 픽스처가 상대경로·비밀값 없이 로드된다."""
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from secscan.output.json_io import from_json
from secscan.report.models import (ACTIONS, OWNER_AUTO, OWNER_HUMAN, PRIORITIES, RESULT_STATUSES, Derived,
                                   Interpretation, KbEntry, ResultRow)

FIX = Path("fixtures/report/work-note-findings.json")


def test_constants_are_closed_sets():
    assert ACTIONS == ("upgrade", "externalize-secret", "sanitize-html", "replace-api", "config-change", "code-fix", "confirm-only")
    assert PRIORITIES == ("P1", "P2", "P3", "P4", "P5")
    assert RESULT_STATUSES == ("fixed", "skipped", "needs_confirmation")
    assert OWNER_AUTO == "자동 수정(LLM)" and OWNER_HUMAN == "사람 확인 후"


def test_models_are_frozen_with_defaults():
    e = KbEntry("n", "w", "y", "h", "upgrade", False)
    assert e.confirm == "" and e.done == "" and e.source == "composed"
    with pytest.raises(FrozenInstanceError):
        e.name = "x"
    assert Derived("P1", OWNER_HUMAN, "b", "", "d", "w").deppath == ""
    assert Interpretation("g", "c").cites == ()
    assert ResultRow("abc", "fixed").commit == ""


def test_fixture_loads_relative_paths_and_no_secret_values():
    text = FIX.read_text(encoding="utf-8")
    fs = from_json(text)
    assert len(fs) == 15
    assert "/Users/" not in text and "pend-" not in text and "ghp_" not in text
    assert all(not f.location.file.startswith("/") for f in fs if f.location)
    assert {f.id for f in fs} >= {"356e4bbab00c", "108d8ee4651c", "0442ba114c70"}
```

- [ ] **Step 2: 실패 확인**

Run: `.venv/bin/pytest tests/test_report_models.py -v`
Expected: FAIL `ModuleNotFoundError: No module named 'secscan.report'`

- [ ] **Step 3: 구현**

`secscan/report/__init__.py` 는 빈 파일.

```python
# secscan/report/models.py
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
```

`pyproject.toml` 의 `[tool.setuptools.packages.find]` 절 바로 아래에 추가:

```toml
[tool.setuptools.package-data]
secscan = ["report/kb/*.json"]
```

- [ ] **Step 4: 통과 확인**

Run: `.venv/bin/pytest tests/test_report_models.py -v`
Expected: 3 passed

- [ ] **Step 5: 커밋**

```bash
git add secscan/report/__init__.py secscan/report/models.py pyproject.toml tests/test_report_models.py
git commit -m "feat(report): 보고서 모델·상수(KbEntry/Derived/Interpretation/ResultRow) + kb 패키지 데이터 등록

다음: 지식베이스 kb.py + rules/cwe/bom_props JSON"
```

---

### Task 2: 지식베이스 (`kb.py` + JSON 3종)

**Files:**
- Create: `secscan/report/kb.py`, `secscan/report/kb/rules.json`, `secscan/report/kb/cwe.json`, `secscan/report/kb/bom_props.json`
- Test: `tests/test_report_kb.py`

**Interfaces:**
- Consumes: `KbEntry`, `ACTIONS` (Task 1); `Finding`(`rule_id`, `category`, `title`, `cwe`, `references`, `component.package/version`, `advisory.fixed_versions`)
- Produces: `load_rules() -> dict`, `load_cwe() -> dict`, `load_bom_props() -> dict`, `validate_rules(rules: dict) -> list[str]`, `target_version(installed: str, fixed: tuple[str, ...]) -> str | None`, `entry_for(f: Finding, *, rules=None, cwe=None, bom_props=None) -> KbEntry`

- [ ] **Step 1: 실패하는 테스트**

```python
# tests/test_report_kb.py
"""지식베이스(spec §5.1) — rules.json 덮어쓰기 > 합성 폴백. 스캔 시점 생성 없음. 문장은 골든 대상."""
from pathlib import Path

from secscan.models import Advisory, Component, Finding, Location
from secscan.output.json_io import from_json
from secscan.report.kb import entry_for, load_bom_props, load_cwe, load_rules, target_version, validate_rules
from secscan.report.models import ACTIONS

FS = {f.id: f for f in from_json(Path("fixtures/report/work-note-findings.json").read_text(encoding="utf-8"))}


def test_shipped_rules_json_validates_and_covers_custom_and_work_note_rules():
    rules = load_rules()
    assert validate_rules(rules) == []
    assert {"secscan.rules.hardcoded-credential", "secscan.rules.mybatis-sqli-value", "secscan.rules.mybatis-sqli-identifier",
            "secscan.rules.zero-salt", "generic-api-key"} <= set(rules)
    assert all(r["action"] in ACTIONS for r in rules.values())


def test_validate_rules_reports_bad_action_and_missing_confirm():
    bad = {"r1": {"name": "n", "what": "w", "why": "y", "how": "h", "action": "delete-it", "ctx": False, "done": "d"},
           "r2": {"name": "n", "what": "w", "why": "y", "how": "h", "action": "code-fix", "ctx": True, "done": "d"},
           "r3": {"name": "n"}}
    errs = validate_rules(bad)
    assert any("r1" in e and "delete-it" in e for e in errs)
    assert any("r2" in e and "confirm" in e for e in errs)
    assert any("r3" in e and "누락" in e for e in errs)


def test_target_version_prefers_same_major_minimum():
    assert target_version("10.1.55", ("11.0.25", "10.1.58", "9.0.121")) == "10.1.58"
    assert target_version("2.24.3", ("2.25.5", "2.26.1")) == "2.25.5"
    assert target_version("1.0", ("2.0",)) == "2.0"
    assert target_version("1.0", ("2.0", "unknown")) == "2.0"
    assert target_version("1.0", ()) is None


def test_hand_written_rule_wins_over_composition():
    e = entry_for(FS["356e4bbab00c"])
    assert e.source == "rules.json" and e.action == "externalize-secret" and e.ctx is True and e.confirm


def test_sca_composed_entry_has_target_and_bom_hint():
    e = entry_for(FS["0442ba114c70"])
    assert e.source == "composed" and e.action == "upgrade" and e.ctx is False
    assert e.name == "tomcat-embed-core 알려진 취약점 CVE-2026-65182"
    assert "10.1.58" in e.how and "ext['tomcat.version']" in e.how
    assert e.done == "재스캔 findings.json 에 이 ID 부재 + tomcat-embed-core 설치 버전 ≥ 10.1.58"
    assert "2.25.5" in entry_for(FS["cae6cff5ca45"]).how and "ext['log4j2.version']" in entry_for(FS["cae6cff5ca45"]).how


def test_sca_without_fixed_version_says_so():
    f = Finding(category="sca", severity="high", title="T", tool="trivy", rule_id="CVE-0",
                component=Component("maven", "a:b", "1.0"), advisory=Advisory("CVE-0"))
    e = entry_for(f, rules={}, cwe={}, bom_props={})
    assert "수정 버전이 공개되지 않음" in e.how and e.action == "upgrade"


def test_unknown_sast_rule_composes_from_cwe_table_and_is_conservative():
    f = Finding(category="sast", severity="medium", title="Rule message here", tool="semgrep", rule_id="x.y.some-rule",
                cwe=("CWE-79",), references=("https://ref/1",), location=Location("a.js", 1))
    e = entry_for(f, rules={})
    assert e.source == "composed" and e.ctx is True and e.action == "code-fix"
    assert e.name == load_cwe()["CWE-79"]["name"] and e.what == "Rule message here"
    assert "https://ref/1" in e.how and e.confirm


def test_unknown_sast_rule_without_cwe_uses_fixed_sentence():
    f = Finding(category="sast", severity="low", title="", tool="semgrep", rule_id="x.y.no-cwe", location=Location("a.js", 1))
    e = entry_for(f, rules={})
    assert e.name == "no-cwe" and e.why == "도구가 CWE 를 주지 않아 위험 설명이 없음(지식베이스 등록 필요)" and e.what == "x.y.no-cwe"


def test_secret_entry_is_hand_written_for_known_rule_and_composed_otherwise():
    assert entry_for(FS["108d8ee4651c"]).source == "rules.json"
    f = Finding(category="secret", severity="high", title="t", tool="gitleaks", rule_id="unknown-secret-rule", location=Location("a", 1))
    e = entry_for(f, rules={})
    assert e.action == "externalize-secret" and e.ctx is True and e.source == "composed"


def test_cwe_and_bom_tables_shape():
    cwe = load_cwe()
    assert {"CWE-79", "CWE-89", "CWE-798", "CWE-345", "CWE-829", "CWE-116", "CWE-863"} <= set(cwe)
    assert all({"name", "why", "fix"} <= set(v) for v in cwe.values())
    props = load_bom_props()
    assert props["org.apache.tomcat.embed:"] == "ext['tomcat.version']" and props["org.apache.logging.log4j:"] == "ext['log4j2.version']"
```

- [ ] **Step 2: 실패 확인**

Run: `.venv/bin/pytest tests/test_report_kb.py -v`
Expected: FAIL `ModuleNotFoundError: No module named 'secscan.report.kb'`

- [ ] **Step 3: JSON 데이터 작성**

`secscan/report/kb/bom_props.json` (긴 접두가 먼저 매칭되도록 코드에서 길이순 정렬):

```json
{
  "org.apache.tomcat.embed:": "ext['tomcat.version']",
  "org.apache.tomcat:": "ext['tomcat.version']",
  "org.apache.logging.log4j:": "ext['log4j2.version']",
  "ch.qos.logback:": "ext['logback.version']",
  "com.fasterxml.jackson": "ext['jackson-bom.version']",
  "org.springframework:": "ext['spring-framework.version']",
  "org.springframework.security:": "ext['spring-security.version']",
  "org.hibernate.orm:": "ext['hibernate.version']",
  "org.postgresql:": "ext['postgresql.version']",
  "com.mysql:": "ext['mysql.version']",
  "org.yaml:snakeyaml": "ext['snakeyaml.version']",
  "io.netty:": "ext['netty.version']",
  "org.apache.commons:commons-lang3": "ext['commons-lang3.version']",
  "org.slf4j:": "ext['slf4j.version']"
}
```

`secscan/report/kb/cwe.json`:

```json
{
  "CWE-79":  {"name": "검사 없이 HTML 을 화면에 삽입 (XSS 가능성)", "why": "외부 입력이 섞인 HTML 이 그대로 그려지면 공격자가 스크립트를 심어 다른 사용자의 브라우저에서 실행시킬 수 있음(XSS)", "fix": "외부 입력은 텍스트로 렌더링하거나 DOMPurify 등으로 정화한 뒤 삽입"},
  "CWE-89":  {"name": "SQL 삽입", "why": "사용자 입력이 SQL 문장으로 해석되어 데이터 유출·변조·인증 우회가 가능", "fix": "바인딩 파라미터(#{}·PreparedStatement)로 값을 전달하고 식별자는 허용 목록으로 제한"},
  "CWE-78":  {"name": "운영체제 명령어 삽입", "why": "입력이 셸 명령에 섞여 서버에서 임의 명령이 실행될 수 있음", "fix": "셸을 거치지 않는 API 로 인자 배열을 전달하고 입력을 허용 목록으로 검증"},
  "CWE-22":  {"name": "경로 조작", "why": "입력으로 만든 파일 경로가 의도한 디렉토리 밖을 가리켜 임의 파일을 읽거나 쓸 수 있음", "fix": "정규화한 경로가 기준 디렉토리 아래인지 확인하고 파일명은 허용 목록으로 제한"},
  "CWE-94":  {"name": "코드 삽입", "why": "입력이 코드로 평가되어 임의 로직이 실행될 수 있음", "fix": "동적 코드 평가를 제거하거나 입력을 데이터로만 다룸"},
  "CWE-798": {"name": "소스코드에 박힌 자격증명", "why": "저장소를 볼 수 있는 사람 누구나 값을 알게 되고, 커밋 이력에 남아 나중에 지워도 회수되지 않음", "fix": "환경변수·시크릿 매니저·외부 설정으로 옮기고 노출된 값은 폐기·교체"},
  "CWE-259": {"name": "소스코드에 박힌 비밀번호", "why": "비밀번호가 코드와 함께 배포·공유되어 회수가 불가능", "fix": "외부 설정으로 옮기고 노출된 비밀번호는 즉시 변경"},
  "CWE-345": {"name": "출처 검증 없는 데이터 수신·송신", "why": "메시지를 주고받는 상대의 출처를 확인하지 않아 다른 사이트가 데이터를 받거나 보낼 수 있음", "fix": "postMessage 의 targetOrigin 을 실제 출처로 고정하고 수신 시 event.origin 을 검사"},
  "CWE-829": {"name": "신뢰되지 않은 출처의 기능 포함", "why": "검증되지 않은 외부 패키지·스크립트가 끼어들어 공급망 공격 통로가 됨", "fix": "패키지 매니저의 신뢰·지연 설정을 켜고 출처를 레지스트리로 제한"},
  "CWE-116": {"name": "출력 인코딩 오류", "why": "출력 시 특수문자를 잘못 인코딩해 로그·JSON 이 위변조되거나 다른 시스템에서 잘못 해석될 수 있음", "fix": "출력 형식에 맞는 인코더를 쓰고 라이브러리를 수정 버전으로 올림"},
  "CWE-284": {"name": "부적절한 접근 제어", "why": "권한 검사가 빠지거나 우회되어 허가되지 않은 자원에 접근할 수 있음", "fix": "모든 진입점에서 인가를 검사하고 라이브러리를 수정 버전으로 올림"},
  "CWE-863": {"name": "잘못된 인가 판단", "why": "인가 검사가 있으나 조건이 틀려 권한 밖 자원에 접근할 수 있음", "fix": "인가 규칙을 재검토하고 라이브러리를 수정 버전으로 올림"},
  "CWE-294": {"name": "재전송 공격에 취약한 인증", "why": "가로챈 인증 정보를 다시 보내 인증을 통과할 수 있음", "fix": "1회용 토큰·타임스탬프를 쓰고 라이브러리를 수정 버전으로 올림"},
  "CWE-502": {"name": "신뢰되지 않은 데이터 역직렬화", "why": "외부에서 온 직렬화 데이터를 복원하면서 임의 코드가 실행될 수 있음", "fix": "역직렬화 대상을 허용 목록으로 제한하거나 JSON 같은 데이터 전용 형식으로 교체"},
  "CWE-611": {"name": "XML 외부 개체 참조(XXE)", "why": "XML 파서가 외부 개체를 해석해 서버 파일을 읽거나 내부 네트워크에 접근할 수 있음", "fix": "파서에서 외부 개체·DTD 해석을 끔"},
  "CWE-601": {"name": "검증 없는 리다이렉트", "why": "입력으로 만든 이동 주소가 피싱 사이트로 사용자를 보낼 수 있음", "fix": "이동 주소를 허용 목록이나 상대 경로로 제한"},
  "CWE-327": {"name": "취약한 암호 알고리즘", "why": "깨진 알고리즘(MD5·SHA1·DES 등)은 실용적 시간 안에 역산·충돌 생성이 가능", "fix": "SHA-256 이상·AES-GCM·Argon2/bcrypt 로 교체"},
  "CWE-330": {"name": "예측 가능한 난수·고정 salt", "why": "같은 입력이 항상 같은 결과가 되어 미리 계산한 표로 역산 가능", "fix": "SecureRandom 으로 값마다 다른 salt·nonce 생성"},
  "CWE-352": {"name": "CSRF", "why": "로그인된 사용자의 브라우저를 이용해 본인 모르게 요청을 보낼 수 있음", "fix": "CSRF 토큰·SameSite 쿠키를 적용"},
  "CWE-200": {"name": "민감 정보 노출", "why": "오류 메시지·응답·로그에 내부 정보나 개인정보가 드러남", "fix": "노출 항목을 제거하고 오류는 일반 메시지로 대체"}
}
```

`secscan/report/kb/rules.json` (12건 — 커스텀 4 + work-note 발화 8):

```json
{
  "secscan.rules.hardcoded-credential": {
    "name": "소스코드에 박힌 자격증명",
    "what": "비밀번호·API 키 같은 비밀값이 소스코드 안에 문자열로 직접 들어 있음",
    "why": "저장소를 볼 수 있는 사람 누구나 그 값을 알게 되고, 한 번 커밋되면 이력에 남아 나중에 지워도 회수되지 않음",
    "how": "값을 환경변수·시크릿 매니저·외부 설정 파일로 옮기고, 이미 노출된 값은 폐기(revoke)하고 새 값으로 교체",
    "action": "externalize-secret", "ctx": true,
    "confirm": "해당 줄의 문자열이 실제 비밀번호/키인가, 아니면 'password' 같은 필드 이름인가?",
    "done": "재스캔 findings.json 에 이 ID 부재 + 해당 줄에 비밀값 리터럴 없음"
  },
  "secscan.rules.mybatis-sqli-value": {
    "name": "MyBatis 값 자리 문자열 치환(${})으로 SQL 조립 (SQL 삽입)",
    "what": "MyBatis 매퍼에서 값 자리에 #{} 대신 ${} 를 써 입력이 SQL 문장에 그대로 붙음",
    "why": "사용자 입력이 SQL 로 해석되어 데이터 유출·변조·인증 우회가 가능(SQL 삽입)",
    "how": "값 자리는 #{} 로 바꿔 바인딩 파라미터로 전달",
    "action": "code-fix", "ctx": false, "confirm": "",
    "done": "재스캔 findings.json 에 이 ID 부재"
  },
  "secscan.rules.mybatis-sqli-identifier": {
    "name": "MyBatis 식별자 자리 문자열 치환(${}) (SQL 삽입 가능성)",
    "what": "테이블·컬럼·정렬 기준 같은 식별자 자리에 ${} 를 써 입력이 SQL 구조에 들어감",
    "why": "식별자는 바인딩할 수 없어 입력이 사용자에게서 오면 SQL 삽입이 됨. 코드 상수에서만 오면 위험 없음",
    "how": "값의 출처를 코드 상수·허용 목록(enum, Map)으로 제한하고 그 밖의 값은 거부",
    "action": "code-fix", "ctx": true,
    "confirm": "해당 식별자 값이 코드 상수·허용 목록에서만 오는가, 사용자 입력에서 오는가?",
    "done": "재스캔 findings.json 에 이 ID 부재 또는 사람 확인 후 억제(사유: 허용 목록 상수, 증거: 출처 코드 줄)"
  },
  "secscan.rules.zero-salt": {
    "name": "고정·빈 salt 로 비밀번호 해시",
    "what": "PBKDF2·해시 함수에 길이 0 또는 상수 salt 를 사용",
    "why": "같은 비밀번호가 항상 같은 해시가 되어 미리 계산한 표(레인보우 테이블)로 역산 가능",
    "how": "SecureRandom 으로 16바이트 이상 salt 를 생성해 해시마다 다르게 만들고 해시와 함께 저장",
    "action": "code-fix", "ctx": true,
    "confirm": "이미 저장된 해시를 새 방식으로 재해시(마이그레이션)하는 경로가 있는가?",
    "done": "재스캔 findings.json 에 이 ID 부재"
  },
  "generic-api-key": {
    "name": "문서/코드에 노출된 키·비밀번호 형태 문자열",
    "what": "API 키·비밀번호로 보이는 문자열이 파일에 그대로 적혀 있음",
    "why": "저장소 접근자 누구나 볼 수 있고, 실제 값이면 그 계정·서비스가 즉시 위험해짐",
    "how": "실제 값이면 즉시 폐기·교체 후 파일과 이력에서 제거. 테스트용 예시값이면 <YOUR_PASSWORD> 같은 자리표시자로 바꾸고 같은 줄에 `# gitleaks:allow` 표시",
    "action": "externalize-secret", "ctx": true,
    "confirm": "해당 줄의 값이 실제 계정에서 쓰이는 비밀번호인가, 테스트용 예시값인가?",
    "done": "재스캔 findings.json 에 이 ID 부재"
  },
  "typescript.react.security.audit.react-dangerouslysetinnerhtml.react-dangerouslysetinnerhtml": {
    "name": "검사 없이 HTML 을 화면에 삽입 (XSS 가능성)",
    "what": "React 의 dangerouslySetInnerHTML 로 HTML 문자열을 그대로 화면에 그림",
    "why": "그 문자열에 사용자·외부 입력이 섞이면 공격자가 스크립트를 심어 다른 사용자의 브라우저에서 실행시킬 수 있음(XSS)",
    "how": "삽입되는 HTML 이 외부 입력에서 오면 DOMPurify 등으로 정화한 뒤 삽입. 이미 정화되거나 고정 문자열이면 위험 없음(정화 근거만 기록)",
    "action": "sanitize-html", "ctx": true,
    "confirm": "삽입되는 HTML 값의 출처는 무엇이고, 정화(sanitize)를 거치는가?",
    "done": "재스캔 findings.json 에 이 ID 부재(정화 래핑) 또는 사람 확인 후 억제(사유·증거 기록)"
  },
  "javascript.browser.security.wildcard-postmessage-configuration.wildcard-postmessage-configuration": {
    "name": "창 간 메시지 수신처를 '*'(아무 사이트)로 지정",
    "what": "window.postMessage 를 보낼 때 받는 쪽 출처(targetOrigin)를 '*' 로 지정",
    "why": "이 창을 연 사이트가 어디든 메시지 내용을 받을 수 있어, 편집 데이터가 다른 출처로 샐 수 있음",
    "how": "targetOrigin 을 실제 부모 창 출처(예: https://app.example.com)로 고정",
    "action": "replace-api", "ctx": true,
    "confirm": "부모 창의 정확한 출처(origin)는 무엇인가? 이 파일이 배포되는 코드인가?",
    "done": "재스캔 findings.json 에 이 ID 부재('*' 제거)"
  },
  "package_managers.pnpm.pnpm-block-exotic-sub-dependencies.pnpm-block-exotic-sub-dependencies": {
    "name": "pnpm 공급망 보호 설정 누락 (blockExoticSubdeps)",
    "what": "하위 의존성이 git/URL 등 레지스트리 밖에서 설치되는 것을 막는 설정이 없음",
    "why": "신뢰되지 않은 출처의 패키지가 끼어드는 공급망 공격 통로가 열려 있음",
    "how": "pnpm-workspace.yaml 에 `blockExoticSubdeps: true` 추가",
    "action": "config-change", "ctx": true,
    "confirm": "설정 추가로 설치·CI 동작이 바뀌어도 되는가?",
    "done": "재스캔 findings.json 에 이 ID 부재"
  },
  "package_managers.pnpm.pnpm-missing-minimum-release-age.pnpm-minimum-release-age": {
    "name": "pnpm 공급망 보호 설정 누락 (minimumReleaseAge)",
    "what": "배포된 지 얼마 안 된 패키지 버전의 설치를 지연시키는 설정이 없음",
    "why": "악성 버전이 배포 직후(탐지 전)에 설치되는 것을 막지 못함",
    "how": "pnpm-workspace.yaml 에 `minimumReleaseAge: 1440`(분, 1일) 추가",
    "action": "config-change", "ctx": true,
    "confirm": "신규 버전 설치가 하루 지연되어도 되는가?",
    "done": "재스캔 findings.json 에 이 ID 부재"
  },
  "package_managers.pnpm.pnpm-trust-policy.pnpm-trust-policy": {
    "name": "pnpm 공급망 보호 설정 누락 (trustPolicy)",
    "what": "패키지 신뢰 수준이 낮아지는(다운그레이드) 것을 막는 설정이 없음",
    "why": "검증된 패키지가 검증되지 않은 버전으로 바뀌어도 알 수 없음",
    "how": "pnpm-workspace.yaml 에 `trustPolicy: no-downgrade` 추가",
    "action": "config-change", "ctx": true,
    "confirm": "설정 추가로 설치·CI 동작이 바뀌어도 되는가?",
    "done": "재스캔 findings.json 에 이 ID 부재"
  }
}
```

- [ ] **Step 4: `kb.py` 구현**

```python
# secscan/report/kb.py
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
```

- [ ] **Step 5: 통과 확인**

Run: `.venv/bin/pytest tests/test_report_kb.py -v`
Expected: 10 passed

- [ ] **Step 6: 커밋**

```bash
git add secscan/report/kb.py secscan/report/kb/ tests/test_report_kb.py
git commit -m "feat(report): 지식베이스 — rules.json 12건 덮어쓰기 > CWE 표·advisory 합성 폴백, target_version, BOM 속성 힌트

다음: derive.py 파생 규칙(우선순위·담당·근거·그룹)"
```

---

### Task 3: 파생 규칙 (`derive.py`)

**Files:**
- Create: `secscan/report/derive.py`
- Test: `tests/test_report_derive.py`

**Interfaces:**
- Consumes: `KbEntry`, `Derived`, `OWNER_*` (Task 1); `entry_for` (Task 2); `secscan.models.{ACTIONABLE, REVIEW, DEMOTED, SUPPRESSED, severity_rank}`; `secscan.output._status.status_rows(meta)`
- Produces: `DISP_KO`, `SEV_KO`, `priority(f) -> str`, `owner(f, kb) -> str`, `basis(f) -> str`, `where(f) -> str`, `done_text(f, kb) -> str`, `derive_all(findings, kbs: dict[str, KbEntry], deppaths: dict[str, str] | None = None) -> dict[str, Derived]`, `sort_for_report(findings, derived) -> list[Finding]`, `needs_question(f, d) -> bool`, `counts(findings, derived) -> dict`, `conclusion(c: dict, meta: dict) -> str`

- [ ] **Step 1: 실패하는 테스트**

```python
# tests/test_report_derive.py
"""파생 규칙(spec §5.2) — 표 기반, disposition 은 읽기만. 픽스처 15건으로 분포를 고정한다."""
from pathlib import Path

import pytest

from secscan.models import DEMOTED, REVIEW, Finding, Location, Reachability, Suppression
from secscan.output.json_io import from_json
from secscan.report.derive import (basis, conclusion, counts, derive_all, needs_question, owner, priority,
                                   sort_for_report, where)
from secscan.report.kb import entry_for
from secscan.report.models import (OWNER_AUTO, OWNER_AUTO_LOW, OWNER_HUMAN, OWNER_NONE, OWNER_SUPPRESSED, KbEntry)

FS = from_json(Path("fixtures/report/work-note-findings.json").read_text(encoding="utf-8"))
BY = {f.id: f for f in FS}
KBS = {f.id: entry_for(f) for f in FS}


def _kb(action="code-fix", ctx=True, done="재스캔 {id} 부재 {package}"):
    return KbEntry("n", "w", "y", "h", action, ctx, confirm="q" if ctx else "", done=done)


def _f(disposition, severity="medium", category="sast", tier=None, **kw):
    return Finding(category=category, severity=severity, title="t", tool="x", rule_id="r", disposition=disposition, tier=tier,
                   location=Location("a/b.java", 3), **kw)


@pytest.mark.parametrize("disp,sev,expect", [
    ("actionable", "critical", "P1"), ("actionable", "high", "P1"), ("actionable", "medium", "P2"), ("actionable", "unknown", "P2"),
    ("review", "high", "P3"), ("demoted", "critical", "P4"), ("suppressed", "high", "P5"), (None, "high", "P3"),
])
def test_priority_table(disp, sev, expect):
    assert priority(_f(disp, sev)) == expect


@pytest.mark.parametrize("disp,action,ctx,expect", [
    ("actionable", "code-fix", False, OWNER_AUTO), ("actionable", "code-fix", True, OWNER_HUMAN),
    ("review", "upgrade", False, OWNER_HUMAN), ("demoted", "upgrade", False, OWNER_AUTO_LOW),
    ("demoted", "code-fix", False, OWNER_NONE), ("suppressed", "upgrade", False, OWNER_SUPPRESSED), (None, "upgrade", False, OWNER_HUMAN),
])
def test_owner_table(disp, action, ctx, expect):
    assert owner(_f(disp), _kb(action, ctx)) == expect


def test_basis_sentences_per_category_and_suppression():
    assert basis(BY["356e4bbab00c"]) == "SAST · 룰 신뢰도 high → tier actionable → 조치대상"
    assert basis(BY["0442ba114c70"]) == "SCA · 도달성 unreachable(dep-scan, evidence 없음) → 강등(낮은 우선순위)"
    assert basis(BY["108d8ee4651c"]) == "Secret · 억제 없음 → 조치대상"
    sup = _f("suppressed", suppression=Suppression("suppressed", "r", "p", "e", "2026-12-31", "k", basis="unreachable"))
    assert basis(sup).startswith("억제(unreachable, 만료 2026-12-31) → SAST ·")


def test_where_and_done_substitution():
    assert where(BY["356e4bbab00c"]) == "backend/src/main/java/com/worknote/admin/BreakGlassFile.java:88"
    assert where(BY["0442ba114c70"]) == "org.apache.tomcat.embed:tomcat-embed-core@10.1.55"
    d = derive_all([BY["0442ba114c70"]], {"0442ba114c70": _kb("upgrade", False)})
    assert d["0442ba114c70"].done == "재스캔 0442ba114c70 부재 org.apache.tomcat.embed:tomcat-embed-core"


def test_fixture_distribution_is_fixed():
    d = derive_all(FS, KBS)
    assert sorted(x.priority for x in d.values()) == ["P1"] * 2 + ["P2"] * 6 + ["P3"] * 3 + ["P4"] * 4
    owners = [x.owner for x in d.values()]
    assert owners.count(OWNER_HUMAN) == 11 and owners.count(OWNER_AUTO_LOW) == 4 and owners.count(OWNER_AUTO) == 0


def test_groups_cover_same_package_target_and_same_file_rule_only():
    d = derive_all(FS, KBS)
    tomcat = {d[i].group for i in ("0442ba114c70", "20f2b757fb2c", "e0d713155712")}
    tweaks = {d[i].group for i in ("3db4c52c28e5", "9744de7de162", "57f818868bca")}
    redmine = {d[i].group for i in ("58ed62d06bb5", "6c4480dfa2aa")}
    assert len(tomcat) == 1 and len(tweaks) == 1 and len(redmine) == 1
    assert tweaks == {"G-1"} and redmine == {"G-2"} and tomcat == {"G-3"}  # 정렬 순서대로 번호
    assert d["cae6cff5ca45"].group == "" and d["553c0d6307df"].group == ""  # 단독 / 같은 파일이지만 다른 룰
    assert d["0442ba114c70"].done.endswith("(대표)") and "G-3 대표와 함께 해소" in d["20f2b757fb2c"].done


def test_sort_is_priority_then_severity_then_location_tuple():
    d = derive_all(FS, KBS)
    ids = [f.id for f in sort_for_report(FS, d)]
    assert ids[:2] == ["356e4bbab00c", "108d8ee4651c"]  # P1: 위치 문자열순(backend < docs)
    assert ids.index("3db4c52c28e5") < ids.index("9744de7de162") < ids.index("57f818868bca")  # 줄 번호 정수 비교
    assert ids[-4:] == ["0442ba114c70", "20f2b757fb2c", "e0d713155712", "cae6cff5ca45"]  # P4: critical 먼저


def test_needs_question_for_human_rows_and_demoted_sca_without_evidence():
    d = derive_all(FS, KBS)
    assert needs_question(BY["356e4bbab00c"], d["356e4bbab00c"]) is True
    assert needs_question(BY["0442ba114c70"], d["0442ba114c70"]) is True  # demoted + evidence None
    with_ev = Finding(category="sca", severity="high", title="t", tool="trivy", rule_id="CVE-9", disposition=DEMOTED,
                      reachability=Reachability("unreachable", evidence="no call path", source="dep-scan"))
    assert needs_question(with_ev, derive_all([with_ev], {with_ev.id: _kb("upgrade", False)})[with_ev.id]) is False


def test_counts_and_conclusion_template():
    d = derive_all(FS, KBS)
    c = counts(FS, d)
    assert c == {"total": 15, "actionable": 8, "auto": 0, "human": 8, "review": 3, "demoted": 4, "auto_low": 4, "suppressed": 0}
    meta = {"scanner_status": [{"tool": "gitleaks", "status": "ok"}, {"tool": "semgrep", "status": "ok"}, {"tool": "trivy", "status": "failed"}],
            "excluded_count": 23}
    assert conclusion(c, meta) == ("총 15건. 즉시 조치 대상 8건(자동 수정 0, 사람 확인 후 8). 검토 후보 3건. "
                                   "도달 불가 강등 4건(업그레이드 가능 4). 억제됨 0건. 스캐너 2종 정상 / 1종 실패. 제외 23건.")
```

- [ ] **Step 2: 실패 확인**

Run: `.venv/bin/pytest tests/test_report_derive.py -v`
Expected: FAIL `ModuleNotFoundError: No module named 'secscan.report.derive'`

- [ ] **Step 3: 구현**

```python
# secscan/report/derive.py
"""파생 규칙(spec §5.2). 입력은 Finding + KbEntry 뿐. disposition/tier 는 읽기만 한다(재계산 금지)."""
from __future__ import annotations

from ..models import ACTIONABLE, DEMOTED, REVIEW, SUPPRESSED, Finding, severity_rank
from ..output._status import status_rows
from .models import OWNER_AUTO, OWNER_AUTO_LOW, OWNER_HUMAN, OWNER_NONE, OWNER_SUPPRESSED, Derived, KbEntry

DISP_KO = {ACTIONABLE: "조치대상", REVIEW: "검토후보", DEMOTED: "강등(낮은 우선순위)", SUPPRESSED: "억제됨", None: "미판정"}
SEV_KO = {"critical": "심각", "high": "위험", "medium": "보통", "low": "낮음", "unknown": "미상"}
_PRIO = {REVIEW: "P3", DEMOTED: "P4", SUPPRESSED: "P5", None: "P3"}


def priority(f: Finding) -> str:
    if f.disposition == ACTIONABLE:
        return "P1" if f.severity in ("critical", "high") else "P2"
    return _PRIO[f.disposition]


def owner(f: Finding, kb: KbEntry) -> str:
    d = f.disposition
    if d == ACTIONABLE:
        return OWNER_HUMAN if kb.ctx else OWNER_AUTO
    if d == REVIEW or d is None:
        return OWNER_HUMAN
    if d == DEMOTED:
        return OWNER_AUTO_LOW if kb.action == "upgrade" else OWNER_NONE
    return OWNER_SUPPRESSED


def basis(f: Finding) -> str:
    verdict = DISP_KO[f.disposition]
    if f.category == "sast":
        core = f"SAST · 룰 신뢰도 {f.confidence} → tier {f.tier or '-'} → {verdict}"
    elif f.category == "sca":
        r = f.reachability
        core = f"SCA · 도달성 {r.status}({r.source or '-'}, evidence {'있음' if r.evidence else '없음'}) → {verdict}"
    else:
        core = f"Secret · 억제 {'있음' if f.suppression else '없음'} → {verdict}"
    if f.suppression:
        core = f"억제({f.suppression.basis or f.suppression.state}, 만료 {f.suppression.expiry or '없음'}) → " + core
    return core


def where(f: Finding) -> str:
    if f.location and f.location.file:
        return f"{f.location.file}:{f.location.start_line}" if f.location.start_line else f.location.file
    if f.component:
        return f"{f.component.package}@{f.component.version}"
    return f.rule_id


def _where_key(f: Finding):
    if f.location and f.location.file:
        return (0, f.location.file, f.location.start_line or 0, "")
    if f.component:
        return (1, f.component.package, 0, f.component.version)
    return (2, f.rule_id, 0, "")


def done_text(f: Finding, kb: KbEntry) -> str:
    pkg = f.component.package if f.component else ""
    return kb.done.replace("{id}", f.id).replace("{package}", pkg)


def _group_key(f: Finding, kb: KbEntry):
    if f.category == "sca" and f.component:
        return ("sca", f.component.package, kb.done)  # done 에 target 버전이 들어 있어 같은 target 끼리만 묶인다
    if f.location and f.location.file:
        return ("loc", f.location.file, f.rule_id)
    return None


def _sort_key(f: Finding, prio: str):
    return (prio, -severity_rank(f.severity), _where_key(f), f.id)


def derive_all(findings: list[Finding], kbs: dict[str, KbEntry], deppaths: dict[str, str] | None = None) -> dict[str, Derived]:
    deppaths = deppaths or {}
    prio = {f.id: priority(f) for f in findings}
    ordered = sorted(findings, key=lambda f: _sort_key(f, prio[f.id]))
    members: dict = {}
    for f in ordered:
        k = _group_key(f, kbs[f.id])
        if k is not None:
            members.setdefault(k, []).append(f.id)
    numbered: dict = {}
    out: dict[str, Derived] = {}
    for f in ordered:
        kb = kbs[f.id]
        k = _group_key(f, kb)
        group, done = "", done_text(f, kb)
        if k is not None and len(members[k]) > 1:
            if k not in numbered:
                numbered[k] = f"G-{len(numbered) + 1}"
            group = numbered[k]
            done += " (대표)" if members[k][0] == f.id else f" — {group} 대표와 함께 해소"
        out[f.id] = Derived(prio[f.id], owner(f, kb), basis(f), group, done, where(f), deppaths.get(f.id, ""))
    return out


def sort_for_report(findings: list[Finding], derived: dict[str, Derived]) -> list[Finding]:
    return sorted(findings, key=lambda f: _sort_key(f, derived[f.id].priority))


def needs_question(f: Finding, d: Derived) -> bool:
    if d.owner == OWNER_HUMAN:
        return True
    return f.category == "sca" and f.disposition == DEMOTED and not f.reachability.evidence


def counts(findings: list[Finding], derived: dict[str, Derived]) -> dict:
    return {
        "total": len(findings),
        "actionable": sum(f.disposition == ACTIONABLE for f in findings),
        "auto": sum(derived[f.id].owner == OWNER_AUTO for f in findings),
        "human": sum(derived[f.id].owner == OWNER_HUMAN and f.disposition == ACTIONABLE for f in findings),
        "review": sum(f.disposition == REVIEW for f in findings),
        "demoted": sum(f.disposition == DEMOTED for f in findings),
        "auto_low": sum(derived[f.id].owner == OWNER_AUTO_LOW for f in findings),
        "suppressed": sum(f.disposition == SUPPRESSED for f in findings),
    }


def conclusion(c: dict, meta: dict) -> str:
    st = status_rows(meta)
    ok = sum(s["status"] == "ok" for s in st)
    return (f"총 {c['total']}건. 즉시 조치 대상 {c['actionable']}건(자동 수정 {c['auto']}, 사람 확인 후 {c['human']}). "
            f"검토 후보 {c['review']}건. 도달 불가 강등 {c['demoted']}건(업그레이드 가능 {c['auto_low']}). 억제됨 {c['suppressed']}건. "
            f"스캐너 {ok}종 정상 / {len(st) - ok}종 실패. 제외 {meta.get('excluded_count', 0)}건.")
```

- [ ] **Step 4: 통과 확인**

Run: `.venv/bin/pytest tests/test_report_derive.py -v`
Expected: 모두 통과(파라미터화 포함 22 passed). `status_rows` 가 status 키를 어떻게 정규화하는지는 `secscan/output/_status.py` 를 읽고 맞춘다(`tool`·`status` 키만 쓰면 된다).

- [ ] **Step 5: 커밋**

```bash
git add secscan/report/derive.py tests/test_report_derive.py
git commit -m "feat(report): 파생 규칙 — 우선순위 P1~P5·담당 5종·판정 근거·그룹(G-n)·정렬·확인질문 대상·결론 템플릿(픽스처 분포 고정)

다음: workbook.py 5 시트 빌더 + 골든"
```

---

### Task 4: 워크북 시트 빌더 (`workbook.py`) + 골든

**Files:**
- Create: `secscan/report/workbook.py`, `tests/golden/report-work-note-sheets.json`
- Test: `tests/test_report_workbook.py`

**Interfaces:**
- Consumes: `Sheet`, `sanitize_cell`, `write_xlsx`, `write_csv_bundle`, `_openpyxl_available` (`secscan/output/xlsx.py`); `status_rows`; Task 3 함수 전부; `Interpretation`, `OWNER_HUMAN`
- Produces: `SHEET_SUMMARY="0_요약"`, `SHEET_ACTIONS="1_조치목록"`, `SHEET_QUESTIONS="2_확인질문"`, `SHEET_RULES="3_판정기준"`, `SHEET_RESULT="4_결과반환"`, `ACTION_HEADER`(17), `QUESTION_HEADER`(9), `RESULT_HEADER`(6), `RULE_ROWS`, `guard_rows(target: str) -> list[list]`, `build_report_sheets(findings, meta, kbs, derived, interps: dict[str, Interpretation] | None = None, interp_meta: dict | None = None) -> dict[str, Sheet]`, `write_report(sheets, out_dir, *, created: str, prefer_xlsx: bool | None = None) -> tuple[list[Path], str | None]`

- [ ] **Step 1: 실패하는 테스트**

```python
# tests/test_report_workbook.py
"""5 시트 빌더(spec §5.5) — 열 계약, 사실/추정 분리, 비밀값 미노출, 결정성, 골든."""
import json
from pathlib import Path

from secscan.output.json_io import from_json
from secscan.report.derive import derive_all
from secscan.report.kb import entry_for
from secscan.report.models import Interpretation
from secscan.report.workbook import (ACTION_HEADER, QUESTION_HEADER, RESULT_HEADER, SHEET_ACTIONS, SHEET_QUESTIONS,
                                     SHEET_RESULT, SHEET_RULES, SHEET_SUMMARY, build_report_sheets, guard_rows, write_report)

FIX = Path("fixtures/report/work-note-findings.json")
GOLDEN = Path("tests/golden/report-work-note-sheets.json")
FS = from_json(FIX.read_text(encoding="utf-8"))
META = json.loads(FIX.read_text(encoding="utf-8"))["meta"]
KBS = {f.id: entry_for(f) for f in FS}
DER = derive_all(FS, KBS)


def _sheets(interps=None, interp_meta=None):
    return build_report_sheets(FS, META, KBS, DER, interps, interp_meta)


def test_sheet_names_and_headers():
    s = _sheets()
    assert list(s) == [SHEET_SUMMARY, SHEET_ACTIONS, SHEET_QUESTIONS, SHEET_RULES, SHEET_RESULT]
    assert s[SHEET_ACTIONS][0] == ACTION_HEADER and len(ACTION_HEADER) == 17
    assert s[SHEET_QUESTIONS][0] == QUESTION_HEADER and len(QUESTION_HEADER) == 9
    assert s[SHEET_RESULT][0] == RESULT_HEADER and len(RESULT_HEADER) == 6
    assert ACTION_HEADER[5] == "의존 경로" and ACTION_HEADER[11] == "같이 해결"


def test_action_rows_sorted_and_first_row_is_hardcoded_credential():
    rows = _sheets()[SHEET_ACTIONS][1]
    assert len(rows) == 15 and rows[0][0] == 1 and rows[0][1] == "P1" and rows[0][2] == "356e4bbab00c"
    assert rows[0][3] == "소스코드에 박힌 자격증명" and rows[0][10] == "사람 확인 후"
    assert rows[0][12] == "SAST · 룰 신뢰도 high → tier actionable → 조치대상"
    assert rows[0][15] == "KISA SF-06 하드코드된 중요정보 · PCI-DSS 6.2.4 — access control"


def test_question_rows_only_for_needs_question_and_interpretation_columns_empty_without_file():
    rows = _sheets()[SHEET_QUESTIONS][1]
    assert len(rows) == 15  # 사람 확인 후 11 + evidence 없는 강등 SCA 4
    for r in rows:
        assert r[5] == "" and r[6] == "" and r[7] == ""  # 추정·확인 방법·인용 비어 있음
        assert r[8].startswith("① 수정")


def test_interpretations_fill_guess_columns_and_summary_reports_status():
    interps = {"356e4bbab00c": Interpretation("상수 PASSWORD 가 KNOWN_KEYS 집합에 들어감.", "88행 리터럴 값 확인.",
                                             ("backend/src/main/java/com/worknote/admin/BreakGlassFile.java:87-89",))}
    s = _sheets(interps, {"status": "ok", "rejected": [{"id": "108d8ee4651c", "reason": "no_cite"}]})
    row = next(r for r in s[SHEET_QUESTIONS][1] if r[1] == "356e4bbab00c")
    assert row[5].startswith("상수 PASSWORD") and row[6] == "88행 리터럴 값 확인." and "87-89" in row[7]
    summary = {r[0]: (r[1], r[2]) for r in s[SHEET_SUMMARY][1]}
    assert summary["해석 상태"][0] == "ok" and "108d8ee4651c: no_cite" in summary["해석 상태"][1]


def test_summary_conclusion_and_counts_and_unregistered_rules():
    summary = {r[0]: (r[1], r[2]) for r in _sheets()[SHEET_SUMMARY][1]}
    assert summary["결론"][0].startswith("총 15건. 즉시 조치 대상 8건(자동 수정 0, 사람 확인 후 8).")
    assert summary["즉시 조치 대상(P1·P2)"][0] == 8 and summary["강등(P4)"][0] == 4 and summary["제외"][0] == 23
    assert summary["스캐너 trivy"][0] == "ok"
    assert summary["지식베이스 미등록 룰"][0] == "없음"  # 12건 등록으로 work-note 는 전부 커버


def test_result_sheet_has_guard_rows_then_one_row_per_finding():
    rows = _sheets()[SHEET_RESULT][1]
    assert [r[0] for r in rows[:4]] == ["#허용 범위", "#금지", "#완료 판정", "#status 값"]
    assert "secscan scan --target work-note" in rows[2][1]
    assert [r[0] for r in rows[4:]] == [r[2] for r in _sheets()[SHEET_ACTIONS][1]]
    assert all(r[1:] == ["", "", "", "", ""] for r in rows[4:])


def test_rules_sheet_is_fixed_table():
    header, rows = _sheets()[SHEET_RULES]
    assert header == ["항목", "규칙 / 뜻"] and [r[0] for r in rows][:3] == ["판정(disposition) 규칙", "우선순위 규칙", "담당 규칙"]


def test_no_secret_values_and_all_cells_sanitized():
    s = _sheets()
    blob = json.dumps({k: v[1] for k, v in s.items()}, ensure_ascii=False)
    assert "pend-" not in blob and "ghp_" not in blob
    for _, rows in s.values():
        for r in rows:
            for c in r:
                assert c is None or isinstance(c, (int, float)) or (isinstance(c, str) and not c.lstrip().startswith(("=", "+", "-", "@")))


def test_deterministic_regardless_of_input_order():
    rev = list(reversed(FS))
    assert build_report_sheets(rev, META, {f.id: KBS[f.id] for f in rev}, derive_all(rev, KBS)) == _sheets()


def test_matches_golden():
    got = {k: {"header": h, "rows": r} for k, (h, r) in _sheets().items()}
    assert got == json.loads(GOLDEN.read_text(encoding="utf-8"))


def test_write_report_xlsx_or_csv(tmp_path):
    paths, warn = write_report(_sheets(), tmp_path, created="2026-09-06", prefer_xlsx=False)
    assert warn and (tmp_path / "report-xlsx" / "1_조치목록.csv").exists()
    try:
        import openpyxl  # noqa: F401
    except ImportError:
        return
    paths, warn = write_report(_sheets(), tmp_path, created="2026-09-06", prefer_xlsx=True)
    assert warn is None and paths == [tmp_path / "report.xlsx"]
    from openpyxl import load_workbook
    wb = load_workbook(paths[0])
    assert wb.sheetnames == [SHEET_SUMMARY, SHEET_ACTIONS, SHEET_QUESTIONS, SHEET_RULES, SHEET_RESULT]
    assert wb.properties.modified == wb.properties.created
```

- [ ] **Step 2: 실패 확인**

Run: `.venv/bin/pytest tests/test_report_workbook.py -v`
Expected: FAIL `ModuleNotFoundError: No module named 'secscan.report.workbook'`

- [ ] **Step 3: 구현**

```python
# secscan/report/workbook.py
"""보고서 워크북 5 시트(spec §5.5). 순수·결정적. 저장은 output/xlsx.py 의 write_xlsx/write_csv_bundle 재사용.
셀 채움 색은 없다(Sheet 는 값만) — 사실/추정은 열로 분리한다. 비밀값은 어느 시트에도 싣지 않는다."""
from __future__ import annotations

from pathlib import Path

from ..models import Finding
from ..output._status import status_rows
from ..output.xlsx import Sheet, _openpyxl_available, sanitize_cell, write_csv_bundle, write_xlsx
from .derive import SEV_KO, conclusion, counts, needs_question, sort_for_report
from .models import Derived, Interpretation, KbEntry

SHEET_SUMMARY, SHEET_ACTIONS, SHEET_QUESTIONS, SHEET_RULES, SHEET_RESULT = "0_요약", "1_조치목록", "2_확인질문", "3_판정기준", "4_결과반환"
SUMMARY_HEADER = ["항목", "값", "설명"]
ACTION_HEADER = ["No.", "우선순위", "ID", "문제", "위치", "의존 경로", "무엇이 문제인가", "왜 위험한가", "해야 할 일", "조치 유형",
                 "담당", "같이 해결", "판정 근거", "심각도", "CWE", "기준(KISA/PCI)", "완료 확인 방법"]
QUESTION_HEADER = ["No.", "ID", "위치", "질문", "사실(측정)", "추정(Claude 해석)", "확인 방법", "인용", "선택지"]
RULES_HEADER = ["항목", "규칙 / 뜻"]
RESULT_HEADER = ["ID", "status", "changed_files", "verification", "question_or_reason", "commit"]
CHOICES = "① 수정(해야 할 일대로) ② 억제(사유·증거·만료를 --suppressions 파일에 기록) ③ 스캔 제외(비배포 경로, --exclude)"
RULE_ROWS = [
    ["판정(disposition) 규칙", "억제 있음 → 억제됨 / SAST → tier actionable 이면 조치대상, 아니면 검토후보 / SCA → 도달 불가면 강등, 아니면 조치대상 / Secret → 조치대상"],
    ["우선순위 규칙", "P1 = 조치대상 & 심각·위험 / P2 = 조치대상 & 보통 이하 / P3 = 검토후보(또는 미판정) / P4 = 강등 / P5 = 억제됨"],
    ["담당 규칙", "조치대상 & 룰이 문맥 무관 → 자동 수정(LLM) / 조치대상 & 문맥 필요 → 사람 확인 후 / 검토후보 → 사람 확인 후 / 강등 & 업그레이드 가능 → 자동 수정 가능(LLM, 비차단) / 강등 그 외 → 조치 불필요(모니터링)"],
    ["심각도 뜻", "심각·위험: 악용 시 인증 우회·데이터 유출 수준 / 보통: 조건부 위험 / 낮음: 제한적 / 미상: 도구가 심각도를 주지 않음(설정 권고류)"],
    ["도달성 주의", "'도달 불가' 는 정적 분석이 호출 경로를 못 찾았다는 뜻. 리플렉션·DI·역직렬화·애노테이션 라우팅은 놓칠 수 있어 우선순위 강등 근거일 뿐 안전 보증이 아님. evidence 가 없으면 근거가 더 약함"],
    ["사실 / 추정 구분", "사실(측정) = 도구 출력 또는 코드에서 직접 확인한 것. 추정(Claude 해석) = 코드 문맥으로 해석한 것이며 반드시 '확인 방법'·'인용' 이 따라붙음. 추정은 사람 확인 전 판정 근거로 쓰지 않음"],
    ["자동 억제 없음", "억제(오탐 확정)는 사람이 사유·증거·만료를 --suppressions 파일에 적어 확정. 도구도 LLM 도 스스로 억제하지 않음"],
    ["조치 유형", "upgrade 의존성 업그레이드 / externalize-secret 비밀값 외부화·회수 / sanitize-html HTML 정화 / replace-api 안전한 API 로 교체 / config-change 설정 추가·변경 / code-fix 코드 수정 / confirm-only 사람 확인만"],
    ["같이 해결", "같은 패키지·같은 목표 버전(SCA) 또는 같은 파일·같은 룰(SAST/Secret)인 항목은 G-n 으로 묶임. 대표 행 하나를 고치면 나머지도 함께 해소"],
]


def guard_rows(target: str) -> list[list]:
    pad = ["", "", "", ""]
    return [
        ["#허용 범위", "'1_조치목록' 의 담당 열이 '자동' 으로 시작하는 행만 수정한다. '사람 확인 후' 행은 수정하지 않고 '2_확인질문' 의 질문을 status=needs_confirmation 으로 옮긴다."] + pad,
        ["#금지", "억제 파일 작성·수정 / 스캔 제외 규칙 추가 / 테스트 삭제·약화 / 조치목록에 없는 파일 변경 / 스캐너·룰 설정 변경"] + pad,
        ["#완료 판정", f"수정 뒤 `secscan scan --target {target} --profile standard --out <dir>` 를 1회 실행하고 findings.json 에서 ID 를 검색한다. 판정 기준은 '1_조치목록' 의 '완료 확인 방법' 열."] + pad,
        ["#status 값", "fixed | skipped(사유 필수) | needs_confirmation(질문 필수) 세 값만"] + pad,
    ]


def _cwe(f: Finding) -> str:
    return ", ".join(f.cwe) or "-"


def _std(f: Finding) -> str:
    c = f.compliance
    if not c:
        return "-"
    k = ", ".join(f"KISA {w.code} {w.name}" for w in c.kisa)
    p = ", ".join(c.pci)
    return " · ".join(x for x in (k, p) if x) or "-"


def _san(rows: list[list]) -> list[list]:
    return [[sanitize_cell(c) for c in r] for r in rows]


def _summary_rows(findings, meta, kbs, derived, interp_meta) -> list[list]:
    c = counts(findings, derived)
    rows = [["대상", meta.get("target", ""), ""], ["프로파일", meta.get("profile", ""), ""]]
    for s in status_rows(meta):
        rows.append([f"스캐너 {s['tool']}", s["status"], f"{s.get('duration_s') or ''}s {s.get('message') or ''}".strip()])
    rows.append(["결론", conclusion(c, meta), "규칙 파생 문장(숫자 손기입 없음)"])
    rows += [
        ["즉시 조치 대상(P1·P2)", c["actionable"], f"규칙상 조치대상. 자동 수정 {c['auto']} · 사람 확인 후 {c['human']}"],
        ["검토 후보(P3)", c["review"], "도구 신뢰도 낮음 또는 심각도 미상. 사람이 보고 결정"],
        ["강등(P4)", c["demoted"], f"호출 경로 없음으로 판정. 업그레이드 가능 {c['auto_low']}(비차단)"],
        ["억제됨(P5)", c["suppressed"], "사람이 확정한 억제. 만료·버전 변경 시 재표면"],
        ["제외", meta.get("excluded_count", 0), "build/·node_modules/·.gitignore 대상 등 기본 제외"],
        ["시트 1_조치목록", "개발자·보안팀", "항목별 무엇/왜/어떻게/담당/근거/완료 확인"],
        ["시트 2_확인질문", "담당 개발자·보안팀", "사람이 답해야 LLM 이 움직일 수 있는 항목의 질문·사실·추정"],
        ["시트 3_판정기준", "보안팀·감사", "우선/검토/강등이 갈린 규칙, 용어 뜻"],
        ["시트 4_결과반환", "수정 LLM → 사람", "허용 범위·금지 4줄 + LLM 이 채워 돌려주는 템플릿"],
    ]
    composed = sorted({f.rule_id for f in findings if f.category != "sca" and kbs[f.id].source == "composed"})
    rows.append(["지식베이스 미등록 룰", ", ".join(composed) or "없음", "합성 폴백으로 설명됨 — rules.json 등록 대기"])
    im = interp_meta or {"status": "absent", "rejected": []}
    rej = "; ".join(f"{r['id']}: {r['reason']}" for r in im.get("rejected", []))
    rows.append(["해석 상태", im.get("status", "absent"), rej or "거부 없음"])
    return rows


def build_report_sheets(findings: list[Finding], meta: dict, kbs: dict[str, KbEntry], derived: dict[str, Derived],
                        interps: dict[str, Interpretation] | None = None, interp_meta: dict | None = None) -> dict[str, Sheet]:
    interps = interps or {}
    ordered = sort_for_report(findings, derived)
    actions, questions, results = [], [], []
    for i, f in enumerate(ordered, 1):
        kb, d = kbs[f.id], derived[f.id]
        actions.append([i, d.priority, f.id, kb.name, d.where, d.deppath, kb.what, kb.why, kb.how, kb.action, d.owner, d.group,
                        d.basis, SEV_KO.get(f.severity, f.severity), _cwe(f), _std(f), d.done])
        results.append([f.id, "", "", "", "", ""])
        if needs_question(f, d):
            it = interps.get(f.id)
            fact = f"룰 {f.rule_id} 발화 · {d.basis} · CWE {_cwe(f)}"
            questions.append([i, f.id, d.where, kb.confirm or "도달 불가 근거(evidence)가 없음 — 실제 호출 경로가 없는지 확인 필요",
                              fact, it.guess if it else "", it.check if it else "", ", ".join(it.cites) if it else "", CHOICES])
    return {
        SHEET_SUMMARY: (SUMMARY_HEADER, _san(_summary_rows(findings, meta, kbs, derived, interp_meta))),
        SHEET_ACTIONS: (ACTION_HEADER, _san(actions)),
        SHEET_QUESTIONS: (QUESTION_HEADER, _san(questions)),
        SHEET_RULES: (RULES_HEADER, _san([list(r) for r in RULE_ROWS])),
        SHEET_RESULT: (RESULT_HEADER, _san(guard_rows(str(meta.get("target", ""))) + results)),
    }


def write_report(sheets: dict[str, Sheet], out_dir, *, created: str, prefer_xlsx: bool | None = None) -> tuple[list[Path], str | None]:
    out = Path(out_dir)
    use_xlsx = _openpyxl_available() if prefer_xlsx is None else prefer_xlsx
    if use_xlsx:
        return [write_xlsx(sheets, out / "report.xlsx", created=created)], None
    return write_csv_bundle(sheets, out / "report-xlsx"), "openpyxl 미설치 — report 시트별 CSV 번들로 대체(`pip install secscan[xlsx]`)"
```

- [ ] **Step 4: 골든 생성 후 통과 확인**

골든은 빌더 출력에서 만든다(손으로 쓰지 않는다). `test_matches_golden` 만 골든 생성 전에는 실패한다.

```bash
.venv/bin/python - <<'EOF'
import json
from pathlib import Path
from secscan.output.json_io import from_json
from secscan.report.derive import derive_all
from secscan.report.kb import entry_for
from secscan.report.workbook import build_report_sheets
fix = Path("fixtures/report/work-note-findings.json").read_text(encoding="utf-8")
fs = from_json(fix); meta = json.loads(fix)["meta"]; kbs = {f.id: entry_for(f) for f in fs}
s = build_report_sheets(fs, meta, kbs, derive_all(fs, kbs))
Path("tests/golden/report-work-note-sheets.json").write_text(
    json.dumps({k: {"header": h, "rows": r} for k, (h, r) in s.items()}, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
EOF
.venv/bin/pytest tests/test_report_workbook.py -v
```
Expected: 11 passed. 골든 파일을 열어 1_조치목록 첫 행이 `356e4bbab00c`·P1·"소스코드에 박힌 자격증명" 인지 눈으로 확인한다.

- [ ] **Step 5: 커밋**

```bash
git add secscan/report/workbook.py tests/test_report_workbook.py tests/golden/report-work-note-sheets.json
git commit -m "feat(report): 5 시트 빌더(요약·조치목록 17열·확인질문·판정기준·결과반환 #지시 4행) + write_report + work-note 골든

다음: secscan report 커맨드 + scan 통합"
```

---

### Task 5: `secscan report` 커맨드 + `scan` 통합

**Files:**
- Create: `secscan/report/cli.py`
- Modify: `secscan/cli.py` (`_cmd_scan` 의 findings.json meta 에 `run_date` 추가, write_workbook 뒤 `write_report_bundle` 호출, 출력 줄에 report 경로; `main` 에 `add_report_parser(sub)` 와 `report` 분기)
- Test: `tests/test_report_cli.py`, `tests/test_cli.py`(기존 scan 테스트 1개 보강)

**Interfaces:**
- Consumes: Task 2~4 전부; `secscan.output.json_io.from_json`; `json.loads(text)["meta"]`
- Produces: `add_report_parser(sub) -> None`, `build_report(findings, meta, *, target=None, deppaths=None, interps=None, interp_meta=None) -> dict[str, Sheet]`, `write_report_bundle(findings, meta, out_dir, *, target=None, deppaths=None, interps=None, interp_meta=None, prefer_xlsx=None) -> tuple[list[Path], str | None]`, `cmd_report(args) -> int`
- `report` 인자: `--findings F`(필수, check 모드 제외) `--target T`(기본: meta.target) `--out D`(기본 `out`). `--bom`·`--interpretations`·`--check-result`·`--rescan` 은 Task 7·9·10 에서 추가.

- [ ] **Step 1: 실패하는 테스트**

```python
# tests/test_report_cli.py
"""`secscan report` — findings.json 만으로 워크북 생성. 상대경로 통일. scan 은 report 유무와 무관하게 exit 불변."""
import json
from pathlib import Path

from secscan import cli
from secscan.output.json_io import from_json
from secscan.report.cli import build_report, write_report_bundle
from secscan.report.workbook import SHEET_ACTIONS, SHEET_SUMMARY

FIX = Path("fixtures/report/work-note-findings.json")


def _load():
    text = FIX.read_text(encoding="utf-8")
    return from_json(text), json.loads(text)["meta"]


def test_build_report_relativizes_absolute_paths_under_target():
    fs, meta = _load()
    abs_fs = [f for f in fs]
    from dataclasses import replace
    from secscan.models import Location
    f0 = abs_fs[0]
    abs_fs[0] = replace(f0, location=Location("/repo/work-note/" + f0.location.file, f0.location.start_line))
    s = build_report(abs_fs, meta, target="/repo/work-note")
    row = next(r for r in s[SHEET_ACTIONS][1] if r[2] == abs_fs[0].id)
    assert row[4].startswith(f0.location.file.split("/")[0])  # 접두 제거됨


def test_write_report_bundle_writes_report_xlsx_or_csv(tmp_path):
    fs, meta = _load()
    paths, warn = write_report_bundle(fs, meta, tmp_path, prefer_xlsx=False)
    assert warn and (tmp_path / "report-xlsx" / f"{SHEET_SUMMARY}.csv").exists()


def test_main_report_command_writes_outputs(tmp_path):
    rc = cli.main(["report", "--findings", str(FIX), "--out", str(tmp_path)])
    assert rc == 0
    assert (tmp_path / "report.xlsx").exists() or (tmp_path / "report-xlsx").is_dir()


def test_main_report_requires_findings(capsys):
    rc = cli.main(["report", "--out", "x"])
    assert rc == 2 and "--findings" in capsys.readouterr().out
```

`tests/test_cli.py` 의 `test_main_scan_writes_outputs` 끝에 두 줄 추가:

```python
    assert (tmp_path / "report.xlsx").exists() or (tmp_path / "report-xlsx").is_dir()
    assert json.loads((tmp_path / "findings.json").read_text())["meta"]["run_date"]
```
(파일 상단에 `import json` 이 없으면 추가.)

- [ ] **Step 2: 실패 확인**

Run: `.venv/bin/pytest tests/test_report_cli.py tests/test_cli.py -v`
Expected: `test_report_cli.py` 4건 ImportError, `test_main_scan_writes_outputs` 는 report 파일 부재로 FAIL

- [ ] **Step 3: 구현**

```python
# secscan/report/cli.py
"""`secscan report` — findings.json(+bom, +interpretations) → 5 시트 워크북. LLM 없이 완성된다."""
from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from ..models import Finding, Location
from ..output.json_io import from_json
from ..output.xlsx import Sheet
from .derive import derive_all
from .kb import entry_for
from .models import Interpretation
from .workbook import build_report_sheets, write_report


def _rel(p: str, target: str | None) -> str:
    if not p or not target:
        return p
    prefix = str(Path(target)) .rstrip("/") + "/"
    return p[len(prefix):] if p.startswith(prefix) else p


def relativize(findings: list[Finding], target: str | None) -> list[Finding]:
    out = []
    for f in findings:
        loc = replace(f.location, file=_rel(f.location.file, target)) if f.location else None
        out.append(replace(f, location=loc, source=_rel(f.source, target)))
    return out


def build_report(findings: list[Finding], meta: dict, *, target: str | None = None, deppaths: dict[str, str] | None = None,
                 interps: dict[str, Interpretation] | None = None, interp_meta: dict | None = None) -> dict[str, Sheet]:
    target = target or meta.get("target")
    fs = relativize(findings, target)
    kbs = {f.id: entry_for(f) for f in fs}
    # relativize 로 id 가 바뀔 수 있다(dedup_key 에 경로 포함) — deppaths/interps 는 새 id 기준으로 넘겨야 한다.
    derived = derive_all(fs, kbs, deppaths)
    meta = {**meta, "target": target or meta.get("target", "")}
    return build_report_sheets(fs, meta, kbs, derived, interps, interp_meta)


def write_report_bundle(findings: list[Finding], meta: dict, out_dir, *, target: str | None = None,
                        deppaths: dict[str, str] | None = None, interps: dict[str, Interpretation] | None = None,
                        interp_meta: dict | None = None, prefer_xlsx: bool | None = None) -> tuple[list[Path], str | None]:
    sheets = build_report(findings, meta, target=target, deppaths=deppaths, interps=interps, interp_meta=interp_meta)
    return write_report(sheets, out_dir, created=str(meta.get("run_date", "")), prefer_xlsx=prefer_xlsx)


def add_report_parser(sub) -> None:
    rp = sub.add_parser("report", help="사람·LLM 겸용 보고서 워크북 생성")
    rp.add_argument("--findings", help="scan 이 낸 findings.json 경로")
    rp.add_argument("--target", help="경로 상대화 기준(기본: findings.json meta.target)")
    rp.add_argument("--out", default="out", help="출력 디렉토리")


def cmd_report(args) -> int:
    if not args.findings:
        print("secscan report: --findings 가 필요합니다")
        return 2
    text = Path(args.findings).read_text(encoding="utf-8")
    findings, meta = from_json(text), json.loads(text).get("meta", {})
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    paths, warn = write_report_bundle(findings, meta, out, target=args.target)
    if warn:
        print(f"⚠️ {warn}")
    print("출력: " + " · ".join(str(p) for p in paths))
    return 0
```

`secscan/cli.py` 수정 3곳:

1. `_cmd_scan` 의 `to_json(... meta={...})` dict 에 `"run_date": date.today().isoformat(),` 추가.
2. `write_workbook` 호출 뒤:
```python
    from .report.cli import write_report_bundle
    rp_paths, rp_warn = write_report_bundle(result.findings, wb_meta, out, target=str(args.target))
    if rp_warn:
        print(f"⚠️ {rp_warn}")
```
그리고 출력 줄을 `print(f"\n출력: {out / 'report.md'} · {out / 'findings.sarif'} · {out / 'findings.json'} · {wb_paths[0]} · {rp_paths[0]}")` 로.
3. `main`: `cp = sub.add_parser("clean", ...)` 블록 뒤에 `from .report.cli import add_report_parser, cmd_report` 와 `add_report_parser(sub)`; 분기에 `if args.command == "report": return cmd_report(args)`.

- [ ] **Step 4: 통과 확인**

Run: `.venv/bin/pytest tests/test_report_cli.py tests/test_cli.py -v` 그리고 `.venv/bin/pytest`
Expected: 전부 통과. `_has_actionable` 경로는 건드리지 않았으므로 exit code 테스트 불변.

- [ ] **Step 5: 커밋**

```bash
git add secscan/report/cli.py secscan/cli.py tests/test_report_cli.py tests/test_cli.py
git commit -m "feat(report): secscan report 커맨드(findings.json → report.xlsx, 상대경로 통일) + scan 끝에 report 자동 생성, findings.json meta.run_date

다음: deppath.py BOM 의존 경로"
```

---

### Task 6: 의존 경로 (`deppath.py`)

**Files:**
- Create: `secscan/report/deppath.py`
- Test: `tests/test_report_deppath.py`

**Interfaces:**
- Consumes: `fixtures/report/work-note-bom.cdx.json`(CycloneDX 1.x: `metadata.component.bom-ref`, `components[].{bom-ref,group,name,version}`, `dependencies[].{ref,dependsOn}`)
- Produces: `class DepGraph` — `DepGraph.from_path(path) -> DepGraph | None`, `DepGraph(bom: dict)`, `.path_for(package: str, version: str) -> str`; 모듈 함수 `deppaths_for(findings, graph: DepGraph | None) -> dict[str, str]`; 상수 `NO_BOM = "BOM 없음"`, `NOT_IN_BOM = "BOM 에 없음"`, `MAX_HOPS = 4`

출력 규칙(spec §5.3): 부모가 루트 → `직접`; 아니면 `전이 ← A ← B`(컴포넌트에서 루트 쪽으로 중간 노드 artifact 이름, 최대 4개, 넘으면 끝에 ` ← …`); 같은 group:artifact 가 다른 버전으로만 있으면 접두를 `직접(버전 상이: x)` / `전이(버전 상이: x)`; 루트에서 도달 불가 → `BOM 에 있음(경로 미상)`; 없음 → `BOM 에 없음`; 그래프 자체 없음 → `BOM 없음`.

- [ ] **Step 1: 실패하는 테스트**

```python
# tests/test_report_deppath.py
"""CycloneDX 의존 그래프 → 직접/전이 경로 문자열(spec §5.3)."""
from pathlib import Path

from secscan.models import Component, Finding
from secscan.report.deppath import MAX_HOPS, NO_BOM, NOT_IN_BOM, DepGraph, deppaths_for

BOM = Path("fixtures/report/work-note-bom.cdx.json")


def test_transitive_chain_from_fixture():
    g = DepGraph.from_path(BOM)
    assert g.path_for("org.apache.tomcat.embed:tomcat-embed-core", "10.1.55") == "전이 ← spring-boot-starter-tomcat ← spring-boot-starter-web"
    assert g.path_for("org.apache.logging.log4j:log4j-api", "2.24.3") == (
        "전이 ← log4j-to-slf4j ← spring-boot-starter-logging ← spring-boot-starter ← mybatis-spring-boot-starter")


def test_direct_missing_and_version_mismatch():
    g = DepGraph.from_path(BOM)
    assert g.path_for("org.flywaydb:flyway-core", "11.7.2") == "직접"
    assert g.path_for("x:y", "1") == NOT_IN_BOM
    assert g.path_for("org.apache.tomcat.embed:tomcat-embed-core", "10.1.99").startswith("전이(버전 상이: 10.1.55) ← ")


def test_missing_bom_file_and_truncation():
    assert DepGraph.from_path(Path("nope/bom.json")) is None
    chain = {"bom-ref": "root", "components": [], "dependencies": []}
    refs = [f"pkg:maven/g/a{i}@1?type=jar" for i in range(7)]
    bom = {"metadata": {"component": {"bom-ref": "pkg:maven/g/root@1?type=jar"}},
           "components": [{"bom-ref": r, "group": "g", "name": f"a{i}", "version": "1"} for i, r in enumerate(refs)],
           "dependencies": [{"ref": "pkg:maven/g/root@1?type=jar", "dependsOn": [refs[0]]}]
                           + [{"ref": refs[i], "dependsOn": [refs[i + 1]]} for i in range(6)]}
    s = DepGraph(bom).path_for("g:a6", "1")
    assert s == "전이 ← a5 ← a4 ← a3 ← a2 ← …" and s.count("←") == MAX_HOPS + 1
    unreachable = {"metadata": {"component": {"bom-ref": "r"}}, "components": [{"bom-ref": "z", "group": "g", "name": "z", "version": "1"}], "dependencies": []}
    assert DepGraph(unreachable).path_for("g:z", "1") == "BOM 에 있음(경로 미상)"


def test_deppaths_for_findings_only_sca_and_none_graph():
    sca = Finding(category="sca", severity="high", title="t", tool="trivy", rule_id="CVE-1",
                  component=Component("maven", "org.flywaydb:flyway-core", "11.7.2"))
    sast = Finding(category="sast", severity="low", title="t", tool="semgrep", rule_id="r")
    g = DepGraph.from_path(BOM)
    assert deppaths_for([sca, sast], g) == {sca.id: "직접"}
    assert deppaths_for([sca, sast], None) == {sca.id: NO_BOM}
```

- [ ] **Step 2: 실패 확인**

Run: `.venv/bin/pytest tests/test_report_deppath.py -v`
Expected: FAIL `ModuleNotFoundError`

- [ ] **Step 3: 구현**

```python
# secscan/report/deppath.py
"""CycloneDX(cdxgen) 의존 그래프 → 직접/전이 경로 문자열(spec §5.3). 루트에서 BFS 최단 경로."""
from __future__ import annotations

import json
from collections import deque
from pathlib import Path

from ..models import Finding

NO_BOM = "BOM 없음"
NOT_IN_BOM = "BOM 에 없음"
UNREACHED = "BOM 에 있음(경로 미상)"
MAX_HOPS = 4


class DepGraph:
    def __init__(self, bom: dict):
        self.root = ((bom.get("metadata") or {}).get("component") or {}).get("bom-ref", "")
        self.deps = {d.get("ref"): list(d.get("dependsOn") or []) for d in bom.get("dependencies") or []}
        self.name = {}  # ref → artifact 이름
        self.by_key: dict[str, list[tuple[str, str]]] = {}  # "group:artifact" → [(version, ref)]
        for c in bom.get("components") or []:
            ref = c.get("bom-ref") or c.get("purl") or ""
            if not ref:
                continue
            self.name[ref] = c.get("name", ref)
            key = f"{c.get('group', '')}:{c.get('name', '')}" if c.get("group") else c.get("name", "")
            self.by_key.setdefault(key, []).append((c.get("version", ""), ref))
        self.parent = self._bfs()

    @classmethod
    def from_path(cls, path) -> "DepGraph | None":
        p = Path(path)
        if not p.exists():
            return None
        try:
            return cls(json.loads(p.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError):
            return None

    def _bfs(self) -> dict[str, str | None]:
        parent: dict[str, str | None] = {self.root: None}
        q = deque([self.root])
        while q:
            n = q.popleft()
            for m in self.deps.get(n, []):
                if m not in parent:
                    parent[m] = n
                    q.append(m)
        return parent

    def _chain(self, ref: str) -> list[str]:
        out, n = [], self.parent.get(ref)
        while n is not None and n != self.root:
            out.append(self.name.get(n, n))
            n = self.parent.get(n)
        return out

    def path_for(self, package: str, version: str) -> str:
        cands = self.by_key.get(package)
        if not cands:
            return NOT_IN_BOM
        exact = [r for v, r in cands if v == version]
        ver_note = ""
        if exact:
            ref = exact[0]
        else:
            other_v, ref = sorted(cands)[0]
            ver_note = f"(버전 상이: {other_v})"
        if ref not in self.parent:
            return UNREACHED
        chain = self._chain(ref)
        if not chain:
            return f"직접{ver_note}"
        shown = chain[:MAX_HOPS]
        tail = " ← …" if len(chain) > MAX_HOPS else ""
        return f"전이{ver_note} ← " + " ← ".join(shown) + tail


def deppaths_for(findings: list[Finding], graph: DepGraph | None) -> dict[str, str]:
    out = {}
    for f in findings:
        if f.category != "sca" or f.component is None:
            continue
        out[f.id] = graph.path_for(f.component.package, f.component.version) if graph else NO_BOM
    return out
```

- [ ] **Step 4: 통과 확인**

Run: `.venv/bin/pytest tests/test_report_deppath.py -v`
Expected: 4 passed

- [ ] **Step 5: 커밋**

```bash
git add secscan/report/deppath.py tests/test_report_deppath.py
git commit -m "feat(report): deppath — CycloneDX 그래프 BFS 로 직접/전이(← 체인, 4단 절단)/버전 상이/BOM 없음

다음: report --bom 배선 + scan 은 sbom 캐시 자동 사용, 골든 재생성"
```

---

### Task 7: `--bom` 배선 (report·scan) + 골든 재생성

**Files:**
- Modify: `secscan/report/cli.py` (`add_report_parser` 에 `--bom`, `cmd_report` 에서 `DepGraph.from_path` → `deppaths_for`; `write_report_bundle` 에 `bom` 인자), `secscan/cli.py` (`write_report_bundle(..., bom=bom_cache_path(args.target))`)
- Modify: `tests/golden/report-work-note-sheets.json` (의존 경로 열 채움 — 재생성), `tests/test_report_workbook.py`(골든 빌드에 deppaths 포함), `tests/test_report_cli.py`
- Test: `tests/test_report_cli.py` 추가 2건

**Interfaces:**
- Consumes: `DepGraph`, `deppaths_for` (Task 6); `secscan.sbom.bom_cache_path(target) -> Path`
- Produces: `write_report_bundle(..., bom: str | Path | None = None, ...)` — `bom` 이 주어지면 `DepGraph.from_path(bom)`(없으면 None → `BOM 없음`); `report --bom B`

- [ ] **Step 1: 실패하는 테스트** (`tests/test_report_cli.py` 에 추가)

```python
def test_report_with_bom_fills_dependency_path_column(tmp_path):
    fs, meta = _load()
    from secscan.report.cli import build_report
    s = build_report(fs, meta, bom="fixtures/report/work-note-bom.cdx.json")
    rows = {r[2]: r for r in s[SHEET_ACTIONS][1]}
    assert rows["0442ba114c70"][5] == "전이 ← spring-boot-starter-tomcat ← spring-boot-starter-web"
    assert rows["356e4bbab00c"][5] == ""  # SAST 는 의존 경로 없음
    s2 = build_report(fs, meta, bom="nope.json")
    assert {r[2]: r for r in s2[SHEET_ACTIONS][1]}["0442ba114c70"][5] == "BOM 없음"


def test_main_report_accepts_bom_flag(tmp_path):
    rc = cli.main(["report", "--findings", str(FIX), "--bom", "fixtures/report/work-note-bom.cdx.json", "--out", str(tmp_path)])
    assert rc == 0
```

`tests/test_report_workbook.py` 의 `DER` 정의를 BOM 포함으로 바꾼다(골든이 의존 경로 열을 담도록):

```python
from secscan.report.deppath import DepGraph, deppaths_for
DER = derive_all(FS, KBS, deppaths_for(FS, DepGraph.from_path("fixtures/report/work-note-bom.cdx.json")))
```
`test_deterministic_regardless_of_input_order` 의 `derive_all(rev, KBS)` 도 같은 deppaths 를 넘긴다.

- [ ] **Step 2: 실패 확인**

Run: `.venv/bin/pytest tests/test_report_cli.py tests/test_report_workbook.py -v`
Expected: 새 테스트 2건 TypeError(`bom` 인자 없음), `test_matches_golden` FAIL(의존 경로 열 차이)

- [ ] **Step 3: 구현**

`secscan/report/cli.py`:
- `build_report(..., bom: str | Path | None = None, ...)`: `deppaths` 가 None 이고 `bom` 이 주어지면 `deppaths = deppaths_for(fs, DepGraph.from_path(bom))` (relativize 뒤의 `fs` 로 계산 — id 가 경로에 의존하므로).
- `write_report_bundle(..., bom=None, ...)` 는 그대로 전달.
- `add_report_parser`: `rp.add_argument("--bom", help="cdxgen BOM(bom.cdx.json). 없으면 의존 경로 열은 'BOM 없음'")`.
- `cmd_report`: `write_report_bundle(findings, meta, out, target=args.target, bom=args.bom)`.

`secscan/cli.py` `_cmd_scan`: `from .sbom import bom_cache_path` 후 `write_report_bundle(result.findings, wb_meta, out, target=str(args.target), bom=bom_cache_path(args.target))`.

- [ ] **Step 4: 골든 재생성 후 통과 확인**

```bash
.venv/bin/python - <<'EOF'
import json
from pathlib import Path
from secscan.output.json_io import from_json
from secscan.report.deppath import DepGraph, deppaths_for
from secscan.report.derive import derive_all
from secscan.report.kb import entry_for
from secscan.report.workbook import build_report_sheets
fix = Path("fixtures/report/work-note-findings.json").read_text(encoding="utf-8")
fs = from_json(fix); meta = json.loads(fix)["meta"]; kbs = {f.id: entry_for(f) for f in fs}
dp = deppaths_for(fs, DepGraph.from_path("fixtures/report/work-note-bom.cdx.json"))
s = build_report_sheets(fs, meta, kbs, derive_all(fs, kbs, dp))
Path("tests/golden/report-work-note-sheets.json").write_text(
    json.dumps({k: {"header": h, "rows": r} for k, (h, r) in s.items()}, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
EOF
git diff --stat tests/golden/report-work-note-sheets.json   # 의존 경로 열(6번째)만 바뀌었는지 확인
.venv/bin/pytest
```
Expected: 전부 통과. 골든 diff 에서 tomcat 3행 `전이 ← spring-boot-starter-tomcat ← spring-boot-starter-web`, log4j 행 `전이 ← log4j-to-slf4j ← spring-boot-starter-logging ← spring-boot-starter ← mybatis-spring-boot-starter` 확인.

- [ ] **Step 5: 커밋**

```bash
git add secscan/report/cli.py secscan/cli.py tests/test_report_cli.py tests/test_report_workbook.py tests/golden/report-work-note-sheets.json
git commit -m "feat(report): --bom 배선(scan 은 sbom 캐시 자동) — 의존 경로 열 채움, 골든 재생성(의존 경로 열만 변경)

다음: interpret.py request/response/검증기"
```

---

### Task 8: 해석 계층 인터페이스·검증기 (`interpret.py`)

**Files:**
- Create: `secscan/report/interpret.py`
- Test: `tests/test_report_interpret.py`

**Interfaces:**
- Consumes: `Derived`, `Interpretation`, `KbEntry` (Task 1); `needs_question` (Task 3)
- Produces: `REQUEST_CONTEXT = "secscan-report-request/v1"`, `RESPONSE_CONTEXT = "secscan-interpretations/v1"`, `FORBIDDEN = ("오탐 확정", "안전함", "문제 없음", "억제함", "수정 완료")`, `MAX_LEN = 600`, `build_request(findings, derived, kbs, *, target: str, findings_path: str) -> dict`, `validate_response(resp: dict, request: dict) -> tuple[dict[str, Interpretation], list[dict]]`, `load_interpretations(path, request) -> tuple[dict[str, Interpretation], dict]` (두 번째는 `interp_meta = {"status": "ok"|"absent"|"bad_context"|"unreadable", "rejected": [...]}`)

거부 사유 enum(문자열): `unknown_id`, `empty`, `too_long`, `no_cite`, `bad_cite`, `verdict_word`, `count_in_guess`, `bad_shape`.

- [ ] **Step 1: 실패하는 테스트**

```python
# tests/test_report_interpret.py
"""Claude 해석 파일 인터페이스(spec §5.4) — request 생성, response 검증(거부 사유 전수), 부재 처리."""
import json
from pathlib import Path

import pytest

from secscan.output.json_io import from_json
from secscan.report.derive import derive_all
from secscan.report.interpret import (FORBIDDEN, MAX_LEN, REQUEST_CONTEXT, RESPONSE_CONTEXT, build_request,
                                      load_interpretations, validate_response)
from secscan.report.kb import entry_for

FS = from_json(Path("fixtures/report/work-note-findings.json").read_text(encoding="utf-8"))
KBS = {f.id: entry_for(f) for f in FS}
DER = derive_all(FS, KBS)
REQ = build_request(FS, DER, KBS, target="work-note", findings_path="out/findings.json")
CITE = "backend/src/main/java/com/worknote/admin/BreakGlassFile.java:87-89"


def _resp(items):
    return {"@context": RESPONSE_CONTEXT, "written_at": "2026-09-07", "items": items}


def _ok(**kw):
    d = {"guess": "상수 PASSWORD 가 KNOWN_KEYS 집합에 들어감.", "check": "88행 리터럴 값 확인.", "cites": [CITE]}
    d.update(kw)
    return d


def test_request_lists_question_items_without_snippets():
    assert REQ["@context"] == REQUEST_CONTEXT and REQ["target"] == "work-note" and REQ["findings"] == "out/findings.json"
    ids = [i["id"] for i in REQ["items"]]
    assert len(ids) == 15 and "356e4bbab00c" in ids and "0442ba114c70" in ids
    item = next(i for i in REQ["items"] if i["id"] == "356e4bbab00c")
    assert item["where"].endswith("BreakGlassFile.java:88") and item["question"] and item["rule_id"]
    assert item["facts"][0].startswith("룰 ") and not any(k in item for k in ("snippet", "code", "lines"))


def test_valid_response_is_accepted():
    acc, rej = validate_response(_resp({"356e4bbab00c": _ok()}), REQ)
    assert rej == [] and acc["356e4bbab00c"].cites == (CITE,) and acc["356e4bbab00c"].check == "88행 리터럴 값 확인."


@pytest.mark.parametrize("item_id,item,reason", [
    ("deadbeef0000", _ok(), "unknown_id"),
    ("356e4bbab00c", _ok(guess=""), "empty"),
    ("356e4bbab00c", _ok(check=""), "empty"),
    ("356e4bbab00c", _ok(guess="x" * (MAX_LEN + 1)), "too_long"),
    ("356e4bbab00c", _ok(cites=[]), "no_cite"),
    ("356e4bbab00c", _ok(cites=["BreakGlassFile.java"]), "bad_cite"),
    ("356e4bbab00c", _ok(cites=["/abs/path.java:1"]), "bad_cite"),
    ("356e4bbab00c", _ok(cites=["../x.java:1"]), "bad_cite"),
    ("356e4bbab00c", _ok(guess="이건 오탐 확정이다."), "verdict_word"),
    ("356e4bbab00c", _ok(check="안전함"), "verdict_word"),
    ("356e4bbab00c", _ok(guess="비슷한 것이 3건 더 있다."), "count_in_guess"),
    ("356e4bbab00c", "not a dict", "bad_shape"),
])
def test_rejection_reasons(item_id, item, reason):
    acc, rej = validate_response(_resp({item_id: item}), REQ)
    assert acc == {} and rej == [{"id": item_id, "reason": reason}]


def test_forbidden_words_are_the_spec_list():
    assert FORBIDDEN == ("오탐 확정", "안전함", "문제 없음", "억제함", "수정 완료")


def test_load_absent_bad_context_and_ok(tmp_path):
    acc, meta = load_interpretations(tmp_path / "none.json", REQ)
    assert acc == {} and meta == {"status": "absent", "rejected": []}
    p = tmp_path / "bad.json"; p.write_text(json.dumps({"@context": "other/v9", "items": {}}), encoding="utf-8")
    assert load_interpretations(p, REQ)[1]["status"] == "bad_context"
    p2 = tmp_path / "broken.json"; p2.write_text("{not json", encoding="utf-8")
    assert load_interpretations(p2, REQ)[1]["status"] == "unreadable"
    p3 = tmp_path / "ok.json"; p3.write_text(json.dumps(_resp({"356e4bbab00c": _ok(), "zzz": _ok()})), encoding="utf-8")
    acc, meta = load_interpretations(p3, REQ)
    assert set(acc) == {"356e4bbab00c"} and meta == {"status": "ok", "rejected": [{"id": "zzz", "reason": "unknown_id"}]}
```

- [ ] **Step 2: 실패 확인**

Run: `.venv/bin/pytest tests/test_report_interpret.py -v`
Expected: FAIL `ModuleNotFoundError`

- [ ] **Step 3: 구현**

```python
# secscan/report/interpret.py
"""Claude 해석 계층의 파일 인터페이스(spec §5.4). 검증기 통과분만 병합, 거부는 사유와 함께 기록. 스니펫은 넣지 않는다."""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..models import Finding
from .derive import needs_question
from .models import Derived, Interpretation, KbEntry

REQUEST_CONTEXT = "secscan-report-request/v1"
RESPONSE_CONTEXT = "secscan-interpretations/v1"
FORBIDDEN = ("오탐 확정", "안전함", "문제 없음", "억제함", "수정 완료")
MAX_LEN = 600
_CITE = re.compile(r"^[^/\s][^\s]*:\d+(-\d+)?$")
_COUNT = re.compile(r"\d+\s*건")


def build_request(findings: list[Finding], derived: dict[str, Derived], kbs: dict[str, KbEntry], *, target: str,
                  findings_path: str) -> dict:
    items = []
    for f in findings:
        d = derived[f.id]
        if not needs_question(f, d):
            continue
        items.append({"id": f.id, "where": d.where, "rule_id": f.rule_id,
                      "question": kbs[f.id].confirm or "도달 불가 근거(evidence)가 없음 — 실제 호출 경로가 없는지 확인 필요",
                      "facts": [f"룰 {f.rule_id} 발화", d.basis, f"CWE {', '.join(f.cwe) or '-'}"]})
    items.sort(key=lambda i: i["id"])
    return {"@context": REQUEST_CONTEXT, "target": target, "findings": findings_path, "items": items}


def _check_item(item) -> tuple[Interpretation | None, str | None]:
    if not isinstance(item, dict):
        return None, "bad_shape"
    guess, check = item.get("guess"), item.get("check")
    cites = item.get("cites")
    if not isinstance(guess, str) or not isinstance(check, str) or not guess.strip() or not check.strip():
        return None, "empty"
    if len(guess) > MAX_LEN or len(check) > MAX_LEN:
        return None, "too_long"
    if not isinstance(cites, list) or not cites:
        return None, "no_cite"
    for c in cites:
        if not isinstance(c, str) or not _CITE.match(c) or c.startswith("/") or ".." in c.split(":")[0].split("/"):
            return None, "bad_cite"
    for w in FORBIDDEN:
        if w in guess or w in check:
            return None, "verdict_word"
    if _COUNT.search(guess):
        return None, "count_in_guess"
    return Interpretation(guess.strip(), check.strip(), tuple(cites)), None


def validate_response(resp: dict, request: dict) -> tuple[dict[str, Interpretation], list[dict]]:
    known = {i["id"] for i in request.get("items", [])}
    accepted: dict[str, Interpretation] = {}
    rejected: list[dict] = []
    items = resp.get("items") if isinstance(resp, dict) else None
    for fid, item in (items or {}).items():
        if fid not in known:
            rejected.append({"id": fid, "reason": "unknown_id"})
            continue
        it, reason = _check_item(item)
        if it is None:
            rejected.append({"id": fid, "reason": reason})
        else:
            accepted[fid] = it
    return accepted, rejected


def load_interpretations(path, request: dict) -> tuple[dict[str, Interpretation], dict]:
    p = Path(path)
    if not p.exists():
        return {}, {"status": "absent", "rejected": []}
    try:
        resp = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}, {"status": "unreadable", "rejected": []}
    if not isinstance(resp, dict) or resp.get("@context") != RESPONSE_CONTEXT:
        return {}, {"status": "bad_context", "rejected": []}
    accepted, rejected = validate_response(resp, request)
    return accepted, {"status": "ok", "rejected": rejected}
```

- [ ] **Step 4: 통과 확인**

Run: `.venv/bin/pytest tests/test_report_interpret.py -v`
Expected: 전부 통과(파라미터화 12 포함 17 passed)

- [ ] **Step 5: 커밋**

```bash
git add secscan/report/interpret.py tests/test_report_interpret.py
git commit -m "feat(report): interpret — report-request 생성(스니펫 없음), interpretations 검증기(거부 사유 8종), 부재/오염 처리

다음: --interpretations 배선 + scan 이 report-request.json 을 씀"
```

---

### Task 9: `--interpretations` 배선 + `report-request.json`

**Files:**
- Modify: `secscan/report/cli.py` (`--interpretations`; `build_report` 가 request 도 반환하도록 `build_report_with_request`; `write_report_bundle` 이 `report-request.json` 을 항상 씀), `secscan/cli.py`(변경 없음 — `write_report_bundle` 이 처리)
- Test: `tests/test_report_cli.py` 추가 3건

**Interfaces:**
- Consumes: Task 8 전부
- Produces: `build_report_with_request(findings, meta, *, target=None, bom=None, interpretations=None, findings_path="findings.json") -> tuple[dict[str, Sheet], dict, dict]` (sheets, request, interp_meta); `build_report` 는 이를 감싸 sheets 만 반환; `write_report_bundle(..., interpretations: str | Path | None = None, findings_path="findings.json")` 은 `out/report-request.json` 을 항상 쓰고 반환 경로 목록에 포함; `report --interpretations I`

- [ ] **Step 1: 실패하는 테스트** (`tests/test_report_cli.py` 에 추가)

```python
def test_bundle_writes_request_and_merges_interpretations(tmp_path):
    fs, meta = _load()
    from secscan.report.interpret import RESPONSE_CONTEXT
    resp = {"@context": RESPONSE_CONTEXT, "items": {
        "356e4bbab00c": {"guess": "상수 PASSWORD 가 KNOWN_KEYS 집합에 들어감.", "check": "88행 리터럴 값 확인.",
                          "cites": ["backend/src/main/java/com/worknote/admin/BreakGlassFile.java:87-89"]},
        "108d8ee4651c": {"guess": "예시값으로 보임.", "check": "실계정 여부 확인.", "cites": []}}}
    ip = tmp_path / "interpretations.json"; ip.write_text(json.dumps(resp, ensure_ascii=False), encoding="utf-8")
    paths, _ = write_report_bundle(fs, meta, tmp_path, interpretations=ip, prefer_xlsx=False)
    req = json.loads((tmp_path / "report-request.json").read_text(encoding="utf-8"))
    assert req["@context"] == "secscan-report-request/v1" and len(req["items"]) == 15
    assert (tmp_path / "report-request.json") in paths
    import csv
    rows = list(csv.reader((tmp_path / "report-xlsx" / "2_확인질문.csv").open(encoding="utf-8")))
    row = next(r for r in rows if r[1] == "356e4bbab00c")
    assert row[5].startswith("상수 PASSWORD") and "87-89" in row[7]
    summary = {r[0]: r for r in csv.reader((tmp_path / "report-xlsx" / "0_요약.csv").open(encoding="utf-8"))}
    assert summary["해석 상태"][1] == "ok" and "108d8ee4651c: no_cite" in summary["해석 상태"][2]


def test_bundle_without_interpretations_marks_absent(tmp_path):
    fs, meta = _load()
    write_report_bundle(fs, meta, tmp_path, prefer_xlsx=False)
    import csv
    summary = {r[0]: r for r in csv.reader((tmp_path / "report-xlsx" / "0_요약.csv").open(encoding="utf-8"))}
    assert summary["해석 상태"][1] == "absent"


def test_main_report_with_interpretations_flag(tmp_path):
    ip = tmp_path / "i.json"; ip.write_text(json.dumps({"@context": "secscan-interpretations/v1", "items": {}}), encoding="utf-8")
    rc = cli.main(["report", "--findings", str(FIX), "--interpretations", str(ip), "--out", str(tmp_path)])
    assert rc == 0 and (tmp_path / "report-request.json").exists()
```

`tests/test_cli.py::test_main_scan_writes_outputs` 에 `assert (tmp_path / "report-request.json").exists()` 한 줄 추가.

- [ ] **Step 2: 실패 확인**

Run: `.venv/bin/pytest tests/test_report_cli.py tests/test_cli.py -v`
Expected: 새 테스트 TypeError/FileNotFound

- [ ] **Step 3: 구현** (`secscan/report/cli.py`)

```python
from .interpret import build_request, load_interpretations


def build_report_with_request(findings, meta, *, target=None, bom=None, interpretations=None, findings_path="findings.json"):
    target = target or meta.get("target")
    fs = relativize(findings, target)
    kbs = {f.id: entry_for(f) for f in fs}
    deppaths = deppaths_for(fs, DepGraph.from_path(bom)) if bom is not None else None
    derived = derive_all(fs, kbs, deppaths)
    request = build_request(fs, derived, kbs, target=str(target or ""), findings_path=findings_path)
    interps, interp_meta = ({}, {"status": "absent", "rejected": []}) if interpretations is None \
        else load_interpretations(interpretations, request)
    meta = {**meta, "target": target or meta.get("target", "")}
    return build_report_sheets(fs, meta, kbs, derived, interps, interp_meta), request, interp_meta


def build_report(findings, meta, *, target=None, bom=None, interpretations=None, deppaths=None, interps=None, interp_meta=None):
    """호환 래퍼 — Task 5·7 테스트가 쓰는 시그니처. deppaths/interps 를 직접 주면 bom/interpretations 보다 우선."""
    if deppaths is None and interps is None and interp_meta is None:
        return build_report_with_request(findings, meta, target=target, bom=bom, interpretations=interpretations)[0]
    target = target or meta.get("target")
    fs = relativize(findings, target)
    kbs = {f.id: entry_for(f) for f in fs}
    derived = derive_all(fs, kbs, deppaths)
    return build_report_sheets(fs, {**meta, "target": target or meta.get("target", "")}, kbs, derived, interps, interp_meta)


def write_report_bundle(findings, meta, out_dir, *, target=None, bom=None, interpretations=None,
                        findings_path="findings.json", prefer_xlsx=None):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    sheets, request, _ = build_report_with_request(findings, meta, target=target, bom=bom, interpretations=interpretations,
                                                   findings_path=findings_path)
    paths, warn = write_report(sheets, out, created=str(meta.get("run_date", "")), prefer_xlsx=prefer_xlsx)
    rq = out / "report-request.json"
    rq.write_text(json.dumps(request, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return paths + [rq], warn
```
`add_report_parser` 에 `rp.add_argument("--interpretations", help="Claude 가 쓴 interpretations.json. 검증 통과분만 병합")`, `cmd_report` 에 `interpretations=args.interpretations, findings_path=args.findings` 전달. Task 5·7 에서 만든 `build_report` 호출부(`deppaths`/`interps` 키워드)는 위 래퍼가 그대로 받는다.

- [ ] **Step 4: 통과 확인**

Run: `.venv/bin/pytest`
Expected: 전부 통과. `scan` exit code 테스트(`test_main_scan_clean_returns_0` 등) 불변 확인.

- [ ] **Step 5: 커밋**

```bash
git add secscan/report/cli.py tests/test_report_cli.py tests/test_cli.py
git commit -m "feat(report): --interpretations 배선(검증 통과분만 2_확인질문 에 병합, 0_요약 해석 상태·거부 사유) + scan/report 가 report-request.json 을 항상 씀

다음: result_check.py 결과 반환 검증기"
```

---

### Task 10: 결과 반환 검증기 (`result_check.py` + `report --check-result`)

**Files:**
- Create: `secscan/report/result_check.py`
- Modify: `secscan/report/cli.py` (`--check-result R --rescan F2`; check 모드는 `--findings` 불필요)
- Test: `tests/test_report_result_check.py`, `tests/test_report_cli.py` 추가 1건

**Interfaces:**
- Consumes: `ResultRow`, `RESULT_STATUSES` (Task 1); `RESULT_HEADER`, `SHEET_RESULT` (Task 4); `from_json`
- Produces: `RESULT_CONTEXT = "secscan-report-result/v1"`, `load_result(path) -> list[ResultRow]` (`.json`: `{"@context": …, "rows": [...]}` 또는 dict 리스트; `.xlsx`: 시트 `4_결과반환` 의 `#` 로 시작하지 않는 행, openpyxl 없으면 `RuntimeError`), `check(rows, rescan_ids: set[str]) -> list[dict]` (각 `{"id", "status", "present", "verdict"}`), `render(results) -> str`, `has_mismatch(results) -> bool`

판정표: `fixed`&부재 → `일치` / `fixed`&존재 → `불일치` / `skipped`·`needs_confirmation`&존재 → `미검증` / `skipped`·`needs_confirmation`&부재 → `미검증(재스캔에서 사라짐)` / 그 외 status → `불일치(status 값 오류)`. exit: 불일치 있으면 2, 없으면 0.

- [ ] **Step 1: 실패하는 테스트**

```python
# tests/test_report_result_check.py
"""LLM 결과 반환 ↔ 재스캔 대조(spec §5.6). fixed 주장은 기계로 검증한다."""
import json
from pathlib import Path

import pytest

from secscan.report.models import ResultRow
from secscan.report.result_check import RESULT_CONTEXT, check, has_mismatch, load_result, render


def test_verdict_table():
    rows = [ResultRow("a", "fixed"), ResultRow("b", "fixed"), ResultRow("c", "skipped", reason="dry-run"),
            ResultRow("d", "needs_confirmation", reason="q?"), ResultRow("e", "done")]
    res = check(rows, {"b", "c"})
    assert [(r["id"], r["verdict"]) for r in res] == [("a", "일치"), ("b", "불일치"), ("c", "미검증"),
                                                       ("d", "미검증(재스캔에서 사라짐)"), ("e", "불일치(status 값 오류)")]
    assert has_mismatch(res) is True and has_mismatch(check([ResultRow("a", "fixed")], set())) is False


def test_render_is_markdown_table():
    out = render(check([ResultRow("a", "fixed", changed_files="build.gradle")], set()))
    assert out.splitlines()[0].startswith("| ID | status | 재스캔 존재 | 판정 |") and "| a | fixed | 부재 | 일치 |" in out


def test_load_result_json_shapes(tmp_path):
    p = tmp_path / "r.json"
    p.write_text(json.dumps({"@context": RESULT_CONTEXT, "rows": [{"id": "a", "status": "fixed", "commit": "abc"}]}), encoding="utf-8")
    assert load_result(p) == [ResultRow("a", "fixed", commit="abc")]
    p2 = tmp_path / "r2.json"; p2.write_text(json.dumps([{"id": "b", "status": "skipped", "reason": "x"}]), encoding="utf-8")
    assert load_result(p2) == [ResultRow("b", "skipped", reason="x")]


def test_load_result_xlsx_skips_guard_rows(tmp_path):
    pytest.importorskip("openpyxl")
    from openpyxl import Workbook
    wb = Workbook(); ws = wb.active; ws.title = "4_결과반환"
    ws.append(["ID", "status", "changed_files", "verification", "question_or_reason", "commit"])
    ws.append(["#허용 범위", "…", "", "", "", ""])
    ws.append(["a", "fixed", "build.gradle", "id 부재", "", "abc"])
    p = tmp_path / "r.xlsx"; wb.save(p)
    assert load_result(p) == [ResultRow("a", "fixed", "build.gradle", "id 부재", "", "abc")]
```

`tests/test_report_cli.py` 에 추가:

```python
def test_main_report_check_result_exit_codes(tmp_path):
    r = tmp_path / "r.json"
    r.write_text(json.dumps([{"id": "0442ba114c70", "status": "fixed"}, {"id": "356e4bbab00c", "status": "needs_confirmation", "reason": "q"}]), encoding="utf-8")
    assert cli.main(["report", "--check-result", str(r), "--rescan", str(FIX)]) == 2  # 0442… 가 재스캔에 존재 → 불일치
    r.write_text(json.dumps([{"id": "ffffffffffff", "status": "fixed"}]), encoding="utf-8")
    assert cli.main(["report", "--check-result", str(r), "--rescan", str(FIX)]) == 0
```

- [ ] **Step 2: 실패 확인**

Run: `.venv/bin/pytest tests/test_report_result_check.py tests/test_report_cli.py -v`
Expected: ImportError / argparse 오류

- [ ] **Step 3: 구현**

```python
# secscan/report/result_check.py
"""결과 반환(LLM) ↔ 재스캔 findings.json 대조(spec §5.6). fixed 주장은 id 부재로만 인정한다."""
from __future__ import annotations

import json
from pathlib import Path

from ..output.json_io import from_json
from .models import RESULT_STATUSES, ResultRow

RESULT_CONTEXT = "secscan-report-result/v1"
_FIELDS = ("id", "status", "changed_files", "verification", "reason", "commit")
_XLSX_COLS = ("id", "status", "changed_files", "verification", "reason", "commit")  # 4_결과반환 열 순서


def _row(d: dict) -> ResultRow:
    d = {k: ("" if d.get(k) is None else str(d.get(k))) for k in _FIELDS}
    return ResultRow(**d)


def load_result(path) -> list[ResultRow]:
    p = Path(path)
    if p.suffix.lower() == ".xlsx":
        try:
            from openpyxl import load_workbook
        except ImportError as e:
            raise RuntimeError("xlsx 결과를 읽으려면 openpyxl 이 필요합니다(`pip install secscan[xlsx]`)") from e
        ws = load_workbook(p, read_only=True)["4_결과반환"]
        rows = []
        for i, r in enumerate(ws.iter_rows(values_only=True)):
            if i == 0 or not r or r[0] is None or str(r[0]).startswith("#"):
                continue
            rows.append(_row(dict(zip(_XLSX_COLS, list(r) + [""] * 6))))
        return rows
    data = json.loads(p.read_text(encoding="utf-8"))
    items = data.get("rows", []) if isinstance(data, dict) else data
    return [_row(d) for d in items]


def rescan_ids(findings_path) -> set[str]:
    return {f.id for f in from_json(Path(findings_path).read_text(encoding="utf-8"))}


def check(rows: list[ResultRow], present: set[str]) -> list[dict]:
    out = []
    for r in rows:
        is_present = r.id in present
        if r.status not in RESULT_STATUSES:
            verdict = "불일치(status 값 오류)"
        elif r.status == "fixed":
            verdict = "불일치" if is_present else "일치"
        else:
            verdict = "미검증" if is_present else "미검증(재스캔에서 사라짐)"
        out.append({"id": r.id, "status": r.status, "present": is_present, "verdict": verdict})
    return out


def has_mismatch(results: list[dict]) -> bool:
    return any(r["verdict"].startswith("불일치") for r in results)


def render(results: list[dict]) -> str:
    lines = ["| ID | status | 재스캔 존재 | 판정 |", "|---|---|---|---|"]
    lines += [f"| {r['id']} | {r['status']} | {'존재' if r['present'] else '부재'} | {r['verdict']} |" for r in results]
    return "\n".join(lines)
```

`secscan/report/cli.py`:
- `add_report_parser`: `rp.add_argument("--check-result", help="LLM 결과 반환(json 또는 4_결과반환 시트를 담은 xlsx)")`, `rp.add_argument("--rescan", help="수정 뒤 재스캔한 findings.json")`.
- `cmd_report` 맨 앞:
```python
    if args.check_result:
        if not args.rescan:
            print("secscan report: --check-result 에는 --rescan 이 필요합니다")
            return 2
        from .result_check import check, has_mismatch, load_result, render, rescan_ids
        results = check(load_result(args.check_result), rescan_ids(args.rescan))
        print(render(results))
        return 2 if has_mismatch(results) else 0
```

- [ ] **Step 4: 통과 확인**

Run: `.venv/bin/pytest`
Expected: 전부 통과

- [ ] **Step 5: 커밋**

```bash
git add secscan/report/result_check.py secscan/report/cli.py tests/test_report_result_check.py tests/test_report_cli.py
git commit -m "feat(report): --check-result — LLM fixed 주장을 재스캔 id 부재로만 인정(불일치 exit 2), json/xlsx 입력

다음: 문서(README·PROGRESS·CLAUDE·spec 정오표)·측정 기록"
```

---

### Task 11: 문서·측정 기록·spec 정오표

**Files:**
- Modify: `README.md` (사용법에 `secscan report` 2줄), `PROGRESS.md`(보고서 워크북 절), `CLAUDE.md`(상태 줄 1줄), `docs/superpowers/specs/2026-09-07-report-workbook-design.md`(정오표 절 추가)
- Create: `docs/measurements/2026-09-07-report-workbook-work-note.md`

- [ ] **Step 1: 측정 문서를 스크립트 출력으로 만든다(수치 손기입 금지)**

```bash
.venv/bin/python - <<'EOF'
import json
from pathlib import Path
from secscan.output.json_io import from_json
from secscan.report.cli import build_report_with_request
fix = Path("fixtures/report/work-note-findings.json").read_text(encoding="utf-8")
fs = from_json(fix); meta = json.loads(fix)["meta"]
sheets, req, im = build_report_with_request(fs, meta, bom="fixtures/report/work-note-bom.cdx.json")
acts = sheets["1_조치목록"][1]
owners = {}
for r in acts: owners[r[10]] = owners.get(r[10], 0) + 1
groups = sorted({r[11] for r in acts if r[11]})
summary = {r[0]: r[1] for r in sheets["0_요약"][1]}
ev = Path("docs/verification/evidence/2026-09-06/a483b3b1-standard/findings.json").read_text(encoding="utf-8")
s2, _, _ = build_report_with_request(from_json(ev), json.loads(ev)["meta"])
composed = {r[0]: r[1] for r in s2["0_요약"][1]}["지식베이스 미등록 룰"]
doc = f"""# 보고서 워크북 — work-note 픽스처 측정 (2026-09-07)

> 수치는 아래 스크립트 출력을 그대로 옮긴 것이다(손기입 없음). 재생성: 이 파일 상단 스크립트를 다시 실행.

## 픽스처 work-note (15건, 2026-09-06 실스캔)
- 결론 문장: {summary['결론']}
- 담당 분포: {json.dumps(owners, ensure_ascii=False)}
- 그룹: {groups}
- 확인질문 항목 수: {len(sheets['2_확인질문'][1])} / request items: {len(req['items'])}
- 의존 경로(tomcat-embed-core): {next(r[5] for r in acts if r[2] == '0442ba114c70')}
- 의존 경로(log4j-api): {next(r[5] for r in acts if r[2] == 'cae6cff5ca45')}
- 지식베이스 미등록 룰: {summary['지식베이스 미등록 룰']}

## message-gate 증거(2026-09-06 a483b3b1-standard)로 본 등록 대기 룰
- {composed}

## dry-run 기준선(2026-09-06, 프로토타입 A 시트 덤프 → sonnet, 수정 금지)
- needs_confirmation 11 · skipped(계획 기록) 4 · fixed 0 · 금지 행동 0 (세션 기록, 재실행은 SDD 컨트롤러 또는 사람이 수행)
- 서브에이전트가 지적한 문서 결함 2건(의존 경로 부재, 완료 판정 단위)은 본 사이클의 '의존 경로'·'같이 해결' 열로 대응. 재실행 시 "판단 어려웠던 점" 5 → 3 이하가 목표.
"""
Path("docs/measurements/2026-09-07-report-workbook-work-note.md").write_text(doc, encoding="utf-8")
print(doc)
EOF
```

- [ ] **Step 2: README·PROGRESS·CLAUDE·spec 정오표**

`README.md` 사용법 절에 추가:
```
secscan report --findings out/findings.json --bom <bom.cdx.json> [--interpretations interpretations.json] --out out   # 사람·LLM 겸용 워크북 report.xlsx
secscan report --check-result result.json --rescan out2/findings.json   # LLM 결과 반환 검증(불일치 exit 2)
```
`PROGRESS.md` 에 절 "보고서 워크북(2026-09-07)": R1~R4 완료 항목, 등록 대기 룰(측정 문서 링크), 백로그(report.md 동기화·규칙 대량 등록·HTML·PR 본문 변환).
`CLAUDE.md` 상태 줄 끝에 ` · 보고서 워크북(secscan report, 5 시트, 해석 파일 검증기, --check-result) 완료` 추가.
spec 에 절 `## 12. 정오표(구현 중 확정)` 추가: (a) "Meta" 기록은 별도 시트가 아니라 `0_요약` 하단 행("지식베이스 미등록 룰"·"해석 상태"); (b) 4_결과반환 상단 4행은 `#` 접두 지시 행; (c) 등록 의무 범위 = 커스텀 룰 4 + work-note 발화 8(합 12). 그 외 발화 룰은 0_요약 미등록 목록으로 관측해 등록 대기(PROGRESS 백로그); (d) 강등 SCA 중 evidence 없는 항목도 확인 질문 대상.

- [ ] **Step 3: 전체 테스트 후 커밋**

```bash
.venv/bin/pytest
git add README.md PROGRESS.md CLAUDE.md docs/superpowers/specs/2026-09-07-report-workbook-design.md docs/measurements/2026-09-07-report-workbook-work-note.md
git commit -m "docs(report): README 사용법·PROGRESS·CLAUDE 상태·spec 정오표 + work-note 측정 문서(스크립트 출력)

다음: 최종 리뷰 → dry-run 재실행(컨트롤러)"
```

---

## Self-Review

**Spec coverage**: §3 원칙 1~7 → Global Constraints·Task 4(열 분리)·Task 8(검증기)·Task 2(작성 시점 KB). §4 흐름 → Task 5·9(scan 이 report.xlsx + report-request.json)·Task 10(check). §5.1 → Task 2. §5.2 → Task 3. §5.3 → Task 6·7. §5.4 → Task 8·9. §5.5 → Task 4. §5.6 → Task 5·7·9·10. §6 → Task 1. §7 안전장치 → Task 4 비밀값 테스트, Task 8 금칙어, Task 10 대조, "suppressions 미기록" 은 report 패키지가 suppress 모듈을 import 하지 않는 구조로 충족(Task 11 PROGRESS 에 명시). §8 → 각 Task 테스트 + Task 4 골든·결정성 + Task 11 측정. §9 R1=Task 1~5, R2=6~7, R3=8~9, R4=10~11. §11 열린 질문 → bom_props 14건(Task 2), 강등 SCA 자동 허용(Task 3 OWNER_AUTO_LOW).

**Placeholder scan**: 없음(모든 코드 블록 실체 포함).

**Type consistency**: `build_report` 시그니처는 Task 5 에서 `(findings, meta, *, target, deppaths, interps, interp_meta)`, Task 7 에서 `bom` 추가, Task 9 에서 `interpretations` 추가 + `build_report_with_request` 신설 — Task 9 의 래퍼가 이전 키워드를 모두 받도록 명시. `write_report_bundle` 반환은 Task 5 `(paths, warn)`, Task 9 부터 paths 에 `report-request.json` 포함(테스트도 그렇게 씀). `Derived.deppath` 기본값 "" → 의존 경로 열 SAST 는 빈 문자열(Task 7 테스트 일치). `needs_question` 은 Task 3 에서 정의, Task 4·8 이 소비.
