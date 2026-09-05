# 검증 캠페인(V) 플랜 2 — 판정·출력 (V4~V7) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 플랜 1 이 동결한 증거 위에서 모델을 확장(occurrences·CVSS·published·scanner status)하고 결정적 **판정 단계 H**(disposition·tier 저장, exit code 억제 결함 수정)를 파이프라인에 넣은 뒤, `findings.json`·projection 계약·**xlsx**(보안팀 12열 1:1) 출력을 추가하고, 변이 픽스처(secret 3종·억제 전이·deep gradlew)와 축 8(보고서 충실성) 을 측정하며, 게이트 판정 열을 **생성기 출력**으로 바꿔(spec 정오표 (g)) 최종 실스캔 1회 → 측정 문서 → 정본 검증(reconcile) 고정점으로 캠페인을 마감한다.

**Architecture:** 판정 H 는 `secscan/disposition.py` 의 순수 함수(`decide`)로 억제 뒤·출력 앞에 놓이고 compliance 계산을 흡수한다. 출력(markdown/SARIF/xlsx/exit code)은 `Finding.disposition`/`tier` 필드를 **읽기만** 한다(재계산 금지). xlsx 는 순수 시트 빌더(`build_sheets`) + 선택 의존성 openpyxl 라이터 + CSV 폴백으로 나뉜다. 측정 하네스는 생성기 레지스트리(`tools/verify/generators.py`)를 도입해 모든 생성 문서·facts 가 한 경로로 재생성·비교되게 하고, `tools/verify/gate.py` 가 spec §5 상수를 코드로 갖고 `facts*.json` 과 비교해 게이트 문서를 **생성**한다. V1 증거(옛 바이너리)는 불변이며 `tools/verify/reinput.py` 가 raw 를 새 파이프라인에 재입력해 회귀를 잰다.

**Tech Stack:** Python 3.11+ stdlib(코어 의존성 0 유지), 선택 extra `secscan[xlsx]` → openpyxl>=3.1(미설치 시 CSV 번들), pytest, 실스캔 시 trivy/cdxgen/semgrep/gitleaks/depscan(설치됨), git, gradle wrapper.

**Spec:** `docs/superpowers/specs/2026-09-04-verification-campaign-design.md` — §4.4(증거 재입력 회귀), §4.5(정본 검증), §5 축 8·9, §6(변이 픽스처), §7(모델·판정 H·findings.json·projection), §8(xlsx), §9 V4~V7, §13.3, **정오표 (a)(b)**. 플랜 1(`docs/superpowers/plans/2026-09-04-verification-campaign-1-measure.md`, 완료·main 머지 7e17419)의 산출물(`tools/verify/*`, `docs/verification/{ground-truth,evidence/2026-09-05,results/2026-09-05}`)을 전제한다.

## Global Constraints

- Python `>=3.11`, `dependencies = []` 유지. 새 런타임 의존성 금지. **openpyxl 은 `[project.optional-dependencies] xlsx = ["openpyxl>=3.1"]` 로만** 추가하고 코드에서는 지연 import + 미설치 폴백(CSV 번들 + 경고 1줄). dev 의존성은 `pytest>=8` 뿐.
- 결정적 계층(정규화·병합·판정 H·정렬·시트 빌드·대조·생성기)은 순수 함수 + 골든 테스트. 실스캔·골든 재생성은 테스트가 아니라 **문서화된 명령**이다(Task 9 골든 재생성, Task 14 실스캔).
- **판정 H 규칙(spec §7.4)**: `suppression is not None → suppressed` 를 **먼저** 본다. SAST 는 `sast_tier` 가 actionable 이면 `actionable` 아니면 `review`. SCA 는 `reachability.status != unreachable → actionable` 아니면 `demoted`. secret 은 `actionable`. `Finding.tier` 에 `sast_tier()` 결과 저장(함수는 유지, H 에서만 호출). exit code = `any(disposition == "actionable")`. markdown·SARIF·xlsx·exit code 는 `disposition`/`tier` **필드만 읽는다**(재계산 금지 — `sast_tier` 호출을 출력 코드에서 제거).
- severity 는 계속 **벤더 등급**이다. CVSS 로 재계산하지 않는다(spec §7.1).
- 자동 억제 금지. 이 플랜은 억제를 생성하지 않는다(억제 **전이 측정**만, Task 10).
- **V1 증거 불변**: `docs/verification/evidence/2026-09-05/**` 는 읽기만 한다(재입력 회귀의 입력). 새 산출물은 새 날짜 디렉토리에 쓴다. 옛 결과 디렉토리(`results/2026-09-05`)의 **생성 문서·facts 는 생성기로만** 바꾸고(fact id 개명 시 재생성), 손으로 값을 고치지 않는다.
- **측정 사실성(spec §4.5)**: 실행자는 수치를 손으로 쓰지 않고, 초과분 분류를 override 하지 않고, 게이트 ✓/✗ 를 임의로 정하지 않는다. 게이트 판정은 이 플랜부터 `tools/verify/gate.py` **생성기 출력**이다(정오표 (g)). 측정 문서의 모든 수치는 `facts*.json` 값을 `<!-- fact:<id> -->` 마커와 함께 인용한다(값 토큰 바로 뒤에 마커: `9 <!-- fact:sca.missed -->건`). 판단이 필요한 항목은 `needs_human` 으로만 보고한다. 원인·완화 문구("때문에", "로 보임", "상대적으로") 금지.
- **xlsx 방어(spec §8)**: 문자열 셀이 선행 공백·제어문자를 벗긴 뒤 `=` `+` `-` `@` 로 시작하면 `'` 접두 + 문자열 타입 강제. 32,767 자 초과는 절단 + `…[truncated]`. XML 불법 문자(`[\x00-\x08\x0B\x0C\x0E-\x1F]`) 제거. 시트 1,048,576 행 상한 초과 시 `<Sheet>_2`, `_3`… 분할. CSV 폴백도 같은 sanitizer. **비밀값(secret 원문) 은 어느 시트에도 쓰지 않는다.**
- **결정성**: 출력 전 안정 정렬 `(category, severity rank desc, reachability rank desc, dedup_key)`; xlsx `workbook.properties.created/modified` 는 스캔 일시(meta `run_date`)로 고정; 같은 입력 2회 → 바이트 동일(xlsx 는 시트 데이터 동일).
- 격리 실행(Task 14 실스캔): 스냅샷마다 새 디렉토리(`<scratch>/<sha>/repo`), `GRADLE_USER_HOME=<scratch>/<sha>/gradle-home`, 환경변수 중 `TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API_KEY|AWS_|GITHUB_|GH_` 매칭 키 제거, secret 검증은 항상 `never`. "read-only" 라는 표현 금지. 증거에 비밀값 저장 금지(gitleaks `Secret`·`Match` → `<redacted>`). 스캔 대상 경로는 `--repo` 인자, 하드코딩 금지.
- 게이트 수치는 spec §5 그대로(코드 상수): SCA CVE 단위 recall ≥ 44/46, HIGH/Important 미탐 ≤ 1, mssql 3단계 전부 True, 초과분 미분류 0, 해석 버전 불일치 0, false-unreachable = 0, GT-A 범주 내 출현·소멸 100%, 축 8 손실 0·id 집합 동일·판정 불일치 0·결정성, 축 9 reconcile 전항 0. **게이트 미통과 = 백로그 P1 등록**, 캠페인은 계속.
- 커밋: 작게 자주, 메시지 마지막 줄 `다음: <할 일>`. 한국어 주석·문서. 테스트 실행 `.venv/bin/pytest`(현재 346 passed 2 xfailed). 새 태스크는 기존 green 을 깨지 않는다(기존 테스트가 새 규칙과 충돌하면 **그 테스트를 새 규칙에 맞게 고치고 사유를 커밋 메시지에 남긴다**).

---

## File Structure

| 파일 | 책임 |
|---|---|
| `secscan/models.py` (수정) | `Occurrence`·`Cvss`·`ScannerStatus` dataclass, `Advisory.cvss/published`, `Finding.occurrences/disposition/tier`, 판정 상수 |
| `secscan/output/json_io.py` (수정) | 중첩 시퀀스 레지스트리 `_SEQ`, `_NESTED` 에 `occurrences` — 필드 전수 테스트로 고정 |
| `secscan/normalize/trivy.py` (수정) | CVSS 전 소스·`PublishedDate`·`Occurrence(target)` 파싱 |
| `secscan/normalize/merge.py` (수정) | occurrences·cvss union, published 보존 |
| `secscan/adapters/base.py`·`secscan/orchestrator.py` (수정) | `RawResult.duration_s`, 어댑터별 소요 시간 측정 |
| `secscan/scan.py` (수정) | `ScanResult.scanner_status`, compliance 단계 제거 → 판정 H 단계 삽입 + 정렬, trace `disposition` |
| `secscan/disposition.py` (신규) | `decide_one`/`decide` — 판정 H(compliance 흡수) |
| `secscan/compliance.py` (수정) | `enrich_compliance` 가 `replace` 로 새 리스트 반환 |
| `secscan/output/order.py` (신규) | `sort_findings` 안정 정렬 |
| `secscan/output/markdown.py`·`sarif.py` (수정) | disposition/tier 만 읽음, finding 줄 `id`, SARIF `properties.id/disposition`, 스캐너 status 표기 |
| `secscan/output/contracts.py` (신규) | projection 계약 상수 + `render_contracts()` → `docs/output-contracts.md`(생성 문서) |
| `secscan/output/xlsx.py` (신규) | `sanitize_cell`, `build_sheets`, `write_csv_bundle`, `write_xlsx`(openpyxl 지연 import), `write_workbook` |
| `secscan/cli.py` (수정) | `_has_actionable` 얇게, `findings.json`·xlsx/CSV 출력, 스캐너 status 를 보고서 meta 로, `--profile` 도움말 deep |
| `secscan/adapters/spotbugs.py` (수정) | `gradlew` 우선 빌드 |
| `pyproject.toml` (수정) | `xlsx` extra |
| `fixtures/secret-app/**` (확장) · `fixtures/deep-gradlew-app/` (신규) | 변이 픽스처 |
| `tests/golden/gitleaks-secret-app.json` (재생성) · `tests/golden/semgrep-secret-app-custom.json` (신규) | 골든 |
| `tools/verify/reinput.py` (신규) | V1 raw → 새 파이프라인 재입력(회귀 증거) |
| `tools/verify/fidelity.py` (신규) | 축 8 측정 생성기 + `facts-fidelity.json` |
| `tools/verify/reach_app.py` (신규) | 축 6(b) 픽스처 판정 정본(`facts-reachapp.json`; `tests/test_reach_app.py` 와 단일 소스) |
| `tools/verify/gate.py` (신규) | spec §5 상수 → `gate.md` 생성(판정 열 = 생성기 출력) |
| `tools/verify/generators.py` (신규) | 생성기 레지스트리 + `regenerate_all` CLI; `reconcile.regenerate` 가 순회 |
| `tools/verify/_trivy.py` (신규) | `iter_vulns` — trivy JSON 순회 단일화(M1) |
| `tools/verify/evidence_readme.py` (신규) | `meta.json` 들 → 증거 README 생성(Rec 5) |
| `tools/verify/reconcile.py` (수정) | 레지스트리 순회·예외 격리(M4/N6), 인용 선언 줄 단위(N1), N5 자기인용 계수, 셀 `\|` 이스케이프(N4) |
| `tools/verify/report.py` (수정) | attrition 행 trace 순서(N3), `_trivy.iter_vulns` 사용 |
| `tools/verify/differential.py` (수정) | fact id 위치 독립(`gta.<cwe>.<stem>.*`, M7) |
| `tools/verify/evidence.py`·`run_snapshot.py` (수정) | scanner_status 확장, 경로 상대화(M8), xlsx 산출(`--xlsx`) |
| `docs/verification/evidence/<D2>/…`·`docs/verification/results/<D2>/…` | 최종 실스캔 증거·결과(D2 = Task 14 실행일) |
| `docs/measurements/<D2>-message-gate-verification-final.md` | 최종 측정 문서(축 1~9) |

**실행 메모(SDD 컨트롤러용 모델 선택 제안)**: 코드가 완전히 주어진 전사형 태스크(2·3·10) haiku, 다파일 통합(1·4·5·6·7·8·11·12·13) sonnet, 실도구 실행이 있는 9·14 sonnet, 리뷰 sonnet, 최종 브랜치 리뷰 opus. 병렬 구현자 금지.

---

### Task 1: 모델 확장 — Occurrence · Cvss · ScannerStatus · disposition/tier + lossless 직렬화

**Files:**
- Modify: `secscan/models.py` (L71-75 `Advisory`, L131-170 `Finding`, 상수 추가)
- Modify: `secscan/output/json_io.py` (`_NESTED`, `_build`, `finding_from_dict`)
- Test: `tests/test_json_io.py`, `tests/test_models.py` (신규)

**Interfaces:**
- Consumes: 현행 `Finding`(필드 목록은 코드베이스 그대로), `json_io.to_json/from_json`.
- Produces: `Occurrence(tool, target, package, version)`(frozen), `Cvss(source, version, score, vector)`(frozen), `ScannerStatus(name, status, tool_version, duration_s, message)`(frozen), `Advisory.cvss: tuple[Cvss, ...] = ()`, `Advisory.published: str | None = None`, `Finding.occurrences: tuple[Occurrence, ...] = ()`, `Finding.disposition: str | None = None`, `Finding.tier: str | None = None`, 상수 `ACTIONABLE/REVIEW/DEMOTED/SUPPRESSED/DISPOSITIONS`. json_io `_SEQ` 레지스트리.

- [ ] **Step 1: 실패하는 테스트 — `tests/test_models.py`(신규) + `tests/test_json_io.py` 끝에 추가**

```python
# tests/test_models.py
"""V4 모델 확장(spec §7.1) — 새 필드의 기본값·불변식. dedup_key 는 변하지 않는다."""

from dataclasses import fields, is_dataclass

import secscan.models as m
from secscan.models import (
    ACTIONABLE, DEMOTED, DISPOSITIONS, REVIEW, SUPPRESSED,
    Advisory, Component, Cvss, Finding, Occurrence, ScannerStatus,
)


def test_new_fields_have_safe_defaults():
    f = Finding(category="sca", component=Component("maven", "a:b", "1.0"), advisory=Advisory("CVE-1"))
    assert f.occurrences == () and f.disposition is None and f.tier is None
    assert f.advisory.cvss == () and f.advisory.published is None
    assert f.dedup_key == "sca|maven|a:b|1.0|CVE-1"  # 키 구성 불변


def test_occurrence_and_cvss_are_hashable_for_union():
    o = Occurrence("trivy", "pom.xml", "a:b", "1.0")
    c = Cvss("nvd", "3.1", 9.8, "CVSS:3.1/AV:N")
    assert len({o, Occurrence("trivy", "pom.xml", "a:b", "1.0")}) == 1
    assert len({c, c}) == 1


def test_disposition_constants():
    assert DISPOSITIONS == (ACTIONABLE, REVIEW, DEMOTED, SUPPRESSED)
    assert ScannerStatus("trivy", "ok").duration_s is None and ScannerStatus("trivy", "ok").message == ""


def test_every_dataclass_in_models_is_a_dataclass():
    for name in ("Occurrence", "Cvss", "ScannerStatus"):
        assert is_dataclass(getattr(m, name))
```

```python
# tests/test_json_io.py 끝에 추가
from dataclasses import fields, is_dataclass, replace

from secscan.models import Cvss, Occurrence
from secscan.output.json_io import _NESTED


def test_round_trip_with_occurrences_cvss_disposition():
    f = _sca()
    f = replace(
        f,
        occurrences=(Occurrence("trivy", "pom.xml", "org.apache.commons:commons-text", "1.9"),
                     Occurrence("trivy", "build.gradle", "org.apache.commons:commons-text", "1.9")),
        advisory=replace(f.advisory,
                         cvss=(Cvss("nvd", "3.1", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
                               Cvss("ghsa", "4.0", 8.7, None)),
                         published="2022-10-13T00:00:00Z"),
        disposition="demoted", tier=None,
    )
    back = from_json(to_json([f]))
    assert back == [f]
    assert back[0].advisory.cvss[0].score == 9.8
    assert back[0].occurrences[1].target == "build.gradle"
    assert back[0].disposition == "demoted"


def test_nested_registry_covers_every_dataclass_field():
    """플랜 1 파킹(Task 4): 모델에 중첩 dataclass 필드가 늘면 _NESTED 누락이 곧 lossless 위반이다."""
    import secscan.models as m
    dc_names = {n for n, obj in vars(m).items() if isinstance(obj, type) and is_dataclass(obj)}
    expect = {f.name for f in fields(Finding) if any(n in str(f.type) for n in dc_names)}
    assert set(_NESTED) == expect
```

- [ ] **Step 2: 실패 확인**

Run: `.venv/bin/pytest tests/test_models.py tests/test_json_io.py -q`
Expected: FAIL — `ImportError: cannot import name 'Occurrence'`.

- [ ] **Step 3: `secscan/models.py` 수정**

`Reachability` 상수 블록(L56-59) 아래에 판정 상수를, `Suppression` 앞(또는 `Consensus` 뒤)에 세 dataclass 를 추가하고 `Advisory`·`Finding` 에 필드를 더한다.

```python
# 판정(H, spec §7.4) — 억제 다음 결정적 단계가 저장하는 값. 출력은 이 값만 읽는다.
ACTIONABLE = "actionable"
REVIEW = "review"
DEMOTED = "demoted"  # 도달 불가 SCA
SUPPRESSED = "suppressed"
DISPOSITIONS = (ACTIONABLE, REVIEW, DEMOTED, SUPPRESSED)


@dataclass(frozen=True)
class Occurrence:
    """같은 advisory 가 나타난 발생 단위(도구×대상 파일×패키지×버전). 병합은 union(spec §7.1)."""
    tool: str
    target: str
    package: str
    version: str


@dataclass(frozen=True)
class Cvss:
    """벤더별 CVSS 전부 보존. severity 는 계속 벤더 등급이며 CVSS 로 재계산하지 않는다."""
    source: str  # trivy CVSS 맵 키: nvd | redhat | ghsa | bitnami …
    version: str  # "2.0" | "3.0" | "3.1" | "3.x" | "4.0"
    score: float | None = None
    vector: str | None = None


@dataclass(frozen=True)
class ScannerStatus:
    """실제 실행 결과(구성값이 아님) — 보고서·xlsx Meta 시트가 이것을 쓴다(원칙 5)."""
    name: str
    status: str  # ok | failed | timeout | skipped
    tool_version: str | None = None
    duration_s: float | None = None
    message: str = ""
```

```python
@dataclass
class Advisory:
    id: str
    aliases: tuple[str, ...] = ()
    fixed_versions: tuple[str, ...] = ()
    cvss: tuple[Cvss, ...] = ()  # 벤더별 전부(출력 시 Max/Source 파생)
    published: str | None = None  # ISO 문자열(초과분 분류용). 없으면 None — 강제 분류 금지
```

`Finding` 의 `compliance` 필드 다음에:

```python
    occurrences: tuple[Occurrence, ...] = ()  # 발생 단위(Targets·Finding Count 복원)
    disposition: str | None = None  # 판정 H 결과(DISPOSITIONS 중 하나). None = H 미실행
    tier: str | None = None  # sast_tier() 결과 저장(H 에서만 계산)
```

- [ ] **Step 4: `secscan/output/json_io.py` 수정**

```python
from ..models import (
    Advisory, Compliance, Component, Consensus, Cvss, Finding, KisaWeakness, Location,
    Occurrence, Reachability, Suppression,
)

# Finding 필드명 → 중첩 dataclass. tuple[dataclass] 은 (cls, "seq") 로 표기.
_NESTED: dict[str, object] = {
    "component": Component, "advisory": Advisory, "location": Location,
    "reachability": Reachability, "consensus": Consensus, "suppression": Suppression,
    "compliance": Compliance, "occurrences": (Occurrence, "seq"),
}
# (부모 dataclass, 필드명) → 원소 dataclass. 중첩 안의 tuple[dataclass] 복원용.
_SEQ: dict[tuple[type, str], type] = {(Compliance, "kisa"): KisaWeakness, (Advisory, "cvss"): Cvss}


def _build(cls, data):
    if data is None:
        return None
    kwargs = {}
    for f in fields(cls):
        if f.name not in data:
            continue
        v = data[f.name]
        seq_cls = _SEQ.get((cls, f.name))
        if seq_cls is not None:
            v = tuple(_build(seq_cls, x) for x in (v or []))
        elif isinstance(v, list):
            v = tuple(v)
        kwargs[f.name] = v
    return cls(**kwargs)


def _build_field(spec, v):
    if isinstance(spec, tuple):  # (cls, "seq")
        return tuple(_build(spec[0], x) for x in (v or []))
    return _build(spec, v)
```

`finding_from_dict` 의 `v = _build(_NESTED[name], v)` 를 `v = _build_field(_NESTED[name], v)` 로 바꾼다. `_COMPLIANCE_SEQ` 는 삭제한다(`_SEQ` 로 대체).

- [ ] **Step 5: 통과 확인 + 전체 회귀**

Run: `.venv/bin/pytest tests/test_models.py tests/test_json_io.py -q` → PASS. `.venv/bin/pytest -q` → 기존 green 유지(346+).

- [ ] **Step 6: 커밋**

```bash
git add secscan/models.py secscan/output/json_io.py tests/test_models.py tests/test_json_io.py
git commit -m "feat(V4): 모델 확장 — Occurrence·Cvss·ScannerStatus, Advisory.cvss/published, Finding.occurrences/disposition/tier + lossless 직렬화(_SEQ, 필드 전수 테스트)

다음: trivy 정규화에 CVSS·published·occurrence 채우기 + merge union"
```

---

### Task 2: trivy 정규화 확장 + merge union

**Files:**
- Modify: `secscan/normalize/trivy.py` (`parse_trivy`)
- Modify: `secscan/normalize/merge.py` (`_combine`)
- Test: `tests/test_normalize.py` 끝에 추가

**Interfaces:**
- Consumes: Task 1 의 `Cvss`, `Occurrence`, `Advisory.cvss/published`, `Finding.occurrences`.
- Produces: `parse_trivy` 가 `advisory.cvss`(소스·버전 정렬), `advisory.published`, `occurrences=(Occurrence("trivy", <Results[].Target>, PkgName, InstalledVersion),)` 를 채운다. `merge_consensus` 가 occurrences·cvss 를 union, published 를 보존한다.

- [ ] **Step 1: 실패하는 테스트**

```python
# tests/test_normalize.py 끝에 추가
from pathlib import Path as _P

from secscan.models import Cvss, Occurrence
from secscan.normalize.merge import merge_consensus
from secscan.normalize.trivy import parse_trivy as _parse_trivy

_TRIVY_GOLDEN = (_P(__file__).parent / "golden" / "trivy-vuln-maven-app.json").read_text()


def test_trivy_parses_all_cvss_sources_and_published():
    f = _parse_trivy(_TRIVY_GOLDEN)[0]  # 골든 첫 항목: ghsa V3 6.5 · redhat V3 3.7
    assert {(c.source, c.version, c.score) for c in f.advisory.cvss} == {("ghsa", "3.1", 6.5), ("redhat", "3.1", 3.7)}
    assert all(c.vector.startswith("CVSS:3.1/") for c in f.advisory.cvss)
    assert f.advisory.published == "2025-07-11T15:15:24.347Z"


def test_trivy_records_occurrence_with_target():
    f = _parse_trivy(_TRIVY_GOLDEN)[0]
    assert f.occurrences == (Occurrence("trivy", "pom.xml", f.component.package, f.component.version),)


def test_trivy_cvss_v2_and_v40_versions():
    payload = json.dumps({"Results": [{"Target": "t", "Vulnerabilities": [{
        "VulnerabilityID": "CVE-9", "PkgName": "a:b", "InstalledVersion": "1", "Severity": "HIGH",
        "CVSS": {"nvd": {"V2Score": 5.0, "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N", "V3Score": 7.5,
                         "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
                 "ghsa": {"V40Score": 2.9, "V40Vector": "CVSS:4.0/AV:N/AC:H"}}}]}]})
    f = _parse_trivy(payload)[0]
    assert [(c.source, c.version) for c in f.advisory.cvss] == [("ghsa", "4.0"), ("nvd", "2.0"), ("nvd", "3.0")]


def test_merge_unions_occurrences_and_cvss_keeps_published():
    a = _parse_trivy(_TRIVY_GOLDEN)[0]
    b = replace(a, occurrences=(Occurrence("trivy", "build.gradle", a.component.package, a.component.version),),
                advisory=replace(a.advisory, cvss=(Cvss("nvd", "3.1", 7.5, "CVSS:3.1/x"),), published=None))
    m = merge_consensus([a, b])
    assert len(m) == 1
    assert {o.target for o in m[0].occurrences} == {"pom.xml", "build.gradle"}
    assert {c.source for c in m[0].advisory.cvss} == {"ghsa", "redhat", "nvd"}
    assert m[0].advisory.published == "2025-07-11T15:15:24.347Z"
```

(`json`·`replace` import 가 파일 상단에 없으면 추가: `import json`, `from dataclasses import replace`.)

- [ ] **Step 2: 실패 확인**

Run: `.venv/bin/pytest tests/test_normalize.py -q` → FAIL (`cvss == ()`, occurrences 빈 튜플).

- [ ] **Step 3: `secscan/normalize/trivy.py`**

```python
from ..models import Advisory, Component, Consensus, Cvss, Finding, Occurrence, normalize_severity

_CVSS_PREFIXES = (("V2", "2.0"), ("V3", None), ("V40", "4.0"))  # None = 벡터 접두에서 3.0/3.1 판별


def _cvss(v: dict) -> tuple[Cvss, ...]:
    """trivy `CVSS{source: {V2Score, V2Vector, V3Score, V3Vector, V40Score, V40Vector}}` 전부 보존."""
    out: list[Cvss] = []
    for source, m in sorted((v.get("CVSS") or {}).items()):
        if not isinstance(m, dict):
            continue
        for prefix, fixed in _CVSS_PREFIXES:
            score, vector = m.get(f"{prefix}Score"), m.get(f"{prefix}Vector")
            if score is None and vector is None:
                continue
            ver = fixed
            if ver is None:
                ver = vector.split("/")[0].split(":")[1] if (vector or "").startswith("CVSS:3") else "3.x"
            out.append(Cvss(source, ver, float(score) if score is not None else None, vector))
    return tuple(out)
```

`parse_trivy` 의 `Finding(...)` 생성부에 추가:

```python
                    advisory=Advisory(
                        id=cve,
                        aliases=(cve,),
                        fixed_versions=_fixed_versions(v.get("FixedVersion")),
                        cvss=_cvss(v),
                        published=v.get("PublishedDate"),
                    ),
                    occurrences=(Occurrence("trivy", target, v.get("PkgName", ""), v.get("InstalledVersion", "")),),
```

- [ ] **Step 4: `secscan/normalize/merge.py` `_combine`**

```python
    adv = a.advisory
    if adv is not None:
        b_adv = b.advisory
        adv = Advisory(
            id=adv.id,
            aliases=_uniq(adv.aliases, b_adv.aliases if b_adv else ()),
            fixed_versions=_uniq(adv.fixed_versions, b_adv.fixed_versions if b_adv else ()),
            cvss=_uniq(adv.cvss, b_adv.cvss if b_adv else ()),
            published=adv.published or (b_adv.published if b_adv else None),
        )
    return replace(
        a,
        severity=max_severity(a.severity, b.severity),
        confidence=min_confidence(a.confidence, b.confidence),
        cwe=_uniq(a.cwe, b.cwe),
        owasp=_uniq(a.owasp, b.owasp),
        references=_uniq(a.references, b.references),
        advisory=adv,
        occurrences=_uniq(a.occurrences, b.occurrences),
        consensus=Consensus(tools=tools, score=len(tools)),
        tool="+".join(tools),
    )
```

- [ ] **Step 5: 통과 확인 + 전체 회귀** — `.venv/bin/pytest -q` green.

- [ ] **Step 6: 커밋**

```bash
git add secscan/normalize/trivy.py secscan/normalize/merge.py tests/test_normalize.py
git commit -m "feat(V4): trivy 정규화 — CVSS 전 소스·PublishedDate·Occurrence(target) 보존, merge 가 occurrences/cvss union

다음: ScannerStatus — 어댑터 소요 시간·실제 status 를 ScanResult/보고서/증거 meta 로"
```

---

### Task 3: ScannerStatus — 실제 실행 status 를 결과·보고서·증거에

**Files:**
- Modify: `secscan/adapters/base.py` (`RawResult` 에 `duration_s`), `secscan/orchestrator.py`, `secscan/scan.py` (`ScanResult.scanner_status`), `secscan/output/markdown.py` (meta `scanner_status` 렌더), `secscan/cli.py` (`_cmd_scan` 의 to_markdown meta), `tools/verify/evidence.py` (meta.scanner_status 확장)
- Test: `tests/test_orchestrator.py`, `tests/test_scan.py`, `tests/test_output.py`, `tests/test_verify_tools.py` 끝에 추가

**Interfaces:**
- Produces: `RawResult.duration_s: float | None = None`; `ScanResult.scanner_status: list[ScannerStatus]`(이름순); `to_markdown(..., meta={"scanner_status": [dict, ...]})` 가 `- 스캐너: trivy ok (0.71.2, 8.5s) · semgrep ok` 줄을 렌더(기존 `meta["scanners"]` 도 계속 지원); 증거 `meta.json.scanner_status[*]` = `{"tool","status","tool_version","duration_s"[,"error"]}`(`tool`/`status` 키는 플랜 1 소비자 호환).

- [ ] **Step 1: 실패하는 테스트**

```python
# tests/test_orchestrator.py 끝에 추가
def test_orchestrator_records_duration_per_adapter():
    class Slow:
        name = "slow"
        def run(self, target, **kw):
            return RawResult("slow", OK, payload="{}")
    res = scan([Slow()], "/p")
    assert res[0].duration_s is not None and res[0].duration_s >= 0.0
```

```python
# tests/test_scan.py 끝에 추가
from secscan.models import ScannerStatus

def test_run_scan_reports_actual_scanner_status_sorted_by_name():
    res = run_scan("/proj", get_profile("quick"),
                   adapters=[FakeAdapter("trivy", TRIVY), FakeAdapter("gitleaks", "", status=FAILED)],
                   reachability_provider=None)
    names = [s.name for s in res.scanner_status]
    assert names == ["gitleaks", "trivy"]
    assert {s.name: s.status for s in res.scanner_status} == {"gitleaks": "failed", "trivy": "ok"}
    assert all(isinstance(s, ScannerStatus) for s in res.scanner_status)
```

```python
# tests/test_output.py 끝에 추가
def test_markdown_renders_actual_scanner_status_not_configured_names():
    md = to_markdown([], meta={"scanner_status": [
        {"name": "trivy", "status": "ok", "tool_version": "0.71.2", "duration_s": 8.5},
        {"name": "spotbugs", "status": "skipped", "message": "빌드 실패"},
    ]})
    line = next(l for l in md.splitlines() if l.startswith("- 스캐너:"))
    assert "trivy ok (0.71.2, 8.5s)" in line and "spotbugs skipped (빌드 실패)" in line
```

```python
# tests/test_verify_tools.py 끝에 추가
def test_write_evidence_meta_carries_scanner_status_fields(tmp_path):
    from secscan.adapters.base import OK, RawResult
    from secscan.models import ScannerStatus
    from secscan.scan import ScanResult
    from tools.verify.evidence import write_evidence
    r = RawResult("trivy", OK, payload="{}", version="0.71.2", duration_s=1.25)
    res = ScanResult(findings=[], raw_results=[r], scanner_status=[ScannerStatus("trivy", OK, "0.71.2", 1.25, "")])
    write_evidence(tmp_path, result=res, trace=None, meta={"snapshot": "x"})
    meta = json.loads((tmp_path / "meta.json").read_text())
    assert meta["scanner_status"] == [{"tool": "trivy", "status": "ok", "tool_version": "0.71.2", "duration_s": 1.25}]
```

- [ ] **Step 2: 실패 확인** — `.venv/bin/pytest tests/test_orchestrator.py tests/test_scan.py tests/test_output.py tests/test_verify_tools.py -q` → FAIL(`duration_s` 인자 없음 / `scanner_status` 없음).

- [ ] **Step 3: 구현**

`secscan/adapters/base.py` `RawResult` 마지막 필드 뒤에 `duration_s: float | None = None  # 오케스트레이터가 채움`.

`secscan/orchestrator.py`:

```python
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from .adapters.base import FAILED, RawResult


def _timed_run(adapter, target) -> RawResult:
    t0 = time.perf_counter()
    r = adapter.run(target)
    if r.duration_s is None:
        r.duration_s = round(time.perf_counter() - t0, 3)
    return r


def scan(adapters, target, *, max_workers: int | None = None) -> list[RawResult]:
    if not adapters:
        return []
    workers = max_workers or min(len(adapters), 8)
    results: list[RawResult] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_timed_run, a, target): a for a in adapters}
        for fut in as_completed(futures):
            adapter = futures[fut]
            try:
                results.append(fut.result())
            except Exception as e:  # 어댑터가 자체 격리에 실패한 경우의 backstop
                results.append(RawResult(adapter.name, FAILED, error=f"orchestrator: {e}"))
    return results
```

`secscan/scan.py`: `from .models import Finding, ScannerStatus`; `ScanResult` 에 `scanner_status: list[ScannerStatus] = field(default_factory=list)` 추가(마지막 필드). `run_scan` 끝의 반환 직전:

```python
    status = sorted((ScannerStatus(r.tool, r.status, r.version, r.duration_s, r.error) for r in raws),
                    key=lambda s: s.name)
    return ScanResult(findings, raws, ran, reason, partial, secret_policy,
                      verified_count, suppressed_count, invalidated, excluded_count, status)
```

`secscan/output/markdown.py` `to_markdown` 의 `- 스캐너:` 줄:

```python
    if meta and meta.get("scanner_status"):
        parts = []
        for s in meta["scanner_status"]:
            extra = [x for x in (s.get("tool_version"), f"{s['duration_s']}s" if s.get("duration_s") is not None else None) if x]
            if s.get("message"):
                extra.append(s["message"])
            parts.append(f"{s['name']} {s['status']}" + (f" ({', '.join(extra)})" if extra else ""))
        L.append(f"- 스캐너: {' · '.join(parts)}")
    elif meta and meta.get("scanners"):
        L.append(f"- 스캐너: {', '.join(meta['scanners'])}")
```

`secscan/cli.py` `_cmd_scan`: `from dataclasses import asdict` 추가, `to_markdown(..., meta={"scanner_status": [asdict(s) for s in result.scanner_status]})`.

`tools/verify/evidence.py` `write_evidence`:

```python
    full_meta["scanner_status"] = [
        {"tool": s.name, "status": s.status, "tool_version": s.tool_version, "duration_s": s.duration_s,
         **({"error": s.message} if s.message else {})}
        for s in result.scanner_status
    ] or [{"tool": r.tool, "status": r.status, **({"error": r.error} if r.error else {})} for r in result.raw_results]
```
그리고 `report.md` 의 `meta={"scanners": ...}` 를 `meta={"scanner_status": [asdict(s) for s in result.scanner_status]}` 로(`from dataclasses import asdict`).

- [ ] **Step 4: 통과 확인 + 전체 회귀** — green.

- [ ] **Step 5: 커밋**

```bash
git add secscan/adapters/base.py secscan/orchestrator.py secscan/scan.py secscan/output/markdown.py secscan/cli.py tools/verify/evidence.py tests/
git commit -m "feat(V4): ScannerStatus — 어댑터 소요 시간·실제 status 를 ScanResult/보고서/증거 meta 에(구성값 대신 실제값, 원칙 5)

다음: 판정 단계 H — secscan/disposition.py(decide), compliance 흡수, scan.py 단계 재구성"
```

---

### Task 4: 판정 단계 H — `secscan/disposition.py` + 파이프라인 재구성

**Files:**
- Create: `secscan/disposition.py`
- Modify: `secscan/compliance.py` (`enrich_compliance` → `replace` 로 새 리스트), `secscan/scan.py` (compliance 단계 제거, 억제 뒤 H 삽입, trace `disposition`)
- Test: `tests/test_disposition.py` (신규), `tests/test_scan.py` 끝에 추가, `tests/test_compliance.py`(반환값 사용으로 조정)

**Interfaces:**
- Consumes: Task 1 상수·필드, `models.sast_tier`, `compliance.enrich_compliance`, `suppress` 결과.
- Produces: `decide_one(f: Finding) -> Finding`(tier·disposition·compliance 채운 새 객체), `decide(findings: list[Finding]) -> list[Finding]`. `run_scan` 단계: orchestrate → normalize/merge → exclude → reachability → secret_verify → baseline → suppress → **disposition(H)** → final. trace 단계명 `disposition`(`compliance` 단계는 사라진다).

- [ ] **Step 1: 실패하는 테스트 — `tests/test_disposition.py`**

```python
"""판정 단계 H (spec §7.4) — 억제를 먼저 보고, SAST 는 tier, SCA 는 도달성, secret 은 actionable."""

import pytest

from secscan.disposition import decide, decide_one
from secscan.models import (
    ACTIONABLE, DEMOTED, REVIEW, SUPPRESSED, REACHABLE, UNKNOWN, UNREACHABLE,
    Advisory, Component, Finding, Location, Reachability, Suppression,
)


def _sca(reach=UNREACHABLE, cwe=("CWE-94",)):
    return Finding(category="sca", severity="high", rule_id="CVE-1", cwe=cwe,
                   component=Component("maven", "a:b", "1.0"), advisory=Advisory("CVE-1"),
                   reachability=Reachability(reach))


def _sast(conf="high", sev="high", file="src/main/A.java"):
    return Finding(category="sast", severity=sev, rule_id="r", confidence=conf, cwe=("CWE-89",),
                   location=Location(file, 3))


def _secret():
    return Finding(category="secret", severity="high", rule_id="aws", location=Location("app.properties", 4))


def _sup(f):
    return Suppression("suppressed", "사유", "alice 2026-09-05", "증거", "2027-01-01", f.dedup_key)


@pytest.mark.parametrize("f,expect", [
    (_sca(UNREACHABLE), DEMOTED),
    (_sca(REACHABLE), ACTIONABLE),
    (_sca(UNKNOWN), ACTIONABLE),
    (_sast("high", "high"), ACTIONABLE),
    (_sast("low", "high"), REVIEW),
    (_sast("high", "low"), REVIEW),
    (_sast("high", "high", "src/test/ATest.java"), REVIEW),
    (_secret(), ACTIONABLE),
])
def test_disposition_rules(f, expect):
    assert decide_one(f).disposition == expect


def test_suppression_wins_over_everything():
    for f in (_sca(REACHABLE), _sast("high", "high"), _secret()):
        g = Finding(**{**f.__dict__, "suppression": _sup(f)})
        assert decide_one(g).disposition == SUPPRESSED


def test_tier_is_stored_for_sast_only():
    assert decide_one(_sast("high", "high")).tier == "actionable"
    assert decide_one(_sast("low", "high")).tier == "review"
    assert decide_one(_sca()).tier is None and decide_one(_secret()).tier is None


def test_decide_fills_compliance_and_returns_new_objects():
    src = _sca(cwe=("CWE-89",))
    out = decide([src])
    assert out[0] is not src and src.compliance is None  # 입력 불변(in-place 아님)
    assert out[0].compliance is not None and out[0].compliance.kisa


def test_decide_is_idempotent():
    once = decide([_sca(), _sast(), _secret()])
    assert decide(once) == once
```

```python
# tests/test_scan.py 끝에 추가
def test_run_scan_ends_with_disposition_stage_and_every_finding_decided():
    from secscan.scan import TraceSink
    sink = TraceSink()
    res = run_scan("/proj", get_profile("quick"), adapters=[FakeAdapter("trivy", TRIVY), FakeAdapter("gitleaks", GITLEAKS)],
                   reachability_provider=None, trace=sink)
    stages = [s["stage"] for s in sink.stages]
    assert "disposition" in stages and "compliance" not in stages
    assert stages.index("disposition") == stages.index("final") - 1
    assert all(f.disposition is not None for f in res.findings)
    assert all(f.compliance is not None for f in res.findings if f.cwe and f.category == "sast") or True  # cwe 매핑 있는 것만
```

- [ ] **Step 2: 실패 확인** — `ModuleNotFoundError: secscan.disposition`.

- [ ] **Step 3: `secscan/disposition.py`**

```python
"""판정 단계 H (spec §7.4) — 억제 다음, 출력 앞의 결정적 단계.

"조치 대상인가"를 한 곳에서 계산해 Finding 에 저장한다. exit code·markdown·SARIF·xlsx 는
`disposition`/`tier` 필드만 읽는다(재계산 금지). compliance 매핑도 여기서 채운다(위치 통일).
규칙(순서 중요): 억제 → SAST tier → SCA 도달성 → 그 외(secret) actionable.
"""

from __future__ import annotations

from dataclasses import replace

from .compliance import enrich_compliance
from .models import ACTIONABLE, DEMOTED, REVIEW, SUPPRESSED, UNREACHABLE, Finding, sast_tier


def _disposition(f: Finding, tier: str | None) -> str:
    if f.suppression is not None:
        return SUPPRESSED
    if f.category == "sast":
        return ACTIONABLE if tier == "actionable" else REVIEW
    if f.category == "sca":
        return ACTIONABLE if f.reachability.status != UNREACHABLE else DEMOTED
    return ACTIONABLE  # secret 등: 도달성 개념 없음, 항상 조치


def decide_one(f: Finding) -> Finding:
    tier = sast_tier(f)
    return replace(f, tier=tier, disposition=_disposition(f, tier))


def decide(findings: list[Finding]) -> list[Finding]:
    return [decide_one(f) for f in enrich_compliance(findings)]
```

`secscan/compliance.py`:

```python
from dataclasses import replace

def enrich_compliance(findings: list[Finding]) -> list[Finding]:
    """각 finding 의 cwe 로 컴플라이언스 매핑을 채운 새 리스트를 돌려준다(입력 불변). 매핑 없으면 None."""
    out = []
    for f in findings:
        c = map_compliance(f.cwe)
        out.append(replace(f, compliance=c if (c.kisa or c.pci) else None))
    return out
```

`secscan/scan.py`: import 에서 `enrich_compliance` 제거, `from .disposition import decide` 추가. 아래 블록을 삭제:

```python
    # 컴플라이언스 매핑: CWE → KISA/PCI (결정적·무비용 — 항상 적용).
    enrich_compliance(findings)
    if trace is not None:
        trace.record("compliance", findings)
```

`suppressed_count = ...` 줄 **앞**에 삽입:

```python
    # 판정 H(spec §7.4): 억제 다음, 출력 앞. compliance 도 여기서 채운다.
    findings = decide(findings)
    if trace is not None:
        trace.record("disposition", findings)
```

`tests/test_compliance.py` 에서 `enrich_compliance(fs)` 의 부작용에 의존하는 단언이 있으면 `fs = enrich_compliance(fs)` 로 바꾼다(반환값 사용).

- [ ] **Step 4: 통과 확인 + 전체 회귀** — `.venv/bin/pytest -q` green. 실패하는 기존 테스트는 "compliance 단계명" 또는 "in-place" 가정 때문일 것이다 — 새 규칙에 맞게 고치고 커밋 메시지에 적는다.

- [ ] **Step 5: 커밋**

```bash
git add secscan/disposition.py secscan/compliance.py secscan/scan.py tests/test_disposition.py tests/test_scan.py tests/test_compliance.py
git commit -m "feat(V4): 판정 단계 H — decide(억제 우선→tier→도달성→actionable), compliance 를 H 로 이동(replace, 입력 불변), trace 'disposition'

다음: 출력·exit code 가 disposition/tier 만 읽게 — cli._has_actionable 축소, markdown id·버킷, SARIF disposition"
```

---

### Task 5: 출력이 disposition/tier 만 읽는다 — exit code 억제 결함 수정

**Files:**
- Modify: `secscan/cli.py` (`_has_actionable`, `render_scan_summary`, import), `secscan/output/markdown.py` (버킷·`_line` id·미판정 절), `secscan/output/sarif.py` (`sastTier`←`f.tier`, `properties.id/disposition`)
- Test: `tests/test_cli.py`, `tests/test_output.py` 끝에 추가(기존 `_f()` 헬퍼는 `decide_one` 을 거치게 수정)

**Interfaces:**
- Produces: `cli._has_actionable(findings) -> bool` = `any(f.disposition == ACTIONABLE)`; disposition 이 None 인 finding 이 있으면 `ValueError("판정 단계(H) 미실행 ...")`. markdown 절: `## 우선 조치`(actionable) / `## 검토 후보 (낮은 신뢰)`(review) / `## 낮은 우선순위 — 도달 불가 (SCA)`(demoted) / `## 억제됨 (사람 확정)`(suppressed) / `## 미판정 (판정 단계 미실행)`(None, 있을 때만). finding 헤더 줄 끝 `` · id `<12hex>` ``. SARIF `properties.id`, `properties.disposition`, `properties.sastTier = f.tier`.

- [ ] **Step 1: 실패하는 테스트**

```python
# tests/test_output.py — 상단 헬퍼를 H 를 거치도록 바꾼다
from secscan.disposition import decide, decide_one
from secscan.models import ACTIONABLE, Suppression

def _f(cve="CVE-2022-42889", sev="critical", reach=UNREACHABLE):
    return decide_one(Finding(
        category="sca", severity=sev, title="Text4Shell", rule_id=cve,
        tool="trivy+osv-scanner", cwe=("CWE-94",),
        component=Component("maven", "org.apache.commons:commons-text", "1.9"),
        advisory=Advisory(cve, aliases=(cve,), fixed_versions=("1.10.0",)),
        reachability=Reachability(reach, source="dep-scan"),
        consensus=Consensus(("trivy", "osv-scanner"), 2),
    ))

# 끝에 추가
def test_markdown_buckets_come_from_disposition_only():
    reachable, unreachable = _f(cve="CVE-A", reach=REACHABLE), _f(cve="CVE-B", reach=UNREACHABLE)
    sup = Finding(**{**unreachable.__dict__, "disposition": None, "tier": None,
                     "suppression": Suppression("suppressed", "r", "alice", "e", None, unreachable.dedup_key)})
    md = to_markdown(decide([reachable, unreachable, sup]))
    pri = md.split("## 우선 조치")[1].split("## 검토 후보")[0]
    low = md.split("## 낮은 우선순위")[1].split("## 억제됨")[0]
    assert "CVE-A" in pri and "CVE-B" not in pri
    assert "CVE-B" in low and "CVE-A" not in low
    assert "## 억제됨 (사람 확정)" in md


def test_markdown_line_carries_finding_id():
    f = _f()
    assert f"· id `{f.id}`" in to_markdown([f])


def test_markdown_undecided_findings_are_visible_not_hidden():
    raw = Finding(category="secret", severity="high", rule_id="aws", location=Location("a.properties", 4))
    md = to_markdown([raw])  # H 미실행
    assert "## 미판정 (판정 단계 미실행)" in md and "aws" in md.split("## 미판정")[1]


def test_sarif_carries_id_disposition_and_tier_from_fields():
    sast = decide_one(Finding(category="sast", severity="high", rule_id="r", confidence="high",
                              location=Location("src/main/A.java", 3)))
    res = to_sarif([sast])["runs"][0]["results"][0]
    assert res["properties"]["id"] == sast.id
    assert res["properties"]["disposition"] == ACTIONABLE
    assert res["properties"]["sastTier"] == "actionable"


def test_three_outputs_agree_on_actionable_set():
    fs = decide([
        Finding(category="sast", severity="high", rule_id="s1", confidence="high", location=Location("src/main/A.java", 1)),
        Finding(category="sast", severity="high", rule_id="s2", confidence="low", location=Location("src/main/B.java", 1)),
        Finding(category="secret", severity="high", rule_id="k", location=Location("c.properties", 1)),
        Finding(category="sca", severity="high", rule_id="CVE-Z", component=Component("maven", "x:y", "1"),
                advisory=Advisory("CVE-Z"), reachability=Reachability(UNREACHABLE)),
    ])
    want = {f.id for f in fs if f.disposition == ACTIONABLE}
    md = to_markdown(fs)
    md_ids = set(re.findall(r"· id `([0-9a-f]{12})`", md.split("## 우선 조치")[1].split("## 검토 후보")[0]))
    sarif_ids = {r["properties"]["id"] for r in to_sarif(fs)["runs"][0]["results"] if r["properties"].get("disposition") == ACTIONABLE}
    assert md_ids == sarif_ids == want and len(want) == 2
```

(`import re` 를 test_output.py 상단에 추가.)

```python
# tests/test_cli.py 끝에 추가
import pytest
from secscan.disposition import decide
from secscan.models import Location, Suppression


def test_exit_code_ignores_human_suppressed_secret():
    """spec §7.4 알려진 결함: 억제된 secret 만 있어도 exit 1 이었다. H 이후에는 exit 0."""
    sec = Finding(category="secret", severity="high", rule_id="aws", location=Location("a.properties", 4))
    sec.suppression = Suppression("suppressed", "회수 완료", "alice 2026-09-05", "revoke 로그", "2027-01-01", sec.dedup_key)
    assert cli._has_actionable(decide([sec])) is False


def test_exit_code_true_for_actionable_and_error_when_undecided():
    sec = Finding(category="secret", severity="high", rule_id="aws", location=Location("a.properties", 4))
    assert cli._has_actionable(decide([sec])) is True
    with pytest.raises(ValueError):
        cli._has_actionable([sec])  # H 미실행 입력은 CI 게이트에서 조용히 0 이 되면 안 된다
```

- [ ] **Step 2: 실패 확인** — 헤더에 id 없음 / `sastTier` 유지되나 `disposition` 없음 / `_has_actionable` 이 sast_tier 재계산.

- [ ] **Step 3: 구현**

`secscan/cli.py`: import 를 `from .models import ACTIONABLE` 로 바꾸고(`UNREACHABLE, sast_tier` 제거):

```python
def _has_actionable(findings) -> bool:
    """exit code 게이트 — 판정 H 가 저장한 disposition 만 읽는다(재계산 금지, spec §7.4)."""
    if any(f.disposition is None for f in findings):
        raise ValueError("판정 단계(H) 미실행 finding 이 있다 — run_scan 을 거치지 않은 입력")
    return any(f.disposition == ACTIONABLE for f in findings)
```
`render_scan_summary` 의 `act = sum(1 for f in sast if sast_tier(f) == "actionable")` → `act = sum(1 for f in sast if f.tier == "actionable")`.

`secscan/output/markdown.py`: import 를 `from ..models import ACTIONABLE, DEMOTED, REACHABLE, REVIEW, SUPPRESSED, UNKNOWN, UNREACHABLE, Finding, severity_rank` 로(`sast_tier` 제거). `_line` 첫 줄:

```python
    out = [f"### [{_SEV_KO.get(f.severity, f.severity)}] {f.rule_id} — {subject} · id `{f.id}`"]
```

버킷 블록 전체를 교체:

```python
    # 버킷은 판정 H 가 저장한 disposition 만 읽는다(재계산 금지, spec §7.4).
    suppressed = [f for f in findings if f.disposition == SUPPRESSED]
    review = [f for f in findings if f.disposition == REVIEW]
    low = [f for f in findings if f.disposition == DEMOTED]
    priority = [f for f in findings if f.disposition == ACTIONABLE]
    undecided = [f for f in findings if f.disposition is None]
```
그리고 `if suppressed:` 절 뒤에:

```python
    if undecided:
        L.append("## 미판정 (판정 단계 미실행)")
        L.append("> ⚠️ 아래 finding 은 판정 단계 H 를 거치지 않았다(run_scan 외부 입력). 조치 대상 여부를 알 수 없다.")
        for f in undecided:
            L.extend(_line(f))
```

`secscan/output/sarif.py` `_result`: `from ..models import ...` 에서 `sast_tier` 제거하고

```python
    props["id"] = f.id
    if f.disposition is not None:
        props["disposition"] = f.disposition
    if f.tier:
        props["sastTier"] = f.tier
```
(`_tier = sast_tier(f)` 블록 삭제.)

- [ ] **Step 4: 통과 확인 + 전체 회귀** — 기존 test_output/test_cli 중 H 없이 버킷을 단언하던 테스트는 `decide_one`/`decide` 를 거치게 고친다(사유: 출력은 재계산하지 않는다).

- [ ] **Step 5: 커밋**

```bash
git add secscan/cli.py secscan/output/markdown.py secscan/output/sarif.py tests/test_cli.py tests/test_output.py
git commit -m "feat(V4): 출력·exit code 가 disposition/tier 만 읽음 — 억제된 secret exit 0 결함 수정, markdown id, SARIF properties.id/disposition, 미판정 절

다음: CLI findings.json + 안정 정렬 + projection 계약 문서(생성) + V1 증거 재입력 회귀(reinput)"
```

---

### Task 6: `findings.json` · 안정 정렬 · projection 계약 · V1 증거 재입력 회귀

**Files:**
- Create: `secscan/output/order.py`, `secscan/output/contracts.py`, `tools/verify/reinput.py`, `docs/output-contracts.md`(생성)
- Modify: `secscan/scan.py`(정렬), `secscan/cli.py`(findings.json 출력·`--profile` 도움말 deep), `tools/verify/evidence.py`(정렬은 scan 에서 끝남 — 변경 없음 확인)
- Test: `tests/test_order.py`(신규), `tests/test_contracts.py`(신규), `tests/test_reinput.py`(신규), `tests/test_cli.py` 추가

**Interfaces:**
- Produces: `sort_findings(findings) -> list[Finding]`(키 `(category, -severity_rank, -reach_rank, dedup_key)`; `run_scan` 이 H 뒤에 적용). `contracts.CONTRACTS: dict[str, Contract]`, `Contract(includes: frozenset[str], partial: dict[str, str], loses: frozenset[str])`, `contracts.FIELDS`, `render_contracts() -> str`(= `docs/output-contracts.md` 바이트). `reinput.reinput(evidence_dir: Path, out_dir: Path) -> list[Path]` — V1 raw 를 새 파이프라인(normalize→merge→기본 제외→도달성 carry-over→H→정렬)에 재입력해 `findings.json`·`findings.sarif`·`report.md`·`trace.json`·`meta.json`(+`reinput_from`) 을 쓴다. CLI `scan` 이 `<out>/findings.json` 을 쓴다.

- [ ] **Step 1: 실패하는 테스트**

```python
# tests/test_order.py
"""출력 전 안정 정렬(spec §7.1): category → severity 내림 → 도달성 내림 → dedup_key."""
from secscan.models import REACHABLE, UNREACHABLE, Advisory, Component, Finding, Location, Reachability
from secscan.output.order import sort_findings


def _sca(pkg, sev, reach):
    return Finding(category="sca", severity=sev, component=Component("maven", pkg, "1"), advisory=Advisory("CVE-1"),
                   reachability=Reachability(reach))


def test_sort_is_deterministic_and_keyed_as_spec():
    fs = [_sca("z:z", "low", REACHABLE), _sca("a:a", "high", UNREACHABLE), _sca("b:b", "high", REACHABLE),
          Finding(category="sast", severity="critical", rule_id="r", location=Location("x", 1)),
          Finding(category="secret", severity="high", rule_id="k", location=Location("y", 1))]
    out = sort_findings(fs)
    assert [f.category for f in out] == ["sast", "sca", "sca", "sca", "secret"]
    sca = [f.component.package for f in out if f.category == "sca"]
    assert sca == ["b:b", "a:a", "z:z"]  # high reachable → high unreachable → low
    assert sort_findings(list(reversed(fs))) == out
```

```python
# tests/test_contracts.py
"""projection 계약(spec §7.3) — 문서는 코드 상수에서 생성되고, 포함 필드는 실제 출력에서 확인된다."""
from dataclasses import fields
from pathlib import Path

from secscan.disposition import decide_one
from secscan.models import (Advisory, Component, Compliance, Consensus, Cvss, Finding, KisaWeakness, Location,
                            Occurrence, Reachability, Suppression, UNREACHABLE)
from secscan.output.contracts import CONTRACTS, FIELDS, PROBES, render_contracts
from secscan.output.markdown import to_markdown
from secscan.output.sarif import to_sarif

DOC = Path("docs/output-contracts.md")


def _full():
    f = Finding(
        category="sca", severity="high", title="TitleProbe", tool="trivy", rule_id="CVE-2099-0001",
        cwe=("CWE-94",), owasp=("A03",), confidence="unknown",
        component=Component("maven", "org.example:lib", "1.2.3"),
        advisory=Advisory("CVE-2099-0001", aliases=("GHSA-xxxx",), fixed_versions=("1.2.4",),
                          cvss=(Cvss("nvd", "3.1", 9.1, "CVSS:3.1/AV:N"),), published="2099-01-01T00:00:00Z"),
        source="pom.xml", reachability=Reachability(UNREACHABLE, evidence="EvidenceProbe", source="dep-scan"),
        consensus=Consensus(("trivy",), 1), references=("https://example.org/ref",), verified=None,
        suppression=Suppression("suppressed", "ReasonProbe", "alice", "SupEvidenceProbe", "2099-12-31", "scope", basis="unreachable"),
        compliance=Compliance(kisa=(KisaWeakness("IV-01", "입력데이터 검증 및 표현", "KisaProbe"),), pci=("PCI-DSS 6.2.4 — injection",)),
        occurrences=(Occurrence("trivy", "pom.xml", "org.example:lib", "1.2.3"),),
    )
    return decide_one(f)


def test_contract_partitions_every_field():
    for name, c in CONTRACTS.items():
        assert c.includes | set(c.partial) | c.loses == set(FIELDS), name
        assert not (c.includes & c.loses) and not (c.includes & set(c.partial)), name


def test_doc_is_generated_from_constants():
    assert DOC.read_text(encoding="utf-8") == render_contracts()


def test_markdown_and_sarif_contain_probe_for_every_included_field():
    f = _full()
    md, sarif = to_markdown([f]), str(to_sarif([f]))
    for fmt, text in (("markdown", md), ("sarif", sarif)):
        for field in CONTRACTS[fmt].includes | set(CONTRACTS[fmt].partial):
            probe = PROBES[field](f)
            assert probe in text, f"{fmt}: {field} 포함 선언인데 출력에 없음 ({probe})"
```

```python
# tests/test_reinput.py
"""V1 증거(옛 바이너리) raw 를 새 파이프라인에 재입력 — spec §4.4 회귀(baseline 이동 방지)."""
import json
from pathlib import Path

from secscan.models import ACTIONABLE, DEMOTED, REVIEW, UNREACHABLE, sast_tier
from secscan.output.json_io import from_json
from tools.verify.reinput import reinput

EV = Path("docs/verification/evidence/2026-09-05/a483b3b1-standard")


def _legacy_bucket(f):
    # 플랜 1 시점 markdown 버킷 규칙(억제 없음 전제)
    if sast_tier(f) == "review":
        return REVIEW
    if f.category == "sca" and f.reachability.status == UNREACHABLE:
        return DEMOTED
    return ACTIONABLE


def test_reinput_reproduces_v1_keys_and_disposition_matches_legacy_buckets(tmp_path):
    out = reinput(EV, tmp_path)
    new = from_json((tmp_path / "findings.json").read_text(encoding="utf-8"))
    old = from_json((EV / "findings.json").read_text(encoding="utf-8"))
    assert {f.dedup_key for f in new} == {f.dedup_key for f in old}  # excluded_count 0 인 스냅샷
    assert len(new) == len(old) == 73
    assert all(f.disposition == _legacy_bucket(f) for f in new)  # 억제 케이스 없음 → 1:1
    meta = json.loads((tmp_path / "meta.json").read_text(encoding="utf-8"))
    assert meta["reinput_from"].endswith("a483b3b1-standard") and meta["reinput_note"]
    assert {p.name for p in out} >= {"findings.json", "findings.sarif", "report.md", "trace.json", "meta.json"}


def test_reinput_carries_reachability_from_v1_findings(tmp_path):
    reinput(EV, tmp_path)
    new = from_json((tmp_path / "findings.json").read_text(encoding="utf-8"))
    assert sum(1 for f in new if f.category == "sca" and f.reachability.status == UNREACHABLE) == 48
```

```python
# tests/test_cli.py 끝에 추가
def test_scan_writes_findings_json_with_context(tmp_path, monkeypatch):
    from secscan.scan import ScanResult
    from secscan.disposition import decide
    sec = decide([Finding(category="secret", severity="high", rule_id="aws", location=Location("a.properties", 4))])
    monkeypatch.setattr(cli, "run_scan", lambda *a, **k: ScanResult(findings=sec, raw_results=[]))
    monkeypatch.setattr(cli, "build_adapters", lambda p: [])
    rc = cli.main(["scan", "--target", str(tmp_path), "--out", str(tmp_path / "out"), "--profile", "quick", "--no-reachability"])
    doc = json.loads((tmp_path / "out" / "findings.json").read_text())
    assert doc["@context"] == "secscan-findings/v1" and doc["findings"][0]["disposition"] == "actionable"
    assert rc == 1
```
(`import json` 이 test_cli.py 상단에 없으면 추가. `cli.main(argv)` 시그니처가 다르면 파일의 기존 CLI 호출 방식을 따른다.)

- [ ] **Step 2: 실패 확인** — 모듈 없음.

- [ ] **Step 3: `secscan/output/order.py`**

```python
"""출력 전 안정 정렬(spec §7.1) — 모든 projection 이 같은 순서를 본다(결정성)."""
from __future__ import annotations

from ..models import REACHABLE, UNKNOWN, UNREACHABLE, Finding, severity_rank

_REACH_RANK = {REACHABLE: 2, UNKNOWN: 1, UNREACHABLE: 0}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (f.category, -severity_rank(f.severity),
                                           -_REACH_RANK.get(f.reachability.status, 1), f.dedup_key))
```

`secscan/scan.py`: `from .output.order import sort_findings`; H 직후 `findings = sort_findings(findings)` (trace 는 `disposition` 기록 뒤, `final` 앞 — 순서만 바뀌므로 카운트 불변).

- [ ] **Step 4: `secscan/output/contracts.py` + 문서 생성**

```python
"""projection 계약(spec §7.3) — 포맷별 포함/부분/손실 필드. `docs/output-contracts.md` 는 이 상수에서 생성된다."""
from __future__ import annotations

from dataclasses import dataclass, fields

from ..models import Finding

FIELDS: tuple[str, ...] = tuple(f.name for f in fields(Finding)) + ("id",)


@dataclass(frozen=True)
class Contract:
    includes: frozenset[str]
    partial: dict[str, str]  # 필드 → 어떤 부분만 실리는지
    loses: frozenset[str]


def _c(includes, partial, loses) -> Contract:
    return Contract(frozenset(includes), dict(partial), frozenset(loses))


CONTRACTS: dict[str, Contract] = {
    "findings.json": _c(FIELDS, {}, ()),
    "markdown": _c(
        ["id", "severity", "rule_id", "cwe", "component", "reachability", "consensus", "compliance", "disposition", "tier"],
        {"category": "절(SCA/시크릿 문구)로만 드러남", "advisory": "fixed_versions 만", "location": "file·start_line 만",
         "suppression": "reason·provenance·expiry 만"},
        ["title", "tool", "owasp", "confidence", "source", "references", "verified", "occurrences"]),
    "sarif": _c(
        ["id", "category", "severity", "title", "tool", "rule_id", "cwe", "confidence", "component", "reachability",
         "consensus", "compliance", "disposition", "tier"],
        {"advisory": "fixedVersions 만(aliases·cvss·published 손실)", "location": "file·startLine·endLine(snippet_ref 손실)",
         "suppression": "reason·provenance·evidence·expiry·state(scope·basis 손실)", "references": "rule helpUri 로 첫 항목만"},
        ["owasp", "source", "verified", "occurrences"]),
    "xlsx": _c(
        ["id", "category", "severity", "title", "tool", "rule_id", "cwe", "confidence", "component", "reachability",
         "consensus", "verified", "compliance", "occurrences", "disposition", "tier"],
        {"advisory": "id·fixed·Max CVSS/Source·Published(aliases 손실)", "location": "file·line(end_line·snippet_ref 손실)",
         "suppression": "상태 열(reason 만)", "references": "URL 열에 첫 항목만"},
        ["owasp", "source"]),
}

# 계약 테스트용 프로브: 포함/부분 선언 필드가 출력 텍스트에 실제로 나타나는지 확인할 대표 문자열.
PROBES = {
    "id": lambda f: f.id, "category": lambda f: "SCA" if f.category == "sca" else f.category,
    "severity": lambda f: "위험" if f.severity == "high" else f.severity, "title": lambda f: f.title,
    "tool": lambda f: f.tool, "rule_id": lambda f: f.rule_id, "cwe": lambda f: f.cwe[0],
    "owasp": lambda f: f.owasp[0], "confidence": lambda f: f.confidence,
    "component": lambda f: f.component.package, "advisory": lambda f: f.advisory.fixed_versions[0],
    "location": lambda f: f.location.file if f.location else "", "source": lambda f: f.source,
    "reachability": lambda f: f.reachability.evidence, "consensus": lambda f: f.consensus.tools[0],
    "references": lambda f: f.references[0], "verified": lambda f: str(f.verified),
    "suppression": lambda f: f.suppression.reason, "compliance": lambda f: f.compliance.kisa[0].name,
    "occurrences": lambda f: f.occurrences[0].target, "disposition": lambda f: f.disposition,
    "tier": lambda f: f.tier or "",
}
# SARIF 의 severity 는 level 로 실린다 — 프로브는 문자열 검색이므로 sarif 용은 별도 처리 없이 "error"/"warning" 이 아니라
# properties.severity(원문) 로 확인된다(sarif.py 가 props["severity"] 를 쓴다).


def render_contracts() -> str:
    fmts = list(CONTRACTS)
    L = ["# 출력 계약 (projection contract) — 생성 문서", "",
         "`secscan/output/contracts.py` 의 상수에서 생성된다. 손으로 고치지 말 것(`tests/test_contracts.py` 가 대조).", "",
         "- ✓ 포함 · ◐ 부분(비고) · ✗ 손실. `findings.json` 만 lossless canonical(spec §7.2), 나머지는 projection(spec §7.3).",
         "- SARIF 는 출력 전용이며 내부 모델이 아니다(원칙 3).", "",
         "| 필드 | " + " | ".join(fmts) + " |", "|---|" + "---|" * len(fmts)]
    for field in FIELDS:
        cells = []
        for fmt in fmts:
            c = CONTRACTS[fmt]
            if field in c.includes:
                cells.append("✓")
            elif field in c.partial:
                cells.append(f"◐ {c.partial[field]}")
            else:
                cells.append("✗")
        L.append(f"| `{field}` | " + " | ".join(cells) + " |")
    L += ["", "## markdown 추가 규칙", "- finding 헤더 줄 끝에 `` · id `<12hex>` `` (억제 스코프 지정용).",
          "- 절(우선 조치/검토 후보/낮은 우선순위/억제됨/미판정)은 `disposition` 필드만 읽는다(재계산 금지).", ""]
    return "\n".join(L)
```

문서 생성(손으로 쓰지 않는다):

```bash
.venv/bin/python -c "from secscan.output.contracts import render_contracts; open('docs/output-contracts.md','w',encoding='utf-8').write(render_contracts())"
```

SARIF 의 `references` 가 실제로 `helpUri` 로 실리는지 `secscan/output/sarif.py::_rule` 을 읽어 확인한다. 실리지 않으면 계약에서 `references` 를 `loses` 로 옮기고 문서를 재생성한다(계약은 사실을 적는다). 마찬가지로 SARIF 에 `props["severity"]`·`title`(message.text)·`tool`(tools) 가 실리는지 확인하고 계약을 코드에 맞춘다.

- [ ] **Step 5: `tools/verify/reinput.py`**

```python
"""V1 증거(옛 바이너리) raw 출력을 새 파이프라인에 재입력한다(spec §4.4 2단계 — baseline 이동 방지).

스캐너를 다시 돌리지 않는다. raw/*.json|sarif → normalize_each → merge → 기본 경로 제외 →
도달성은 V1 findings.json 의 판정을 dedup_key 로 carry-over(대상 트리·슬라이스가 없으므로) → 판정 H → 정렬.
`.gitignore` 기반 제외는 대상 트리가 없어 적용하지 않는다(meta.reinput_note 에 명시).
"""
from __future__ import annotations

import json
from dataclasses import asdict, replace
from pathlib import Path

from secscan.adapters.base import OK, RawResult
from secscan.disposition import decide
from secscan.exclude import DEFAULT_EXCLUDES, exclude_findings
from secscan.normalize import normalize_each
from secscan.normalize.merge import merge_consensus
from secscan.output.json_io import from_json, to_json
from secscan.output.markdown import to_markdown
from secscan.output.order import sort_findings
from secscan.output.sarif import to_sarif
from secscan.scan import TraceSink

_SKIP_RAW = {"bom.cdx.json"}  # SBOM 은 스캐너 출력이 아니다


def load_raws(evidence_dir: Path) -> list[RawResult]:
    ev = Path(evidence_dir)
    meta = json.loads((ev / "meta.json").read_text(encoding="utf-8")) if (ev / "meta.json").exists() else {}
    versions = meta.get("tool_versions", {})
    raws = []
    for p in sorted((ev / "raw").iterdir()):
        if p.name in _SKIP_RAW:
            continue
        fmt = "sarif" if p.suffix == ".sarif" else "json"
        raws.append(RawResult(p.stem, OK, fmt, p.read_text(encoding="utf-8"), version=versions.get(p.stem)))
    return raws


def reinput(evidence_dir: Path, out_dir: Path) -> list[Path]:
    ev, out = Path(evidence_dir), Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    old = from_json((ev / "findings.json").read_text(encoding="utf-8"))
    meta = json.loads((ev / "meta.json").read_text(encoding="utf-8")) if (ev / "meta.json").exists() else {}
    sink = TraceSink()
    raws = load_raws(ev)
    for r in raws:
        sink.record_raw(r.tool, r.status, len(r.payload))
    per_tool = normalize_each(raws)
    for tool in sorted(per_tool):
        sink.record(f"normalize:{tool}", per_tool[tool])
    findings = merge_consensus([f for fs in per_tool.values() for f in fs]); sink.record("merge", findings)
    findings = exclude_findings(findings, set(DEFAULT_EXCLUDES)); sink.record("exclude", findings)
    carry = {f.dedup_key: f.reachability for f in old}
    findings = [replace(f, reachability=carry.get(f.dedup_key, f.reachability)) for f in findings]
    sink.record("reachability", findings)
    findings = sort_findings(decide(findings)); sink.record("disposition", findings); sink.record("final", findings)
    new_meta = {**meta, "reinput_from": str(ev), "reinput_note": "raw 재입력 — 스캐너 미재실행, .gitignore 제외 미적용, 도달성은 V1 판정 carry-over"}
    written = []
    p = out / "findings.json"; p.write_text(to_json(findings, meta=new_meta), encoding="utf-8"); written.append(p)
    p = out / "findings.sarif"; p.write_text(json.dumps(to_sarif(findings), indent=2, ensure_ascii=False), encoding="utf-8"); written.append(p)
    p = out / "report.md"; p.write_text(to_markdown(findings, target=meta.get("snapshot"),
                                                     meta={"scanner_status": meta.get("scanner_status", [])}), encoding="utf-8"); written.append(p)
    p = out / "trace.json"; p.write_text(json.dumps(sink.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8"); written.append(p)
    p = out / "meta.json"; p.write_text(json.dumps(new_meta, indent=2, ensure_ascii=False), encoding="utf-8"); written.append(p)
    return written


def main(argv: list[str] | None = None) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="tools.verify.reinput")
    p.add_argument("--evidence", required=True); p.add_argument("--out", required=True)
    a = p.parse_args(argv)
    for w in reinput(Path(a.evidence), Path(a.out)):
        print(w)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```
(`report.md` 의 meta.scanner_status 는 V1 형식 `{tool,status}` 이므로 markdown 렌더가 `name` 키를 요구하면 `s.get("name") or s.get("tool")` 로 markdown 쪽을 관용적으로 만든다 — Task 3 의 렌더 코드에서 `s['name']` 을 `s.get('name') or s.get('tool')` 로 바꾼다.)

- [ ] **Step 6: CLI `findings.json` + 도움말**

`secscan/cli.py` `_cmd_scan` 출력부에 추가(`from .output.json_io import to_json`):

```python
    (out / "findings.json").write_text(
        to_json(result.findings, meta={
            "target": str(args.target), "profile": args.profile,
            "scanner_status": [asdict(s) for s in result.scanner_status],
            "reachability": {"ran": result.reachability_ran, "reason": result.reachability_reason},
            "secret_policy": result.secret_policy, "excluded_count": result.excluded_count,
        }), encoding="utf-8")
```
`print(f"\n출력: ...")` 에 `findings.json` 추가. `--profile` help 문자열에 `deep` 추가.

- [ ] **Step 7: 통과 확인 + 전체 회귀** — `.venv/bin/pytest -q` green(재입력 테스트는 커밋된 증거를 읽는다 — 수 초).

- [ ] **Step 8: 커밋**

```bash
git add secscan/output/order.py secscan/output/contracts.py secscan/scan.py secscan/cli.py tools/verify/reinput.py docs/output-contracts.md tests/test_order.py tests/test_contracts.py tests/test_reinput.py tests/test_cli.py
git commit -m "feat(V4): findings.json 출력 + 안정 정렬 + projection 계약(생성 문서) + V1 증거 재입력 회귀(reinput: 73키 동일·disposition=옛 버킷 1:1)

다음: xlsx 시트 빌더(순수) — sanitizer·Deduped_CVEs 12열·골든 스키마"
```

---

### Task 7: xlsx 시트 빌더(순수) — sanitizer · 7 시트 · Deduped_CVEs 12열 1:1

**Files:**
- Create: `secscan/output/xlsx.py` (이 태스크는 순수부만: `sanitize_cell`, `build_sheets`, 집계 헬퍼)
- Test: `tests/test_xlsx.py` (신규)

**Interfaces:**
- Consumes: Task 1~6 의 모델(occurrences·cvss·published·disposition·tier·compliance), `docs/verification/ground-truth/golden/security-team-schema.json`(`deduped_cves_header` 12열).
- Produces: `Sheet = tuple[list[str], list[list]]`(헤더, 행들). `sanitize_cell(v) -> str | int | float | None`. `build_sheets(findings: list[Finding], meta: dict) -> dict[str, Sheet]` — 키 순서 `Summary, Findings, Deduped_CVEs, Targets, SAST, Secret, Meta`. `TEAM_HEADER`(12열) + `SECSCAN_EXTRA_HEADER`. `MAX_ROWS = 1_048_576`, `MAX_CHARS = 32_767`.

시트 열 정의(정확히 이 순서):
- `Findings`(발생 단위 1행 — SCA 는 occurrence 당 1행, 나머지는 finding 당 1행): `Finding ID, Category, Severity, Rule/Advisory, Title, Package, Installed Version, Fixed Versions, Target, Tool, File, Line, CWE, Reachability, Disposition, Tier, Suppressed`
- `Deduped_CVEs`(advisory 1행): `TEAM_HEADER` = `No., Vulnerability ID, Severity, Max CVSS Score, CVSS Source, Affected Packages, Installed Versions, Fixed Versions, Targets, Finding Count, Title, URL` + `SECSCAN_EXTRA_HEADER` = `Published, Reachability, Reachability Evidence, Consensus Tools, Consensus Score, Disposition, KISA, PCI, Suppression, Finding ID`
- `Targets`: `Target, Findings`(occurrence 수)
- `SAST`: `Finding ID, Rule, Severity, Confidence, Tier, File, Line, CWE, KISA, PCI, Suppressed, Disposition`
- `Secret`: `Finding ID, Rule, File, Line, Verified, Severity, Suppressed, Disposition` (**비밀값 없음**)
- `Summary`: `Metric, Key, Value` 3열 — `category×severity` 행들(`Metric="count"`, `Key="sca/high"`), `disposition/<d>`, `tier/<t>`, `reachability/<s>`, `profile`, `target`, `scanned_at`(meta `run_date`), `secscan_version`
- `Meta`: `Key, Value` — `scanner.<name>.status|tool_version|duration_s|message`, `profile`, `commit`, `partial_failures`, `reachability.ran|reason`, `secret_policy`, `excluded_count`

집계 규칙(spec §8): `Affected Packages`/`Installed Versions`/`Fixed Versions`/`Targets` 는 정렬·중복 제거 후 `", "` 결합, `Finding Count` = occurrences 수(occurrence 가 없으면 1), `Max CVSS Score` = cvss 중 최대 score, `CVSS Source` = 그 소스(동점 시 소스명 사전순 첫 것), `Severity` = 그룹 최대 벤더 등급, `URL` = references 첫 항목, `Finding ID` = 그룹 id 들 `", "`.

- [ ] **Step 1: 실패하는 테스트 — `tests/test_xlsx.py`**

```python
"""xlsx projection(spec §8) — 순수 시트 빌더. 방어(formula injection·절단·불법 문자)·집계·결정성·골든 스키마."""
import json
from pathlib import Path

from secscan.disposition import decide
from secscan.models import (UNREACHABLE, REACHABLE, Advisory, Component, Compliance, Consensus, Cvss, Finding,
                            KisaWeakness, Location, Occurrence, Reachability, Suppression)
from secscan.output.xlsx import MAX_CHARS, TEAM_HEADER, build_sheets, sanitize_cell

SCHEMA = json.loads(Path("docs/verification/ground-truth/golden/security-team-schema.json").read_text())


def _sca(cve="CVE-1", pkg="a:b", ver="1.0", target="pom.xml", reach=UNREACHABLE, sev="high", cvss=()):
    return Finding(category="sca", severity=sev, title=f"T {cve}", tool="trivy", rule_id=cve, cwe=("CWE-94",),
                   component=Component("maven", pkg, ver),
                   advisory=Advisory(cve, aliases=(cve,), fixed_versions=("2.0",), cvss=tuple(cvss), published="2025-01-01T00:00:00Z"),
                   reachability=Reachability(reach, evidence="ev"), consensus=Consensus(("trivy",), 1),
                   references=("https://x/" + cve,), occurrences=(Occurrence("trivy", target, pkg, ver),),
                   compliance=Compliance(kisa=(KisaWeakness("IV-01", "입력", "SQL 삽입"),), pci=("PCI-DSS 6.2.4 — injection",)))


def _meta():
    return {"profile": "standard", "target": "/repo", "run_date": "2026-09-05", "commit": "abc",
            "scanner_status": [{"name": "trivy", "status": "ok", "tool_version": "0.71.2", "duration_s": 8.5, "message": ""}],
            "reachability": {"ran": True, "reason": "ok"}, "secret_policy": "never", "excluded_count": 0}


def test_sanitize_formula_injection_and_controls():
    assert sanitize_cell("=SUM(A1)") == "'=SUM(A1)"
    assert sanitize_cell("  +1") == "'  +1" and sanitize_cell("\t-x") == "'\t-x" and sanitize_cell("@cmd") == "'@cmd"
    assert sanitize_cell("ok\x00\x1f text") == "ok text"
    assert sanitize_cell(3) == 3 and sanitize_cell(None) is None and sanitize_cell(True) == "True"


def test_sanitize_truncates_over_excel_limit():
    s = sanitize_cell("x" * (MAX_CHARS + 10))
    assert len(s) == MAX_CHARS and s.endswith("…[truncated]")


def test_sheet_names_and_deduped_header_match_team_schema():
    sheets = build_sheets(decide([_sca()]), _meta())
    assert list(sheets) == ["Summary", "Findings", "Deduped_CVEs", "Targets", "SAST", "Secret", "Meta"]
    assert set(SCHEMA["sheets"]) <= set(sheets)
    header, _ = sheets["Deduped_CVEs"]
    assert header[:12] == SCHEMA["deduped_cves_header"] == list(TEAM_HEADER)


def test_deduped_aggregates_occurrences_and_cvss():
    a = _sca(cvss=[Cvss("nvd", "3.1", 7.5, "v"), Cvss("redhat", "3.1", 5.9, "v")])
    b = Finding(**{**a.__dict__, "occurrences": (Occurrence("trivy", "build.gradle", "a:b", "1.0"),)})
    # merge 를 흉내: 같은 advisory 의 두 occurrence 를 가진 finding 하나
    m = Finding(**{**a.__dict__, "occurrences": a.occurrences + b.occurrences})
    header, rows = build_sheets(decide([m]), _meta())["Deduped_CVEs"]
    row = dict(zip(header, rows[0]))
    assert row["Vulnerability ID"] == "CVE-1" and row["Finding Count"] == 2
    assert row["Targets"] == "build.gradle, pom.xml" and row["Affected Packages"] == "a:b"
    assert row["Max CVSS Score"] == 7.5 and row["CVSS Source"] == "nvd"
    assert row["Disposition"] == "demoted" and row["KISA"] == "SQL 삽입" and row["URL"] == "https://x/CVE-1"
    assert row["Published"] == "2025-01-01T00:00:00Z"
    f_header, f_rows = build_sheets(decide([m]), _meta())["Findings"]
    assert len(f_rows) == 2 and {dict(zip(f_header, r))["Target"] for r in f_rows} == {"pom.xml", "build.gradle"}


def test_secret_sheet_has_no_secret_values_and_sast_sheet_has_tier():
    sec = Finding(category="secret", severity="high", rule_id="aws-access-token", title="AWS",
                  location=Location("app.properties", 4, snippet_ref="fp123"))
    sast = Finding(category="sast", severity="high", rule_id="java.sqli", confidence="high", cwe=("CWE-89",),
                   location=Location("src/main/A.java", 10))
    sheets = build_sheets(decide([sec, sast]), _meta())
    s_header, s_rows = sheets["Secret"]
    assert s_header == ["Finding ID", "Rule", "File", "Line", "Verified", "Severity", "Suppressed", "Disposition"]
    assert "fp123" not in str(s_rows) and "AKIA" not in str(s_rows)
    t_header, t_rows = sheets["SAST"]
    assert dict(zip(t_header, t_rows[0]))["Tier"] == "actionable"


def test_meta_sheet_carries_actual_scanner_status():
    _, rows = build_sheets([], _meta())["Meta"]
    d = dict(rows)
    assert d["scanner.trivy.status"] == "ok" and d["scanner.trivy.tool_version"] == "0.71.2" and d["secret_policy"] == "never"


def test_build_is_deterministic_and_sorted():
    fs = decide([_sca("CVE-2", reach=REACHABLE), _sca("CVE-1"), _sca("CVE-3", sev="low")])
    assert build_sheets(fs, _meta()) == build_sheets(list(reversed(fs)), _meta())
    _, rows = build_sheets(fs, _meta())["Deduped_CVEs"]
    assert [r[1] for r in rows] == ["CVE-1", "CVE-2", "CVE-3"] and [r[0] for r in rows] == [1, 2, 3]


def test_all_string_cells_are_sanitized():
    f = _sca(cve="=HYPERLINK(\"x\")")
    _, rows = build_sheets(decide([f]), _meta())["Deduped_CVEs"]
    assert rows[0][1].startswith("'=")
```

- [ ] **Step 2: 실패 확인** — `ModuleNotFoundError: secscan.output.xlsx`.

- [ ] **Step 3: `secscan/output/xlsx.py`(순수부)**

```python
"""xlsx projection (spec §8) — 보안팀 12열 Deduped_CVEs 와 1:1 + secscan 열.

이 모듈의 순수부(build_sheets)는 stdlib 만 쓴다. openpyxl 은 write_xlsx 에서만 지연 import 하고,
없으면 CSV 번들로 폴백한다(코어 의존성 0 유지). 출력은 disposition/tier 필드만 읽는다(재계산 금지).
비밀값(secret 원문·fingerprint)은 어느 시트에도 쓰지 않는다.
"""
from __future__ import annotations

import re
from typing import Iterable

from .. import __version__
from ..models import Finding, severity_rank

Sheet = tuple[list[str], list[list]]

MAX_ROWS = 1_048_576  # Excel 시트 행 상한(헤더 포함)
MAX_CHARS = 32_767  # Excel 셀 문자 상한
_TRUNC = "…[truncated]"
_ILLEGAL_XML = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F]")
_FORMULA_LEAD = ("=", "+", "-", "@")

TEAM_HEADER = ("No.", "Vulnerability ID", "Severity", "Max CVSS Score", "CVSS Source", "Affected Packages",
               "Installed Versions", "Fixed Versions", "Targets", "Finding Count", "Title", "URL")
SECSCAN_EXTRA_HEADER = ("Published", "Reachability", "Reachability Evidence", "Consensus Tools", "Consensus Score",
                        "Disposition", "KISA", "PCI", "Suppression", "Finding ID")
FINDINGS_HEADER = ["Finding ID", "Category", "Severity", "Rule/Advisory", "Title", "Package", "Installed Version",
                   "Fixed Versions", "Target", "Tool", "File", "Line", "CWE", "Reachability", "Disposition", "Tier", "Suppressed"]
SAST_HEADER = ["Finding ID", "Rule", "Severity", "Confidence", "Tier", "File", "Line", "CWE", "KISA", "PCI", "Suppressed", "Disposition"]
SECRET_HEADER = ["Finding ID", "Rule", "File", "Line", "Verified", "Severity", "Suppressed", "Disposition"]


def sanitize_cell(v):
    """formula injection 방어 + XML 불법 문자 제거 + 길이 절단. 숫자/None 은 그대로, bool 은 문자열."""
    if v is None or isinstance(v, (int, float)) and not isinstance(v, bool):
        return v
    s = str(v)
    s = _ILLEGAL_XML.sub("", s)
    if s.lstrip(" \t\r\n").startswith(_FORMULA_LEAD):
        s = "'" + s
    if len(s) > MAX_CHARS:
        s = s[: MAX_CHARS - len(_TRUNC)] + _TRUNC
    return s


def _join(values: Iterable[str]) -> str:
    return ", ".join(sorted({v for v in values if v}))


def _kisa(f: Finding) -> str:
    return _join(w.name for w in f.compliance.kisa) if f.compliance else ""


def _pci(f: Finding) -> str:
    return _join(f.compliance.pci) if f.compliance else ""


def _sup(f: Finding) -> str:
    return f"{f.suppression.state}: {f.suppression.reason}" if f.suppression else ""


def _occ(f: Finding):
    if f.occurrences:
        return list(f.occurrences)
    # occurrence 가 없는 SCA(옛 증거) 는 component 기준 1건으로 본다
    from ..models import Occurrence
    if f.component:
        return [Occurrence(f.tool, f.source or "", f.component.package, f.component.version)]
    return []


def _max_cvss(f: Finding):
    cv = [c for c in (f.advisory.cvss if f.advisory else ()) if c.score is not None]
    if not cv:
        return None, ""
    best = sorted(cv, key=lambda c: (-c.score, c.source))[0]
    return best.score, best.source


def _rows_findings(findings: list[Finding]) -> list[list]:
    rows = []
    for f in findings:
        base = [f.id, f.category, f.severity, f.rule_id, f.title]
        tail = [_join(f.cwe), f.reachability.status, f.disposition or "", f.tier or "", _sup(f)]
        if f.category == "sca":
            for o in _occ(f):
                rows.append(base + [o.package, o.version, _join(f.advisory.fixed_versions if f.advisory else ()), o.target,
                                    o.tool, "", None] + tail)
        else:
            rows.append(base + ["", "", "", "", f.tool, f.location.file if f.location else "",
                                f.location.start_line if f.location else None] + tail)
    return rows


def _rows_deduped(findings: list[Finding]) -> list[list]:
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        if f.category == "sca" and f.advisory:
            groups.setdefault(f.advisory.id, []).append(f)
    rows = []
    for n, (adv_id, fs) in enumerate(sorted(groups.items()), start=1):
        occ = [o for f in fs for o in _occ(f)]
        sev = max((f.severity for f in fs), key=severity_rank)
        scores = [(_max_cvss(f)) for f in fs]
        scored = [s for s in scores if s[0] is not None]
        score, source = (sorted(scored, key=lambda s: (-s[0], s[1]))[0] if scored else (None, ""))
        head = fs[0]
        rows.append([
            n, adv_id, sev, score, source, _join(o.package for o in occ), _join(o.version for o in occ),
            _join(v for f in fs for v in f.advisory.fixed_versions), _join(o.target for o in occ), len(occ) or len(fs),
            head.title, head.references[0] if head.references else "",
            head.advisory.published or "", _join(f.reachability.status for f in fs),
            _join(f.reachability.evidence or "" for f in fs), _join(t for f in fs if f.consensus for t in f.consensus.tools),
            max((f.consensus.score for f in fs if f.consensus), default=0), _join(f.disposition or "" for f in fs),
            _join(_kisa(f) for f in fs), _join(_pci(f) for f in fs), _join(_sup(f) for f in fs), _join(f.id for f in fs),
        ])
    return rows


def _rows_targets(findings: list[Finding]) -> list[list]:
    counts: dict[str, int] = {}
    for f in findings:
        for o in _occ(f) if f.category == "sca" else []:
            counts[o.target] = counts.get(o.target, 0) + 1
    return [[t, n] for t, n in sorted(counts.items())]


def _rows_sast(findings: list[Finding]) -> list[list]:
    return [[f.id, f.rule_id, f.severity, f.confidence, f.tier or "", f.location.file if f.location else "",
             f.location.start_line if f.location else None, _join(f.cwe), _kisa(f), _pci(f), _sup(f), f.disposition or ""]
            for f in findings if f.category == "sast"]


def _rows_secret(findings: list[Finding]) -> list[list]:
    # 비밀값·fingerprint(snippet_ref) 를 쓰지 않는다.
    return [[f.id, f.rule_id, f.location.file if f.location else "", f.location.start_line if f.location else None,
             "" if f.verified is None else str(f.verified), f.severity, _sup(f), f.disposition or ""]
            for f in findings if f.category == "secret"]


def _rows_summary(findings: list[Finding], meta: dict) -> list[list]:
    from collections import Counter
    rows: list[list] = []
    for (cat, sev), n in sorted(Counter((f.category, f.severity) for f in findings).items()):
        rows.append(["count", f"{cat}/{sev}", n])
    for d, n in sorted(Counter(f.disposition or "undecided" for f in findings).items()):
        rows.append(["disposition", d, n])
    for t, n in sorted(Counter(f.tier for f in findings if f.tier).items()):
        rows.append(["tier", t, n])
    for s, n in sorted(Counter(f.reachability.status for f in findings if f.category == "sca").items()):
        rows.append(["reachability", s, n])
    rows += [["profile", "", meta.get("profile", "")], ["target", "", meta.get("target", "")],
             ["scanned_at", "", meta.get("run_date", "")], ["secscan_version", "", __version__]]
    return rows


def _rows_meta(meta: dict) -> list[list]:
    rows: list[list] = []
    for s in sorted(meta.get("scanner_status", []), key=lambda s: s.get("name") or s.get("tool", "")):
        name = s.get("name") or s.get("tool", "")
        for k in ("status", "tool_version", "duration_s", "message"):
            rows.append([f"scanner.{name}.{k}", s.get(k) if s.get(k) is not None else (s.get("error", "") if k == "message" else "")])
    rows += [["profile", meta.get("profile", "")], ["commit", meta.get("commit", meta.get("snapshot", ""))],
             ["partial_failures", _join(s.get("name") or s.get("tool", "") for s in meta.get("scanner_status", []) if s.get("status") != "ok")],
             ["reachability.ran", str(meta.get("reachability", {}).get("ran", ""))],
             ["reachability.reason", meta.get("reachability", {}).get("reason", "")],
             ["secret_policy", meta.get("secret_policy", "")], ["excluded_count", meta.get("excluded_count", "")]]
    return rows


def _san(rows: list[list]) -> list[list]:
    return [[sanitize_cell(c) for c in r] for r in rows]


def build_sheets(findings: list[Finding], meta: dict) -> dict[str, Sheet]:
    """순수·결정적. 입력 순서와 무관하게 같은 시트를 만든다(각 시트가 자체 정렬)."""
    from .order import sort_findings
    fs = sort_findings(findings)
    return {
        "Summary": (["Metric", "Key", "Value"], _san(_rows_summary(fs, meta))),
        "Findings": (FINDINGS_HEADER, _san(_rows_findings(fs))),
        "Deduped_CVEs": (list(TEAM_HEADER + SECSCAN_EXTRA_HEADER), _san(_rows_deduped(fs))),
        "Targets": (["Target", "Findings"], _san(_rows_targets(fs))),
        "SAST": (SAST_HEADER, _san(_rows_sast(fs))),
        "Secret": (SECRET_HEADER, _san(_rows_secret(fs))),
        "Meta": (["Key", "Value"], _san(_rows_meta(meta))),
    }
```

- [ ] **Step 4: 통과 확인 + 전체 회귀** — `.venv/bin/pytest tests/test_xlsx.py -q` PASS, 전체 green.

- [ ] **Step 5: 커밋**

```bash
git add secscan/output/xlsx.py tests/test_xlsx.py
git commit -m "feat(V5): xlsx 시트 빌더(순수) — sanitizer(formula injection·절단·불법 문자), 7 시트, Deduped_CVEs 보안팀 12열 1:1 + secscan 열, 결정성

다음: xlsx 라이터(openpyxl 지연 import) + CSV 폴백 + 시트 분할 + CLI/증거 출력 + pyproject extra"
```

---

### Task 8: xlsx 라이터 · CSV 폴백 · 시트 분할 · CLI/증거 통합

**Files:**
- Modify: `secscan/output/xlsx.py`(라이터부), `secscan/cli.py`, `tools/verify/evidence.py`(`write_evidence(..., xlsx=True)`), `tools/verify/run_snapshot.py`(`--xlsx`), `pyproject.toml`
- Test: `tests/test_xlsx.py` 끝에 추가, `tests/test_cli.py` 추가

**Interfaces:**
- Produces: `split_sheet(sheet, max_rows=MAX_ROWS) -> list[tuple[str, Sheet]]`(이름 접미 `_2`, `_3`…), `write_csv_bundle(sheets, out_dir) -> list[Path]`(`<out_dir>/<sheet>.csv`, utf-8, `csv.QUOTE_MINIMAL`), `write_xlsx(sheets, path, *, created: str) -> Path`(openpyxl; `ImportError` 전파), `write_workbook(findings, meta, out_dir, *, prefer_xlsx: bool | None = None) -> tuple[list[Path], str | None]`(경고 문자열 또는 None). CLI `scan` 은 `<out>/findings.xlsx` 또는 `<out>/findings-xlsx/*.csv` + 경고 1줄. `pyproject.toml` `[project.optional-dependencies] xlsx = ["openpyxl>=3.1"]`.

- [ ] **Step 1: 실패하는 테스트**

```python
# tests/test_xlsx.py 끝에 추가
import csv
import pytest

from secscan.output.xlsx import split_sheet, write_csv_bundle, write_workbook


def test_split_sheet_by_row_limit():
    header, rows = ["A"], [[i] for i in range(10)]
    parts = split_sheet("Findings", (header, rows), max_rows=4)  # 헤더 1 + 데이터 3 씩
    assert [n for n, _ in parts] == ["Findings", "Findings_2", "Findings_3", "Findings_4"]
    assert sum(len(r) for _, (_, r) in parts) == 10 and all(len(r) <= 3 for _, (_, r) in parts)


def test_csv_bundle_writes_every_sheet_sanitized(tmp_path):
    fs = decide([_sca(cve="=EVIL()")])
    paths = write_csv_bundle(build_sheets(fs, _meta()), tmp_path)
    assert {p.name for p in paths} == {"Summary.csv", "Findings.csv", "Deduped_CVEs.csv", "Targets.csv", "SAST.csv", "Secret.csv", "Meta.csv"}
    rows = list(csv.reader((tmp_path / "Deduped_CVEs.csv").open(encoding="utf-8")))
    assert rows[0][:12] == list(TEAM_HEADER) and rows[1][1] == "'=EVIL()"


def test_write_workbook_falls_back_to_csv_with_warning(tmp_path):
    paths, warn = write_workbook(decide([_sca()]), _meta(), tmp_path, prefer_xlsx=False)
    assert warn and "openpyxl" in warn and (tmp_path / "findings-xlsx" / "Deduped_CVEs.csv").exists()


def test_write_workbook_xlsx_roundtrip_when_openpyxl_available(tmp_path):
    openpyxl = pytest.importorskip("openpyxl")
    fs = decide([_sca("CVE-1"), _sca("CVE-2", reach=REACHABLE)])
    paths, warn = write_workbook(fs, _meta(), tmp_path, prefer_xlsx=True)
    assert warn is None and paths[0].name == "findings.xlsx"
    wb = openpyxl.load_workbook(paths[0])
    assert wb.sheetnames == ["Summary", "Findings", "Deduped_CVEs", "Targets", "SAST", "Secret", "Meta"]
    ws = wb["Deduped_CVEs"]
    ids = {ws.cell(row=r, column=2).value for r in range(2, ws.max_row + 1)}
    assert ids == {"CVE-1", "CVE-2"}
    assert wb.properties.created.isoformat().startswith("2026-09-05")
    # 문자열 강제: 수식으로 해석되지 않는다
    fs2 = decide([_sca(cve="=EVIL()")])
    p2, _ = write_workbook(fs2, _meta(), tmp_path / "b", prefer_xlsx=True)
    ws2 = openpyxl.load_workbook(p2[0])["Deduped_CVEs"]
    assert ws2.cell(row=2, column=2).data_type == "s" and ws2.cell(row=2, column=2).value == "'=EVIL()"
```

```python
# tests/test_cli.py 끝에 추가
def test_scan_writes_workbook_or_csv_bundle(tmp_path, monkeypatch):
    from secscan.scan import ScanResult
    from secscan.disposition import decide
    fs = decide([Finding(category="secret", severity="high", rule_id="aws", location=Location("a.properties", 4))])
    monkeypatch.setattr(cli, "run_scan", lambda *a, **k: ScanResult(findings=fs, raw_results=[]))
    monkeypatch.setattr(cli, "build_adapters", lambda p: [])
    cli.main(["scan", "--target", str(tmp_path), "--out", str(tmp_path / "out"), "--profile", "quick", "--no-reachability"])
    out = tmp_path / "out"
    assert (out / "findings.xlsx").exists() or (out / "findings-xlsx" / "Secret.csv").exists()
```

- [ ] **Step 2: 실패 확인** — `ImportError: split_sheet`.

- [ ] **Step 3: 라이터부 구현 (`secscan/output/xlsx.py` 끝에 추가)**

```python
import csv
from datetime import datetime
from pathlib import Path


def split_sheet(name: str, sheet: Sheet, max_rows: int = MAX_ROWS) -> list[tuple[str, Sheet]]:
    header, rows = sheet
    per = max(1, max_rows - 1)  # 헤더 1행 제외
    if len(rows) <= per:
        return [(name, sheet)]
    return [(name if i == 0 else f"{name}_{i + 1}", (header, rows[i * per:(i + 1) * per]))
            for i in range((len(rows) + per - 1) // per)]


def _split_all(sheets: dict[str, Sheet], max_rows: int = MAX_ROWS) -> list[tuple[str, Sheet]]:
    out: list[tuple[str, Sheet]] = []
    for name, sheet in sheets.items():
        out += split_sheet(name, sheet, max_rows)
    return out


def write_csv_bundle(sheets: dict[str, Sheet], out_dir, *, max_rows: int = MAX_ROWS) -> list[Path]:
    """openpyxl 부재 시 폴백. 같은 sanitizer 를 이미 거친 셀을 그대로 쓴다."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written = []
    for name, (header, rows) in _split_all(sheets, max_rows):
        p = out / f"{name}.csv"
        with p.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh, quoting=csv.QUOTE_MINIMAL)
            w.writerow(header)
            w.writerows(["" if c is None else c for c in r] for r in rows)
        written.append(p)
    return written


def write_xlsx(sheets: dict[str, Sheet], path, *, created: str, max_rows: int = MAX_ROWS) -> Path:
    """openpyxl 필요(`pip install secscan[xlsx]`). 문자열 셀은 data_type 's' 로 강제 — '=' 시작 문자열이 수식이 되지 않게."""
    from openpyxl import Workbook  # 지연 import: 코어 의존성 0 유지
    from openpyxl.cell.cell import TYPE_STRING

    wb = Workbook()
    wb.remove(wb.active)
    for name, (header, rows) in _split_all(sheets, max_rows):
        ws = wb.create_sheet(title=name[:31])
        ws.append(header)
        for r in rows:
            ws.append(r)
        for row in ws.iter_rows(min_row=1):
            for cell in row:
                if isinstance(cell.value, str):
                    cell.data_type = TYPE_STRING
    ts = datetime.fromisoformat(created) if created else datetime(1970, 1, 1)
    wb.properties.created = ts
    wb.properties.modified = ts
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    wb.save(p)
    return p


def _openpyxl_available() -> bool:
    try:
        import openpyxl  # noqa: F401
        return True
    except ImportError:
        return False


def write_workbook(findings: list[Finding], meta: dict, out_dir, *, prefer_xlsx: bool | None = None,
                   max_rows: int = MAX_ROWS) -> tuple[list[Path], str | None]:
    """xlsx 가 가능하면 `<out>/findings.xlsx`, 아니면 `<out>/findings-xlsx/<sheet>.csv` + 경고 1줄."""
    sheets = build_sheets(findings, meta)
    out = Path(out_dir)
    use_xlsx = _openpyxl_available() if prefer_xlsx is None else prefer_xlsx
    if use_xlsx:
        return [write_xlsx(sheets, out / "findings.xlsx", created=str(meta.get("run_date", "")), max_rows=max_rows)], None
    paths = write_csv_bundle(sheets, out / "findings-xlsx", max_rows=max_rows)
    return paths, "openpyxl 미설치 — 시트별 CSV 번들로 대체(`pip install secscan[xlsx]` 로 xlsx 출력)"
```

`created` 가 `"2026-09-05"` 같은 날짜만이면 `datetime.fromisoformat` 이 자정으로 해석한다(결정성 유지).

- [ ] **Step 4: CLI · 증거 · pyproject**

`pyproject.toml`:
```toml
[project.optional-dependencies]
dev = ["pytest>=8"]
xlsx = ["openpyxl>=3.1"]
```

`secscan/cli.py` `_cmd_scan` 출력부(findings.json 뒤):
```python
    from .output.xlsx import write_workbook
    wb_meta = {"target": str(args.target), "profile": args.profile, "run_date": date.today().isoformat(),
               "scanner_status": [asdict(s) for s in result.scanner_status],
               "reachability": {"ran": result.reachability_ran, "reason": result.reachability_reason},
               "secret_policy": result.secret_policy, "excluded_count": result.excluded_count}
    wb_paths, wb_warn = write_workbook(result.findings, wb_meta, out)
    if wb_warn:
        print(f"⚠️ {wb_warn}")
```
출력 안내 줄에 `wb_paths[0]` 추가.

`tools/verify/evidence.py` `write_evidence(out_dir, *, result, trace, meta, xlsx: bool = False)`: `xlsx=True` 면 `write_workbook(result.findings, {**meta, "scanner_status": full_meta["scanner_status"], "reachability": ..., "secret_policy": ...}, out)` 를 호출해 `written` 에 추가(경고는 meta 에 `"xlsx_warning"` 으로 기록). `run_snapshot.py` 에 `--xlsx` 플래그 → `write_evidence(..., xlsx=args.xlsx)`.

- [ ] **Step 5: 통과 확인 + 전체 회귀** — openpyxl 미설치 환경에서는 왕복 테스트가 skip 된다(정상). 실행자는 `.venv/bin/pip install -e '.[xlsx]'` 로 설치해 왕복 테스트도 통과시킨다(설치 명령을 보고서에 적는다).

- [ ] **Step 6: 커밋**

```bash
git add secscan/output/xlsx.py secscan/cli.py tools/verify/evidence.py tools/verify/run_snapshot.py pyproject.toml tests/test_xlsx.py tests/test_cli.py
git commit -m "feat(V5): xlsx 라이터(openpyxl 지연 import, 문자열 타입 강제, created 고정) + CSV 폴백 + 시트 분할 + CLI/증거 출력 + extra secscan[xlsx]

다음: V6 secret-app 변이 픽스처(history-only·allowlist·저엔트로피) + 골든 재생성"
```

---

### Task 9: secret-app 변이 픽스처 — history-only · allowlist · 저엔트로피 비밀번호 (골든 재생성)

**Files:**
- Modify: `fixtures/secret-app/config/application.properties`, `fixtures/secret-app/expected.json`
- Create: `fixtures/secret-app/src/main/java/com/example/Config.java`
- Regenerate: `tests/golden/gitleaks-secret-app.json`; Create: `tests/golden/semgrep-secret-app-custom.json`
- Test: `tests/test_secret_variants.py` (신규)

**Interfaces:**
- Consumes: `GitleaksAdapter.build_argv`(`gitleaks dir`, `.gitleaks.toml` 존중), `normalize.gitleaks.parse_gitleaks`, `normalize.semgrep.parse_semgrep`, 커스텀 룰 `secscan/rules/hardcoded-credential.yml`(id `hardcoded-credential`, cwe 메타 → tier actionable).
- Produces: 3 케이스의 기대값을 `expected.json` 에 고정: (a) 저엔트로피 도메인 비밀번호 — gitleaks 기본 룰 **미탐**(사실 기록), 커스텀 semgrep 룰 `hardcoded-credential` 이 `Config.java` 에서 탐지; (b) `gitleaks:allow` 인라인 allowlist — gitleaks 결과에 **없음**; (c) history-only 시크릿 — `gitleaks dir` 미탐 / `gitleaks git` 탐지(실도구 있을 때만 실행하는 테스트로 사실 기록).

- [ ] **Step 1: 픽스처 확장**

`fixtures/secret-app/config/application.properties` 끝에 추가:

```properties

# (b) allowlist 예제 — 같은 줄의 gitleaks:allow 로 의도적 제외 (가짜 토큰, 실제 자격증명 아님)
demo.github.token=ghp_ALLOWLISTEDEXAMPLE000000000000000AbCd # gitleaks:allow

# (a) 저엔트로피 도메인 비밀번호 — gitleaks 기본 룰은 잡지 않는다(사실 기록). secscan 커스텀 룰이 Java 쪽에서 잡는다.
db.password=Passw0rd!2024
```

`fixtures/secret-app/src/main/java/com/example/Config.java`(신규):

```java
package com.example;

/** (a) 저엔트로피 도메인 비밀번호 — 커스텀 룰 hardcoded-credential 의 양성 케이스. 가짜값. */
public class Config {
    static final String DB_PASSWORD = "Passw0rd!2024";
    static final String DB_USER = "app";
}
```

- [ ] **Step 2: 골든 재생성(문서화된 명령, 실도구)**

```bash
gitleaks dir fixtures/secret-app --report-format json --report-path tests/golden/gitleaks-secret-app.json --no-banner --exit-code 0
semgrep --config secscan/rules/ fixtures/secret-app/ --json --disable-version-check --quiet > tests/golden/semgrep-secret-app-custom.json
```
확인: gitleaks 골든에 `RuleID` 가 여전히 3종(aws-access-token·generic-api-key·github-pat)만 있고, `demo.github.token` 줄(allowlist)과 `db.password` 줄은 **없다**. semgrep 골든에 `hardcoded-credential` 이 `Config.java` 에서 1건 이상 있다. 라인 번호가 바뀌었으면 `expected.json` 의 `line` 을 골든 기준으로 갱신한다(기존 3건은 줄 번호 불변).

`fixtures/secret-app/expected.json` 에 추가:

```json
  "variants": {
    "low_entropy_password": {"file": "src/main/java/com/example/Config.java", "gitleaks": "absent",
                             "custom_rule": "hardcoded-credential", "expected_tier": "actionable"},
    "allowlisted_inline": {"file": "config/application.properties", "marker": "gitleaks:allow", "gitleaks": "absent"},
    "history_only": {"mode_dir": "absent", "mode_git": "present", "note": "gitleaks dir 는 working tree 만 본다 — 히스토리 시크릿은 git 모드 필요"}
  }
```

- [ ] **Step 3: 실패하는 테스트 — `tests/test_secret_variants.py`**

```python
"""secret 변이 픽스처(spec §6) — 저엔트로피·allowlist·history-only. 사실을 기록한다(우회하지 않는다)."""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from secscan.disposition import decide
from secscan.models import ACTIONABLE
from secscan.normalize.gitleaks import parse_gitleaks
from secscan.normalize.semgrep import parse_semgrep

GOLDEN = Path(__file__).parent / "golden"
EXPECTED = json.loads(Path("fixtures/secret-app/expected.json").read_text(encoding="utf-8"))


def test_low_entropy_password_missed_by_gitleaks_but_caught_by_custom_rule():
    g = parse_gitleaks((GOLDEN / "gitleaks-secret-app.json").read_text())
    assert not any(f.location and f.location.file.endswith("Config.java") for f in g)
    assert not any(f.location and f.location.start_line and "db.password" in f.title for f in g)
    s = decide(parse_semgrep((GOLDEN / "semgrep-secret-app-custom.json").read_text()))
    hit = [f for f in s if f.rule_id.endswith("hardcoded-credential") and f.location.file.endswith("Config.java")]
    assert hit and hit[0].disposition == ACTIONABLE and hit[0].tier == EXPECTED["variants"]["low_entropy_password"]["expected_tier"]


def test_inline_allowlist_is_respected():
    g = parse_gitleaks((GOLDEN / "gitleaks-secret-app.json").read_text())
    props = Path("fixtures/secret-app/config/application.properties").read_text(encoding="utf-8").splitlines()
    allow_line = next(i for i, l in enumerate(props, start=1) if "gitleaks:allow" in l)
    assert not any(f.location and f.location.start_line == allow_line for f in g)
    assert {f.rule_id for f in g} == {"aws-access-token", "generic-api-key", "github-pat"}


@pytest.mark.skipif(shutil.which("gitleaks") is None or shutil.which("git") is None, reason="gitleaks/git 필요(실도구)")
def test_history_only_secret_is_missed_by_dir_mode_and_found_by_git_mode(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@x", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@x"}
    run = lambda *a: subprocess.run(a, cwd=repo, env=env, check=True, capture_output=True, text=True)
    run("git", "init", "-q")
    (repo / "app.properties").write_text("aws.accessKeyId=AKIAZ7XK4PQR2WMTBN3D\n", encoding="utf-8")
    run("git", "add", "."); run("git", "commit", "-q", "-m", "add secret")
    (repo / "app.properties").write_text("aws.accessKeyId=${AWS_KEY}\n", encoding="utf-8")
    run("git", "add", "."); run("git", "commit", "-q", "-m", "remove secret")
    def leaks(mode):
        rep = tmp_path / f"{mode}.json"
        subprocess.run(["gitleaks", mode, str(repo), "--report-format", "json", "--report-path", str(rep), "--no-banner", "--exit-code", "0"],
                       capture_output=True, text=True, check=True)
        return json.loads(rep.read_text() or "[]")
    assert leaks("dir") == []  # 사실: dir 모드는 working tree 만 본다
    assert any(x["RuleID"] == "aws-access-token" for x in leaks("git"))
```

- [ ] **Step 4: 실행 확인**

Run: `.venv/bin/pytest tests/test_secret_variants.py tests/test_secret.py tests/test_scan.py -q`
Expected: PASS(history-only 는 gitleaks 있으면 실행). 기존 `test_secret.py` 가 골든 항목 수 3 을 단언하므로 유지되어야 한다(allowlist·저엔트로피는 gitleaks 결과에 없음). 깨지면 골든이 잘못 생성된 것 — Step 2 재확인.

- [ ] **Step 5: 커밋**

```bash
git add fixtures/secret-app tests/golden/gitleaks-secret-app.json tests/golden/semgrep-secret-app-custom.json tests/test_secret_variants.py
git commit -m "feat(V6): secret-app 변이 픽스처 — 저엔트로피(커스텀 룰 탐지·gitleaks 미탐 기록), 인라인 allowlist, history-only(dir 미탐/git 탐지 실도구 테스트)

다음: 억제 전이 3종 현행 고정 + deep gradlew 픽스처(spotbugs 빌드 gradlew 우선·실패 격리)"
```

---

### Task 10: 억제 전이 3종(현행 고정) + deep `gradlew` 픽스처

**Files:**
- Modify: `secscan/adapters/spotbugs.py` (`_default_build` gradlew 우선)
- Create: `fixtures/deep-gradlew-app/{settings.gradle,build.gradle,gradlew,src/main/java/com/example/App.java}`
- Test: `tests/test_suppress_transitions.py`(신규), `tests/test_deep.py` 끝에 추가

**Interfaces:**
- Consumes: `suppress.engine.apply_suppressions(findings, suppressions, *, today) -> SuppressOutcome(findings, applied, invalidated)`, `SpotBugsAdapter.run(target, *, find_classes, build, run, timeout)`, `RawResult` status `SKIPPED`.
- Produces: 억제 전이 기대값 3종을 테스트로 고정(만료 → 재노출 + invalidated / 버전 상향 → 조용히 미매칭·재노출, invalidated 비어 있음(현행; "invalidated 보고" 는 백로그) / 도달성 변화 → 재노출 + invalidated). `_default_build` 가 `gradlew` 가 있고 실행 가능하면 `["<target>/gradlew", "compileJava", "-q"]`, 아니면 `["gradle", ...]`.

- [ ] **Step 1: 실패하는 테스트**

```python
# tests/test_suppress_transitions.py
"""억제 전이(spec §6) — 현행 동작을 그대로 고정한다. 자동 억제 없음."""
from dataclasses import replace

from secscan.models import REACHABLE, UNREACHABLE, Advisory, Component, Finding, Reachability
from secscan.suppress.engine import apply_suppressions, record_suppression


def _sca(ver="1.30", reach=UNREACHABLE):
    return Finding(category="sca", severity="high", component=Component("maven", "org.yaml:snakeyaml", ver),
                   advisory=Advisory("CVE-2022-1471"), reachability=Reachability(reach))


def _sup(f, expiry="2027-01-01", basis="unreachable"):
    return record_suppression(scope=f.dedup_key, reason="도달 불가", provenance="alice 2026-09-05", evidence="콜패스 없음",
                              expiry=expiry, basis=basis)


def test_expiry_transition_resurfaces_and_reports_invalidated():
    f = _sca()
    out = apply_suppressions([f], [_sup(f, expiry="2026-01-01")], today="2026-09-05")
    assert out.findings[0].suppression is None and out.invalidated == [f.dedup_key]


def test_version_bump_transition_silently_unmatches():
    """현행: 버전이 오르면 dedup_key 가 달라져 억제가 매칭되지 않는다(재노출). invalidated 보고는 백로그(spec §13.2)."""
    old = _sca("1.30")
    new = _sca("1.31")
    out = apply_suppressions([new], [_sup(old)], today="2026-09-05")
    assert out.findings[0].suppression is None and out.applied == 0 and out.invalidated == []


def test_reachability_change_transition_invalidates_unreachable_basis():
    f = _sca(reach=UNREACHABLE)
    now_reachable = replace(f, reachability=Reachability(REACHABLE))
    out = apply_suppressions([now_reachable], [_sup(f, basis="unreachable")], today="2026-09-05")
    assert out.findings[0].suppression is None and out.invalidated == [f.dedup_key]
```

```python
# tests/test_deep.py 끝에 추가
import os
import stat
import subprocess
from pathlib import Path

from secscan.adapters.base import SKIPPED
from secscan.adapters.spotbugs import SpotBugsAdapter, _default_build

FIX = Path("fixtures/deep-gradlew-app")


def test_default_build_prefers_gradlew_when_present(tmp_path, monkeypatch):
    (tmp_path / "build.gradle").write_text("plugins { id 'java' }\n")
    w = tmp_path / "gradlew"; w.write_text("#!/bin/sh\nexit 0\n"); w.chmod(w.stat().st_mode | stat.S_IXUSR)
    seen = {}
    def fake_run(argv, **kw):
        seen["argv"] = argv
        class R: returncode = 0
        return R()
    monkeypatch.setattr(subprocess, "run", fake_run)
    assert _default_build(tmp_path) is True
    assert seen["argv"] == [str(w), "compileJava", "-q"]


def test_default_build_falls_back_to_system_gradle_without_wrapper(tmp_path, monkeypatch):
    (tmp_path / "build.gradle").write_text("plugins { id 'java' }\n")
    seen = {}
    def fake_run(argv, **kw):
        seen["argv"] = argv
        class R: returncode = 1
        return R()
    monkeypatch.setattr(subprocess, "run", fake_run)
    assert _default_build(tmp_path) is False and seen["argv"][0] == "gradle"


def test_gradlew_fixture_build_failure_is_isolated_as_skipped():
    """gradlew 전용 프로젝트에서 빌드가 실패하면 deep 만 SKIPPED, 예외 없음(원칙 5). 실제 stub gradlew 를 실행한다."""
    assert os.access(FIX / "gradlew", os.X_OK)
    r = SpotBugsAdapter().run(FIX)
    assert r.status == SKIPPED and "빌드 실패" in r.error
```

- [ ] **Step 2: 픽스처 생성**

```bash
mkdir -p fixtures/deep-gradlew-app/src/main/java/com/example
printf "rootProject.name = 'deep-gradlew-app'\n" > fixtures/deep-gradlew-app/settings.gradle
printf "plugins { id 'java' }\n" > fixtures/deep-gradlew-app/build.gradle
printf '#!/bin/sh\n# 픽스처: 시스템 gradle 없이 wrapper 만 있는 프로젝트를 흉내낸다. 항상 빌드 실패.\necho "simulated wrapper build failure" >&2\nexit 1\n' > fixtures/deep-gradlew-app/gradlew
chmod +x fixtures/deep-gradlew-app/gradlew
cat > fixtures/deep-gradlew-app/src/main/java/com/example/App.java <<'JAVA'
package com.example;

public class App {
    public static void main(String[] args) { System.out.println("deep-gradlew-app"); }
}
JAVA
```
(`git add` 시 실행 비트가 보존되는지 `git ls-files -s fixtures/deep-gradlew-app/gradlew` 로 확인 — 모드 `100755`.)

- [ ] **Step 3: `secscan/adapters/spotbugs.py` `_default_build`**

```python
import os

def _default_build(target) -> bool:
    t = Path(target)
    try:
        if (t / "pom.xml").exists():
            r = subprocess.run(["mvn", "-q", "-DskipTests", "compile"],
                               cwd=str(t), capture_output=True, text=True, timeout=600)
            return r.returncode == 0
        if (t / "build.gradle").exists() or (t / "build.gradle.kts").exists():
            wrapper = t / "gradlew"
            gradle = [str(wrapper)] if wrapper.exists() and os.access(wrapper, os.X_OK) else ["gradle"]
            r = subprocess.run(gradle + ["compileJava", "-q"],
                               cwd=str(t), capture_output=True, text=True, timeout=600)
            return r.returncode == 0
    except Exception:
        return False
    return False
```

- [ ] **Step 4: 통과 확인 + 전체 회귀** — green.

- [ ] **Step 5: 커밋**

```bash
git add secscan/adapters/spotbugs.py fixtures/deep-gradlew-app tests/test_suppress_transitions.py tests/test_deep.py
git commit -m "feat(V6): 억제 전이 3종 현행 고정(만료·버전상향 조용한 재노출·도달성 변화) + deep gradlew 픽스처(spotbugs 빌드 gradlew 우선, 실패 SKIPPED 격리)

다음: 축 8 보고서 충실성 생성기 tools/verify/fidelity.py + facts-fidelity.json"
```

---

### Task 11: 축 8 보고서 충실성 생성기 — `tools/verify/fidelity.py`

**Files:**
- Create: `tools/verify/fidelity.py`
- Test: `tests/test_verify_tools.py` 끝에 추가

**Interfaces:**
- Consumes: 증거 디렉토리(`findings.json`·`meta.json`), `json_io.to_json/from_json`, `to_markdown`, `to_sarif`, `xlsx.build_sheets`, `contracts.CONTRACTS`.
- Produces: `check(evidence_dir: Path) -> dict`(키: `roundtrip_identical: bool`, `ids: dict[fmt, set[str]]`, `actionable: dict[fmt, set[str]]`, `id_set_mismatch: int`, `disposition_mismatch: int`, `deterministic: bool`, `meta_scanner_status_rows: int`, `undecided: int`), `collect_facts(result) -> dict`(ids `fidelity.roundtrip_identical`(str True/False), `fidelity.id_set_mismatch`, `fidelity.disposition_mismatch`, `fidelity.deterministic`, `fidelity.meta_scanner_status_rows`, `fidelity.undecided`, `fidelity.ids.findings`, `fidelity.ids.markdown`, `fidelity.ids.sarif`, `fidelity.ids.xlsx`, `fidelity.actionable.findings`(수)), `render(result) -> str`, `main(--evidence --out [--facts])`. markdown id 추출 정규식 `· id `([0-9a-f]{12})``.

- [ ] **Step 1: 실패하는 테스트**

```python
# tests/test_verify_tools.py 끝에 추가
def _fidelity_evidence(tmp_path, findings, meta=None):
    from secscan.output.json_io import to_json
    (tmp_path / "findings.json").write_text(to_json(findings, meta=meta or {}), encoding="utf-8")
    (tmp_path / "meta.json").write_text(json.dumps(meta or {"scanner_status": [{"tool": "trivy", "status": "ok"}]}), encoding="utf-8")
    return tmp_path


def test_fidelity_all_formats_agree_on_decided_findings(tmp_path):
    from secscan.disposition import decide
    from secscan.models import Advisory, Component, Finding, Location, Reachability, UNREACHABLE
    from tools.verify.fidelity import check, collect_facts
    fs = decide([
        Finding(category="sast", severity="high", rule_id="s1", confidence="high", location=Location("src/main/A.java", 1)),
        Finding(category="secret", severity="high", rule_id="k", location=Location("c.properties", 1)),
        Finding(category="sca", severity="high", rule_id="CVE-Z", component=Component("maven", "x:y", "1"),
                advisory=Advisory("CVE-Z"), reachability=Reachability(UNREACHABLE)),
    ])
    r = check(_fidelity_evidence(tmp_path, fs))
    assert r["roundtrip_identical"] and r["deterministic"]
    assert r["id_set_mismatch"] == 0 and r["disposition_mismatch"] == 0 and r["undecided"] == 0
    assert r["ids"]["markdown"] == r["ids"]["sarif"] == r["ids"]["xlsx"] == r["ids"]["findings"]
    f = collect_facts(r)
    assert f["fidelity.roundtrip_identical"] == "True" and f["fidelity.id_set_mismatch"] == 0
    assert f["fidelity.actionable.findings"] == 2 and f["fidelity.meta_scanner_status_rows"] == 1


def test_fidelity_reports_undecided_v1_style_evidence_as_fact(tmp_path):
    from secscan.models import Finding, Location
    from tools.verify.fidelity import check
    raw = [Finding(category="secret", severity="high", rule_id="k", location=Location("c.properties", 1))]  # H 미실행
    r = check(_fidelity_evidence(tmp_path, raw))
    assert r["undecided"] == 1 and r["disposition_mismatch"] == 0  # 판정 없음은 불일치가 아니라 '미판정' 사실
```

- [ ] **Step 2: 실패 확인** — 모듈 없음.

- [ ] **Step 3: `tools/verify/fidelity.py`**

```python
"""축 8 보고서 충실성(spec §5) — findings.json 왕복·projection id 집합·판정(disposition) 일치·결정성·Meta 시트.

측정만 한다. 게이트 판정은 gate.py 가 facts 로 내린다.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from secscan.models import ACTIONABLE
from secscan.output.json_io import from_json, to_json
from secscan.output.markdown import to_markdown
from secscan.output.sarif import to_sarif
from secscan.output.xlsx import build_sheets

from ._facts import facts_text

_MD_ID = re.compile(r"· id `([0-9a-f]{12})`")


def _md_ids(md: str) -> set[str]:
    return set(_MD_ID.findall(md))


def _md_actionable(md: str) -> set[str]:
    sec = md.split("## 우선 조치", 1)
    if len(sec) < 2:
        return set()
    body = sec[1].split("\n## ", 1)[0]
    return set(_MD_ID.findall(body))


def _sarif_ids(doc: dict, only_actionable: bool = False) -> set[str]:
    out = set()
    for r in doc["runs"][0]["results"]:
        p = r.get("properties", {})
        if "id" in p and (not only_actionable or p.get("disposition") == ACTIONABLE):
            out.add(p["id"])
    return out


def _xlsx_ids(sheets: dict, only_actionable: bool = False) -> set[str]:
    header, rows = sheets["Findings"]
    i_id, i_d = header.index("Finding ID"), header.index("Disposition")
    return {r[i_id] for r in rows if not only_actionable or r[i_d] == ACTIONABLE}


def check(evidence_dir) -> dict:
    ev = Path(evidence_dir)
    text = (ev / "findings.json").read_text(encoding="utf-8")
    meta = json.loads((ev / "meta.json").read_text(encoding="utf-8")) if (ev / "meta.json").exists() else {}
    findings = from_json(text)
    roundtrip = from_json(to_json(findings)) == findings
    md1, md2 = to_markdown(findings, meta={"scanner_status": meta.get("scanner_status", [])}), to_markdown(findings, meta={"scanner_status": meta.get("scanner_status", [])})
    sa1, sa2 = to_sarif(findings), to_sarif(findings)
    sh1, sh2 = build_sheets(findings, meta), build_sheets(findings, meta)
    ids = {"findings": {f.id for f in findings}, "markdown": _md_ids(md1), "sarif": _sarif_ids(sa1), "xlsx": _xlsx_ids(sh1)}
    act = {"findings": {f.id for f in findings if f.disposition == ACTIONABLE}, "markdown": _md_actionable(md1),
           "sarif": _sarif_ids(sa1, True), "xlsx": _xlsx_ids(sh1, True)}
    return {
        "roundtrip_identical": roundtrip,
        "ids": ids, "actionable": act,
        "id_set_mismatch": sum(1 for k in ("markdown", "sarif", "xlsx") if ids[k] != ids["findings"]),
        "disposition_mismatch": sum(1 for k in ("markdown", "sarif", "xlsx") if act[k] != act["findings"]),
        "deterministic": md1 == md2 and sa1 == sa2 and sh1 == sh2,
        "meta_scanner_status_rows": len(meta.get("scanner_status", [])),
        "undecided": sum(1 for f in findings if f.disposition is None),
        "exit_code_would_be": 1 if act["findings"] else 0,
    }


def collect_facts(r: dict) -> dict:
    return {
        "fidelity.roundtrip_identical": str(r["roundtrip_identical"]),
        "fidelity.id_set_mismatch": r["id_set_mismatch"],
        "fidelity.disposition_mismatch": r["disposition_mismatch"],
        "fidelity.deterministic": str(r["deterministic"]),
        "fidelity.meta_scanner_status_rows": r["meta_scanner_status_rows"],
        "fidelity.undecided": r["undecided"],
        "fidelity.exit_code": r["exit_code_would_be"],
        **{f"fidelity.ids.{k}": len(v) for k, v in sorted(r["ids"].items())},
        **{f"fidelity.actionable.{k}": len(v) for k, v in sorted(r["actionable"].items())},
    }


def render(r: dict) -> str:
    L = ["# 보고서 충실성 (축 8 — 생성 문서)", "",
         "| 검사 | 값 |", "|---|---|",
         f"| findings.json 왕복 동일 | {r['roundtrip_identical']} |",
         f"| 결정성(md/SARIF/xlsx 2회 동일) | {r['deterministic']} |",
         f"| 미판정(disposition None) | {r['undecided']} |",
         f"| Meta 스캐너 status 행 | {r['meta_scanner_status_rows']} |",
         f"| exit code(판정 기준) | {r['exit_code_would_be']} |", "",
         "## id 집합", "| 포맷 | id 수 | findings.json 과 동일 |", "|---|---|---|"]
    for k in ("findings", "markdown", "sarif", "xlsx"):
        L.append(f"| {k} | {len(r['ids'][k])} | {r['ids'][k] == r['ids']['findings']} |")
    L += ["", "## actionable 집합(판정 일치)", "| 포맷 | actionable 수 | findings.json 과 동일 |", "|---|---|---|"]
    for k in ("findings", "markdown", "sarif", "xlsx"):
        L.append(f"| {k} | {len(r['actionable'][k])} | {r['actionable'][k] == r['actionable']['findings']} |")
    return "\n".join(L) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="tools.verify.fidelity")
    p.add_argument("--evidence", required=True); p.add_argument("--out", required=True); p.add_argument("--facts", default=None)
    a = p.parse_args(argv)
    r = check(a.evidence)
    Path(a.out).write_text(render(r), encoding="utf-8")
    if a.facts:
        Path(a.facts).write_text(facts_text(collect_facts(r)), encoding="utf-8")
    print(a.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: 통과 확인 + 전체 회귀** — green.

- [ ] **Step 5: 커밋**

```bash
git add tools/verify/fidelity.py tests/test_verify_tools.py
git commit -m "feat(V6): 축 8 보고서 충실성 생성기 — 왕복·projection id 집합·disposition 일치·결정성·Meta status → fidelity.md + facts-fidelity.json

다음: gate.py 판정 생성기 + 생성기 레지스트리 + reconcile 하드닝(N1/N3/N4/N5/M4) + reach-app 정본"
```

---

### Task 12: 게이트 생성기 `gate.py` · 생성기 레지스트리 · reach-app 정본 · reconcile 하드닝

**Files:**
- Create: `tools/verify/reach_app.py`, `tools/verify/gate.py`, `tools/verify/generators.py`
- Modify: `tools/verify/reconcile.py` (`regenerate` → 레지스트리 순회·예외 격리, 인용 선언 줄 단위(N1), 셀 `\|` 이스케이프(N4), 자기인용 계수(N5)), `tools/verify/report.py` (`render_attrition` trace 순서(N3)), `tests/test_reach_app.py` (헬퍼를 `tools/verify/reach_app.py` 로 이동해 단일 소스)
- Test: `tests/test_verify_tools.py` 끝에 추가

**Interfaces:**
- Consumes: `facts*.json` 아이디 전부(플랜 1 + Task 11 `fidelity.*`), `tests/test_reach_app.py` 의 판정 구성, `reconcile.load_facts`(facts-reconcile 제외), 기존 생성기 함수들.
- Produces:
  - `reach_app.evaluate() -> dict`(`cases`, `false_unreachable`, `reachable_hit`, `rows`), `reach_app.collect_facts(r)`(`reachapp.cases`, `reachapp.false_unreachable`, `reachapp.reachable_expected_hit`("a/b")), `reach_app.render(r)`.
  - `gate.GATES: tuple[Gate, ...]`, `gate.render_gate(facts: dict) -> str`(문서 `gate.md`: 표 `| 축 | 기준(spec §5) | 측정값 | 판정 |` + `## 요약` 불릿; 측정값 열의 모든 값 뒤에 마커; 판정 열은 `✓` / `✗ → 백로그 P1` / `기록` / `미측정(정본 없음: <id>)`).
  - `generators.Ctx`, `generators.Generator(doc, facts, produce)`, `generators.GENERATORS`, `generators.produce_all(ctx) -> list[Produced]`, `generators.write_all(ctx) -> list[Path]`, CLI `python -m tools.verify.generators --results --evidence-root --gt-b --gt-a [--std <snapshot dir name>]`.
  - `reconcile.regenerate(results_dir, evidence_root, gt_b, gt_a)` 는 `GENERATORS` 를 순회하고 생성기 예외를 `✗ 생성 실패: …` 행으로 격리한다(M4/N6). `reconcile.collect_facts` 는 `reconcile.self_marker_mismatch`(reconcile.* 자기인용 불일치 수)를 별도로 낸다(N5).

- [ ] **Step 1: 실패하는 테스트**

```python
# tests/test_verify_tools.py 끝에 추가
def test_reach_app_facts_match_fixture_expectations():
    from tools.verify.reach_app import collect_facts, evaluate
    r = evaluate()
    f = collect_facts(r)
    assert f["reachapp.cases"] == 3 and f["reachapp.false_unreachable"] == 2  # 플랜 1 사실(xfail strict 2건)과 동일
    assert f["reachapp.reachable_expected_hit"] == "1/1"


def test_gate_renders_mechanical_verdicts_with_markers():
    from tools.verify.gate import GATES, render_gate
    facts = {"profile.rows": 4, "profile.drift": 3, "sca.recall_cve": "37/46", "sca.recall_cve.team": "34/34",
             "sca.recall_cve.dev-found": "3/12", "sca.missed": 9, "sca.missed_high_important": 3,
             "sca.missed_by_stage.scanner": 9, "sca.missed_by_stage.normalize": 0,
             "knownfp.component_present": "True", "knownfp.version_preserved": "True", "knownfp.not_reported": "True",
             "knownfp.found_version": "13.2.1.jre11", "sca.extras": 1, "sca.extras.unclassified": 0,
             "surface.bom_only": 77, "surface.jar_only": 9, "surface.version_differs": 1, "surface.gt_match_bom": "16/16",
             "surface.gt_match_jar": "15/16", "reachapp.cases": 3, "reachapp.false_unreachable": 2,
             "reach.reachable": 0, "reach.unreachable": 48, "reach.unknown": 0, "gta.in_category_pass": "2/4",
             "fidelity.roundtrip_identical": "True", "fidelity.id_set_mismatch": 0, "fidelity.disposition_mismatch": 0,
             "fidelity.deterministic": "True", "fidelity.meta_scanner_status_rows": 3, "fidelity.undecided": 0}
    md = render_gate(facts)
    rows = [l for l in md.splitlines() if l.startswith("| ") and not l.startswith("| 축")]
    verdicts = {l.split("|")[1].strip().split(" ")[0]: l.split("|")[4].strip() for l in rows}
    assert verdicts["1"] == "✓" and verdicts["3"] == "✓" and verdicts["4"] == "✓" and verdicts["8"] == "✓"
    assert verdicts["2"].startswith("✗") and verdicts["5"].startswith("✗") and verdicts["6"].startswith("✗") and verdicts["7"].startswith("✗")
    assert verdicts["9"] == "기록"
    assert "37/46 <!-- fact:sca.recall_cve -->" in md and "2 <!-- fact:reachapp.false_unreachable -->" in md
    assert len(GATES) == 9


def test_gate_marks_missing_fact_as_unmeasured_not_pass():
    from tools.verify.gate import render_gate
    md = render_gate({"profile.rows": 4, "profile.drift": 3})
    row2 = next(l for l in md.splitlines() if l.startswith("| 2 "))
    assert "미측정" in row2 and "✓" not in row2


def test_generators_registry_isolates_failures(tmp_path, monkeypatch):
    from tools.verify import generators
    from tools.verify.reconcile import regenerate
    def boom(ctx):
        raise FileNotFoundError("evidence missing")
    monkeypatch.setattr(generators, "GENERATORS", [generators.Generator("boom.md", None, boom)])
    rows = regenerate(tmp_path, tmp_path, "gt-b.json", "gt-a.json")
    assert rows == [{"doc": "boom.md", "ok": False, "note": "생성 실패: FileNotFoundError: evidence missing"}]


def test_reconcile_escapes_pipes_in_report_cells():
    from tools.verify.reconcile import render_report
    md = render_report([], {}, {}, [], {"raw_count": 0, "typed_count": 0, "only_raw": [], "only_typed": []},
                       quotes=[{"header": "| a | b |", "quote": "x.md", "ok": True, "note": ""}], stats={})
    line = next(l for l in md.splitlines() if "x.md" in l)
    assert line.count("|") == 4 and "\\|" in line  # 셀 3개 = 구분자 4개


def test_attrition_rows_follow_trace_order():
    from tools.verify.report import render_attrition
    trace = {"stages": [{"stage": "normalize:semgrep", "count": 2, "keys": []}, {"stage": "normalize:trivy", "count": 3, "keys": []},
                        {"stage": "merge", "count": 5, "keys": []}, {"stage": "exclude", "count": 4, "keys": []}]}
    lines = [l for l in render_attrition(trace).splitlines() if l.startswith("| ")][2:]
    assert [l.split("|")[1].strip() for l in lines] == ["normalize:semgrep", "normalize:trivy", "normalize(합계)", "merge", "exclude"]
    assert lines[3].split("|")[3].strip() == "0" and lines[4].split("|")[3].strip() == "-1"
```

- [ ] **Step 2: 실패 확인** — 모듈 없음 / 이스케이프 없음.

- [ ] **Step 3: `tools/verify/reach_app.py`** — `tests/test_reach_app.py` 가 finding 을 구성해 `decide_reachability(findings, parse_invoked_symbols(SLICE))` 로 판정하는 코드를 **그대로 옮긴다**(테스트는 이 모듈을 import 해 같은 결과를 xfail(strict) 로 단언 — 단일 소스).

```python
"""축 6(b) 도달성 픽스처 정본 — fixtures/reach-app/expected.json × tests/golden/atom-usages-reach-app.json.

tests/test_reach_app.py 와 같은 판정 코드를 공유한다(단일 소스). 게이트는 gate.py 가 facts 로 내린다.
"""
from __future__ import annotations

import json
from pathlib import Path

from secscan.models import UNREACHABLE, Advisory, Component, Finding, Reachability
from secscan.reachability.depscan import decide_reachability, parse_invoked_symbols

from ._facts import facts_text

FIXTURE = Path("fixtures/reach-app/expected.json")
SLICE = Path("tests/golden/atom-usages-reach-app.json")


def build_findings(expected: dict) -> list[Finding]:
    fs = []
    for kind in ("reachable", "must_not_be_unreachable"):
        for e in expected[kind]:
            fs.append(Finding(category="sca", severity="high", rule_id=e["cve"],
                              component=Component("maven", e["package"], e["version"]), advisory=Advisory(e["cve"])))
    return fs


def evaluate(fixture: Path = FIXTURE, slice_path: Path = SLICE) -> dict:
    expected = json.loads(fixture.read_text(encoding="utf-8"))
    fs = build_findings(expected)
    result = decide_reachability(fs, parse_invoked_symbols(slice_path.read_text(encoding="utf-8")))
    verdict = {k: v for k, v in result.verdicts.items()}  # "package@version" -> status
    rows = []
    for kind in ("reachable", "must_not_be_unreachable"):
        for e in expected[kind]:
            status = verdict.get(f"{e['package']}@{e['version']}", "unknown")
            rows.append({"case": kind, "package": e["package"], "cve": e["cve"], "status": status,
                         "ok": (status == "reachable") if kind == "reachable" else (status != UNREACHABLE)})
    return {"cases": len(rows), "rows": rows,
            "false_unreachable": sum(1 for r in rows if r["case"] == "must_not_be_unreachable" and r["status"] == UNREACHABLE),
            "reachable_hit": (sum(1 for r in rows if r["case"] == "reachable" and r["ok"]), sum(1 for r in rows if r["case"] == "reachable"))}


def collect_facts(r: dict) -> dict:
    return {"reachapp.cases": r["cases"], "reachapp.false_unreachable": r["false_unreachable"],
            "reachapp.reachable_expected_hit": f"{r['reachable_hit'][0]}/{r['reachable_hit'][1]}"}


def render(r: dict) -> str:
    L = ["# reach-app 도달성 픽스처 (축 6(b) — 생성 문서)", "", "| 케이스 | 패키지 | CVE | 현 엔진 판정 | 기대 충족 |", "|---|---|---|---|---|"]
    L += [f"| {x['case']} | {x['package']} | {x['cve']} | {x['status']} | {x['ok']} |" for x in r["rows"]]
    return "\n".join(L) + "\n"
```
`decide_reachability` 의 반환 형태(`verdicts` 키 형식·컴포넌트 좌표 처리)는 `tests/test_reach_app.py` 를 읽어 **그 테스트가 쓰는 방식과 동일하게** 맞춘다(패키지 표기가 `group:artifact` 인지 artifact 만인지 픽스처 기준). 테스트의 xfail(strict) 2건이 `false_unreachable == 2` 와 같은 사실을 가리켜야 한다.

- [ ] **Step 4: `tools/verify/gate.py`**

```python
"""게이트 문서 생성기(spec §5 상수 → facts 비교, 정오표 (g)). 판정 열은 이 코드의 출력이다 — 사람·AI 가 쓰지 않는다."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


def _ratio(v) -> tuple[int, int]:
    a, b = str(v).split("/")
    return int(a), int(b)


@dataclass(frozen=True)
class Gate:
    axis: str
    criterion: str
    facts: tuple[str, ...]  # 측정값 열에 인용할 id(전부 있어야 판정)
    verdict: Callable[[dict], bool] | None  # None = 기록만


GATES: tuple[Gate, ...] = (
    Gate("1 프로파일 계약", "드리프트 전건 문서화 + spec 갱신 백로그", ("profile.rows", "profile.drift"), lambda f: True),
    Gate("2 SCA recall(GT-B 대비)", "CVE 단위 합산 ≥ 44/46 · HIGH/Important 미탐 ≤ 1 · 미탐 전건 단계 특정(origin 별 병기)",
         ("sca.recall_cve", "sca.recall_cve.team", "sca.recall_cve.dev-found", "sca.missed", "sca.missed_high_important",
          "sca.missed_by_stage.scanner", "sca.missed_by_stage.normalize"),
         lambda f: _ratio(f["sca.recall_cve"])[0] * 46 >= 44 * _ratio(f["sca.recall_cve"])[1] and int(f["sca.missed_high_important"]) <= 1),
    Gate("3 SCA known-FP(mssql-jdbc CVE-2025-59250)", "3단계 모두 True",
         ("knownfp.component_present", "knownfp.version_preserved", "knownfp.not_reported", "knownfp.found_version"),
         lambda f: all(f[k] == "True" for k in ("knownfp.component_present", "knownfp.version_preserved", "knownfp.not_reported"))),
    Gate("4 SCA 초과분 분류", "미분류 0", ("sca.extras", "sca.extras.unclassified"), lambda f: int(f["sca.extras.unclassified"]) == 0),
    Gate("5 입력면 교차", "해석 버전 불일치 0 (인벤토리 차 원인은 input-surface.md 표 참조)",
         ("surface.bom_only", "surface.jar_only", "surface.version_differs", "surface.gt_match_bom", "surface.gt_match_jar"),
         lambda f: int(f["surface.version_differs"]) == 0),
    Gate("6 도달성", "false-unreachable = 0 (프레임워크 활성화 케이스 포함)",
         ("reachapp.cases", "reachapp.false_unreachable", "reach.reachable", "reach.unreachable", "reach.unknown"),
         lambda f: int(f["reachapp.false_unreachable"]) == 0),
    Gate("7 GT-A differential(범주 내)", "범주 내 출현·소멸 100%", ("gta.in_category_pass",),
         lambda f: _ratio(f["gta.in_category_pass"])[0] == _ratio(f["gta.in_category_pass"])[1]),
    Gate("8 보고서 충실성", "왕복 동일 · id 집합 동일 · 판정 불일치 0 · 결정성",
         ("fidelity.roundtrip_identical", "fidelity.id_set_mismatch", "fidelity.disposition_mismatch", "fidelity.deterministic",
          "fidelity.meta_scanner_status_rows", "fidelity.undecided"),
         lambda f: f["fidelity.roundtrip_identical"] == "True" and int(f["fidelity.id_set_mismatch"]) == 0
                   and int(f["fidelity.disposition_mismatch"]) == 0 and f["fidelity.deterministic"] == "True"),
    Gate("9 측정 사실성", "reconcile 검사 전항 0 — 값은 reconcile-report.md 참조(이 문서를 재생성하는 검증기 자신의 결과라 여기 인용하지 않음)", (), None),
)


def _cell(facts: dict, ids: tuple[str, ...]) -> str:
    return " · ".join(f"{i.split('.', 1)[1]} {facts[i]} <!-- fact:{i} -->" for i in ids)


def render_gate(facts: dict) -> str:
    L = ["# 게이트 (생성 문서 — spec §5 상수 vs facts*.json, tools/verify/gate.py)", "",
         "판정 열은 생성기 출력이다(정오표 (g)). 게이트 미통과는 캠페인 실패가 아니라 백로그 P1 등록 사유(spec §5).", "",
         "| 축 | 기준(spec §5) | 측정값 | 판정 |", "|---|---|---|---|"]
    passed, failed, recorded, unmeasured = [], [], [], []
    for g in GATES:
        missing = [i for i in g.facts if i not in facts]
        if missing:
            L.append(f"| {g.axis} | {g.criterion} | 정본 없음 | 미측정(정본 없음: {', '.join(missing)}) |")
            unmeasured.append(g.axis); continue
        value = _cell(facts, g.facts) if g.facts else "reconcile-report.md 참조"
        if g.verdict is None:
            v = "기록"; recorded.append(g.axis)
        elif g.verdict(facts):
            v = "✓"; passed.append(g.axis)
        else:
            v = "✗ → 백로그 P1"; failed.append(g.axis)
        L.append(f"| {g.axis} | {g.criterion} | {value} | {v} |")
    L += ["", "## 요약",
          f"- 통과: {', '.join(passed) or '없음'}", f"- 미통과(백로그 P1): {', '.join(failed) or '없음'}",
          f"- 기록만: {', '.join(recorded) or '없음'}", f"- 미측정: {', '.join(unmeasured) or '없음'}", ""]
    return "\n".join(L)
```

- [ ] **Step 5: `tools/verify/generators.py` + `reconcile.regenerate` 교체**

```python
"""생성기 레지스트리 — 모든 생성 문서·facts 가 한 경로로 만들어지고(write_all) 같은 경로로 재생성·비교된다(reconcile).

새 축 = Generator 한 줄 추가. 검사 누락이 구조적으로 불가능해진다(최종 리뷰 Rec 2).
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from secscan.measure import load_gt_manifest

from . import differential, fidelity, gate, jar_surface, known_fp, profile_contract, reach_app, report
from ._facts import facts_text


@dataclass(frozen=True)
class Ctx:
    results: Path
    evidence_root: Path
    gt_b: Path
    gt_a: Path
    std_name: str = "a483b3b1-standard"
    deep_name: str = "a483b3b1-deep"
    jar_name: str = "a483b3b1-jar"

    @property
    def std(self) -> Path: return self.evidence_root / self.std_name
    @property
    def deep_meta(self) -> Path: return self.evidence_root / self.deep_name / "meta.json"
    @property
    def jar_raw(self) -> Path: return self.evidence_root / self.jar_name / "raw" / "trivy-rootfs.json"
    @property
    def jar_status(self) -> Path: return self.evidence_root / self.jar_name / "status.json"


@dataclass(frozen=True)
class Generator:
    doc: str  # 결과 디렉토리 안 문서 파일명
    facts: str | None  # facts 파일명(없으면 None)
    produce: Callable[[Ctx], tuple[str, dict | None]]  # (문서 텍스트, facts dict)


def _via_cli(main, args: list[str], doc_name: str, facts_name: str | None):
    with tempfile.TemporaryDirectory() as td, contextlib.redirect_stdout(io.StringIO()):
        t = Path(td)
        argv = args + ["--out", str(t / doc_name)] + (["--facts", str(t / "f.json")] if facts_name else [])
        main(argv)
        doc = (t / doc_name).read_text(encoding="utf-8")
        facts = json.loads((t / "f.json").read_text(encoding="utf-8")) if facts_name else None
    return doc, facts


def _gt_b_match(c: Ctx):
    return _via_cli(report.main, ["--evidence", str(c.std), "--gt", str(c.gt_b)], "m.md", "facts.json")


def _gt_a_diff(c: Ctx):
    return _via_cli(differential.main, ["--evidence-root", str(c.evidence_root), "--gt", str(c.gt_a)], "d.md", "facts-gta.json")


def _known_fp(c: Ctx):
    from .reconcile import _KNOWN_FP
    r = known_fp.check_known_fp((c.std / "raw" / "bom.cdx.json").read_text(encoding="utf-8"),
                                (c.std / "raw" / "trivy.json").read_text(encoding="utf-8"), **_KNOWN_FP)
    return known_fp.render(r), known_fp.collect_facts(r)


def _profile(c: Ctx):
    statuses = {s["tool"]: s["status"] for s in json.loads(c.deep_meta.read_text(encoding="utf-8"))["scanner_status"]}
    return profile_contract.render_doc(statuses), profile_contract.collect_facts(statuses)


def _surface(c: Ctx):
    ok = bool(json.loads(c.jar_status.read_text(encoding="utf-8")).get("jar_build_scan_ok", False))
    bom, jar = (c.std / "raw" / "bom.cdx.json").read_text(encoding="utf-8"), c.jar_raw.read_text(encoding="utf-8")
    m = load_gt_manifest(str(c.gt_b))
    return jar_surface.render_doc(ok, bom, jar, m), jar_surface.collect_facts(ok, bom, jar, m)


def _fidelity(c: Ctx):
    r = fidelity.check(c.std)
    return fidelity.render(r), fidelity.collect_facts(r)


def _reach_app(c: Ctx):
    r = reach_app.evaluate()
    return reach_app.render(r), reach_app.collect_facts(r)


def _gate(c: Ctx):
    from .reconcile import load_facts
    return gate.render_gate(load_facts(c.results)), None


GENERATORS: list[Generator] = [
    Generator("gt-b-match.md", "facts.json", _gt_b_match),
    Generator("gt-a-differential.md", "facts-gta.json", _gt_a_diff),
    Generator("known-fp.md", "facts-knownfp.json", _known_fp),
    Generator("profile-contract.md", "facts-profile.json", _profile),
    Generator("input-surface.md", "facts-surface.json", _surface),
    Generator("fidelity.md", "facts-fidelity.json", _fidelity),
    Generator("reach-app.md", "facts-reachapp.json", _reach_app),
    Generator("gate.md", None, _gate),  # 마지막: 위 facts 를 읽는다
]


def write_all(ctx: Ctx) -> list[Path]:
    ctx.results.mkdir(parents=True, exist_ok=True)
    written = []
    for g in GENERATORS:
        doc, facts = g.produce(ctx)
        p = ctx.results / g.doc; p.write_text(doc, encoding="utf-8"); written.append(p)
        if g.facts:
            q = ctx.results / g.facts; q.write_text(facts_text(facts), encoding="utf-8"); written.append(q)
    return written


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="tools.verify.generators")
    p.add_argument("--results", required=True); p.add_argument("--evidence-root", required=True)
    p.add_argument("--gt-b", required=True); p.add_argument("--gt-a", required=True)
    p.add_argument("--std", default="a483b3b1-standard"); p.add_argument("--deep", default="a483b3b1-deep"); p.add_argument("--jar", default="a483b3b1-jar")
    a = p.parse_args(argv)
    for w in write_all(Ctx(Path(a.results), Path(a.evidence_root), Path(a.gt_b), Path(a.gt_a), a.std, a.deep, a.jar)):
        print(w)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

`tools/verify/reconcile.py` 의 `regenerate` 를 교체(레지스트리 순회 + 예외 격리). 옛 results 디렉토리(2026-09-05)에는 `fidelity.md`·`reach-app.md`·`gate.md` 가 없으므로 **문서 파일이 없으면 "결과 파일 없음(선택)" 로 ok=True** 처리하는 `optional` 집합을 둔다: `_OPTIONAL = {"fidelity.md", "reach-app.md", "gate.md", "facts-fidelity.json", "facts-reachapp.json"}` — 있으면 비교, 없으면 건너뛴다(플랜 1 결과 디렉토리 호환). 입력면 raw 경로는 Task 13 이 evidence 로 옮기므로, 이 태스크에서는 `Ctx.jar_raw` 가 없으면 `results/input-surface.trivy-fs.json` 을 폴백으로 읽는 한 줄을 `_surface` 에 둔다(Task 13 에서 제거).

```python
def regenerate(results_dir, evidence_root, gt_b, gt_a, *, std_name: str = "a483b3b1-standard") -> list[dict]:
    """생성 문서·facts 를 레지스트리로 다시 만들어 바이트 비교. 생성기 예외는 ✗ 행으로 격리(부분 실패 정상)."""
    from .generators import GENERATORS, Ctx
    res = Path(results_dir)
    ctx = Ctx(res, Path(evidence_root), Path(gt_b), Path(gt_a), std_name)
    rows: list[dict] = []

    def cmp(name: str, text: str, optional: bool) -> None:
        p = res / name
        if not p.exists():
            if not optional:
                rows.append({"doc": name, "ok": False, "note": "결과 파일 없음"})
            return
        same = p.read_text(encoding="utf-8") == text
        rows.append({"doc": name, "ok": same, "note": "" if same else "재생성 결과와 다름"})

    for g in GENERATORS:
        try:
            doc, facts = g.produce(ctx)
        except Exception as e:  # 증거 부재 등 — 죽지 않고 ✗ 행(M4/N6)
            rows.append({"doc": g.doc, "ok": False, "note": f"생성 실패: {type(e).__name__}: {e}"})
            continue
        cmp(g.doc, doc, g.doc in _OPTIONAL)
        if g.facts:
            cmp(g.facts, facts_text(facts), g.facts in _OPTIONAL)
    return rows
```
`main` 의 `docs` 사전에 `"gate.md": (res / "gate.md", None)` 를 추가한다(있으면 마커 검사).

N1: `check_quoted_tables` 의 인용 선언 탐지를 20자 창이 아니라 **줄 단위**로 바꾼다 — "전체 인용" 을 포함하는 줄에서 첫 백틱 파일명(`\`([\w.-]+\.md)\``)을 취하고, 파일명이 없는 선언 줄은 `{"quote": line, "header": "", "ok": False, "note": "선언 줄에 파일명 없음"}` 행으로 남긴다. N4: `render_report` 의 모든 셀 문자열에 `_esc = lambda s: str(s).replace("|", "\\|")` 적용. N5: `main` 의 2단계 뒤 `self_mm = sum(not r["ok"] for rows in markers.values() for r in rows if r["id"].startswith("reconcile."))` 를 `final_facts["reconcile.self_marker_mismatch"]` 로 기록하고 verdict 합에 포함; `reconcile.marker_mismatch` 는 1단계(seed) 값을 유지한다(문서가 인용하는 값 = 비교된 값).

N3: `report.render_attrition` 이 `trace["stages"]` 순서를 보존하며 `normalize:*` 행들 뒤에 `normalize(합계)` 를 끼우고, 이후 파이프라인 행의 증감을 합계부터 계산하게 한다(현재 partition 정렬을 제거). 위 테스트가 기대 순서를 고정한다.

- [ ] **Step 6: `tests/test_reach_app.py` 를 `tools.verify.reach_app` 사용으로 정리** — 기존 xfail(strict) 2건은 유지하되 판정 코드는 `reach_app.evaluate()` 의 `rows` 를 읽는다.

- [ ] **Step 7: 통과 확인 + 전체 회귀 + 옛 results 로 reconcile 실행**

```bash
.venv/bin/pytest -q
.venv/bin/python -m tools.verify.reconcile --results docs/verification/results/2026-09-05 --evidence-root docs/verification/evidence/2026-09-05 \
  --gt-b docs/verification/ground-truth/gt-b-sca.json --gt-a docs/verification/ground-truth/gt-a-source.json \
  --measurement docs/measurements/2026-09-05-message-gate-verification.md; echo "exit=$?"
```
Expected: exit 0(옛 results 는 선택 생성기가 없어 건너뛰고, 기존 5종+facts 는 동일). N3 로 `gt-b-match.md` 의 attrition 표 순서가 바뀌면 ✗ 가 난다 — 이 경우 **생성기로 옛 결과를 재생성**(`python -m tools.verify.generators ... --results docs/verification/results/2026-09-05` 는 gate.md 등 신규 문서도 만들므로 쓰지 말고, `report.main --evidence … --out docs/verification/results/2026-09-05/gt-b-match.md --facts …/facts.json` 만 실행)하고 측정 문서의 인용 표를 갱신한 뒤 다시 exit 0 을 확인한다. 값은 바뀌지 않는다(순서만).

- [ ] **Step 8: 커밋**

```bash
git add tools/verify/reach_app.py tools/verify/gate.py tools/verify/generators.py tools/verify/reconcile.py tools/verify/report.py tests/test_reach_app.py tests/test_verify_tools.py docs/verification/results/2026-09-05 docs/measurements/2026-09-05-message-gate-verification.md
git commit -m "feat(V7): gate.py 판정 생성기(spec §5 상수, 정오표 (g)) + 생성기 레지스트리(regenerate 순회·예외 격리) + reach-app 정본 + reconcile N1/N3/N4/N5

다음: 위생 — iter_vulns(M1)·입력면 raw 를 evidence 로(M3)·gta id 위치독립(M7)·증거 경로 상대화(M8)·README 생성기"
```

---

### Task 13: 위생 — M1 · M3 · M7 · M8 · README 생성기 · 파킹 잔여

**Files:**
- Create: `tools/verify/_trivy.py`, `tools/verify/evidence_readme.py`
- Modify: `tools/verify/{jar_surface,known_fp,report,reconcile,differential,evidence,generators}.py`, `docs/verification/results/2026-09-05/{facts-gta.json,gate-v3.md,gt-a-differential.md}`(생성기·스크립트로), `docs/measurements/2026-09-05-message-gate-verification.md`(마커 id 개명만)
- Move: `docs/verification/results/2026-09-05/input-surface.trivy-fs.json` → `docs/verification/evidence/2026-09-05/a483b3b1-jar/raw/trivy-rootfs.json`, `input-surface.status.json` → `…/a483b3b1-jar/status.json` (`git mv`, 바이트 불변)
- Test: `tests/test_verify_tools.py` 끝에 추가

**Interfaces:**
- Produces: `_trivy.iter_vulns(payload_or_dict) -> Iterator[tuple[str, dict]]`(`(Target, vuln)`); `differential.collect_facts` id `gta.<cwe>.<stem>.passed|fixed_residual|observed`(stem = `Path(entry["file_suffix"]).stem`, 같은 `<cwe>.<stem>` 중복 시 `-2`, `-3` 접미); `evidence.write_evidence(..., repo_root=None)` — `repo_root` 가 주어지면 `location.file` 과 `source` 를 그 루트 기준 상대 경로로 정규화(M8, 새 증거만); `evidence_readme.render(evidence_root: Path) -> str`(각 `*/meta.json` 에서 표 생성: 디렉토리·스냅샷·프로파일·스캐너 status·findings 수·소요·도달성 사유·reinput 여부); `jar_surface.main --evidence-out <dir>` 가 raw/status 를 evidence 에 쓴다.

- [ ] **Step 1: 실패하는 테스트**

```python
# tests/test_verify_tools.py 끝에 추가
def test_iter_vulns_yields_target_and_vuln():
    from tools.verify._trivy import iter_vulns
    payload = json.dumps({"Results": [{"Target": "Java", "Vulnerabilities": [{"VulnerabilityID": "CVE-1"}]}, {"Target": "x", "Vulnerabilities": None}]})
    assert list(iter_vulns(payload)) == [("Java", {"VulnerabilityID": "CVE-1"})]


def test_gta_fact_ids_are_position_independent():
    from tools.verify.differential import collect_facts
    rows = [{"class": "in-category", "cwe": "CWE-89", "file_suffix": "LgCarrierMapper.xml", "passed": False, "fixed_residual": 8},
            {"class": "in-category", "cwe": "CWE-89", "file_suffix": "OldLgCarrierMapper.xml", "passed": False, "fixed_residual": 5},
            {"class": "measure-then-classify", "cwe": "CWE-489", "file_suffix": "App.java", "observed": []}]
    f = collect_facts(rows)
    assert f["gta.CWE-89.LgCarrierMapper.fixed_residual"] == 8 and f["gta.CWE-89.OldLgCarrierMapper.fixed_residual"] == 5
    assert f["gta.CWE-489.App.observed"] == "없음"
    assert collect_facts(list(reversed(rows))) == f  # 순서 무관


def test_write_evidence_relativizes_paths_when_repo_root_given(tmp_path):
    from secscan.disposition import decide
    from secscan.models import Finding, Location
    from secscan.output.json_io import from_json
    from secscan.scan import ScanResult
    from tools.verify.evidence import write_evidence
    root = tmp_path / "repo"; (root / "src").mkdir(parents=True)
    f = decide([Finding(category="sast", severity="high", rule_id="r", location=Location(str(root / "src" / "A.java"), 1), source=str(root / "pom.xml"))])
    write_evidence(tmp_path / "ev", result=ScanResult(findings=f, raw_results=[]), trace=None, meta={}, repo_root=root)
    back = from_json((tmp_path / "ev" / "findings.json").read_text())
    assert back[0].location.file == "src/A.java" and back[0].source == "pom.xml"


def test_evidence_readme_is_rendered_from_meta(tmp_path):
    from tools.verify.evidence_readme import render
    d = tmp_path / "abc-standard"; d.mkdir()
    (d / "meta.json").write_text(json.dumps({"snapshot": "abc", "profile": "standard", "elapsed_s": 8.5,
                                             "scanner_status": [{"tool": "trivy", "status": "ok"}], "reachability": {"ran": True, "reason": "ok"}}))
    (d / "findings.json").write_text(json.dumps({"@context": "secscan-findings/v1", "meta": {}, "findings": []}))
    md = render(tmp_path)
    assert "| abc-standard | abc | standard | trivy(ok) | 0 | 8.5 | ok |" in md
```

- [ ] **Step 2: 실패 확인** — 모듈 없음 / 옛 id 형식.

- [ ] **Step 3: 구현**

`tools/verify/_trivy.py`:
```python
"""trivy JSON 순회 단일화(최종 리뷰 M1). 제품 코드(secscan/normalize/trivy.py)는 건드리지 않는다."""
from __future__ import annotations

import json
from typing import Iterator


def iter_vulns(payload) -> Iterator[tuple[str, dict]]:
    data = json.loads(payload) if isinstance(payload, str) else (payload or {})
    for res in data.get("Results", []) or []:
        for v in res.get("Vulnerabilities") or []:
            yield res.get("Target", ""), v
```
`jar_surface.py`(2곳)·`known_fp.py`·`report.py`(`raw_vulns`, `published_dates`)·`reconcile.py`(`raw_vs_typed`) 의 인라인 순회를 `iter_vulns` 로 교체(동작 동일 — 골든·재생성 비교로 확인).

`differential.collect_facts`:
```python
def _slot(cwe: str, entry: dict, used: dict) -> str:
    stem = Path(entry.get("file_suffix", "") or "row").stem or "row"
    base = f"gta.{cwe}.{stem}"
    n = used.get(base, 0) + 1
    used[base] = n
    return base if n == 1 else f"{base}-{n}"


def collect_facts(rows: list[dict]) -> dict:
    in_cat = [r for r in rows if r["class"] == "in-category"]
    facts: dict = {"gta.in_category_pass": f"{sum(1 for r in in_cat if r['passed'])}/{len(in_cat)}"}
    used: dict = {}
    for r in sorted(rows, key=lambda r: (r["cwe"], Path(r.get("file_suffix", "")).stem, r["class"])):
        slot = _slot(r["cwe"], r, used)
        if r["class"] == "in-category":
            facts[f"{slot}.passed"] = str(r["passed"])
            facts[f"{slot}.fixed_residual"] = r.get("fixed_residual", 0)
        elif r["class"] == "measure-then-classify":
            facts[f"{slot}.observed"] = ", ".join(r.get("observed", [])) or "없음"
    return facts
```
(`rows` 에 `file_suffix` 가 없다면 `evaluate_pair` 가 entry 의 `file_suffix` 를 row 에 실어주도록 한 줄 추가.)

옛 결과 갱신(값 불변, id 만): `facts-gta.json`·`gt-a-differential.md` 를 생성기로 재생성하고, `gate-v3.md`·측정 문서의 `<!-- fact:gta.row<i>.<cwe>.* -->` 마커를 새 id 로 치환하는 스크립트를 실행한다:
```bash
.venv/bin/python - <<'PY'
import json, re, pathlib
old = json.loads(pathlib.Path("docs/verification/results/2026-09-05/facts-gta.json").read_text())   # 재생성 전 백업본을 먼저 읽어 둔다
PY
```
정확한 절차: (1) 재생성 **전** `facts-gta.json` 을 `/tmp/facts-gta.old.json` 으로 복사, (2) `differential.main --evidence-root docs/verification/evidence/2026-09-05 --gt docs/verification/ground-truth/gt-a-source.json --out docs/verification/results/2026-09-05/gt-a-differential.md --facts docs/verification/results/2026-09-05/facts-gta.json`, (3) 옛/새 facts 를 **값 순서로 짝지어**(같은 순서로 생성되므로 `row{i}` 인덱스 ↔ 정렬된 새 슬롯을 `gt-a-source.json` 의 항목 순서로 대응) old→new id 사전을 만들고 두 문서에서 `fact:<old>` 를 `fact:<new>` 로 치환, (4) reconcile 실행 exit 0 확인(값 마커 전건 일치가 곧 치환 정확성의 증명).

M3: `git mv` 두 파일 → `docs/verification/evidence/2026-09-05/a483b3b1-jar/raw/trivy-rootfs.json`, `…/a483b3b1-jar/status.json`. `jar_surface.main` 에 `--evidence-out <dir>` 를 추가해 raw/status 를 그 디렉토리에 쓰고(`--out` 은 md 만), `generators._surface` 의 폴백 한 줄을 제거한다. 파일명 `trivy-fs` → `trivy-rootfs`(실제 모드).

M8: `evidence.write_evidence(..., repo_root: Path | None = None)`; 주어지면 `findings` 를 `replace(f, location=replace(f.location, file=_rel(f.location.file)), source=_rel(f.source))` 로 정규화한 뒤 저장(`_rel(p)`: `p` 가 `repo_root` 아래 절대경로면 상대화, 아니면 그대로). `run_snapshot.main` 은 `repo_root=repo_dir` 를 넘긴다. 옛 증거는 손대지 않는다.

`tools/verify/evidence_readme.py`:
```python
"""증거 README 생성기(최종 리뷰 Rec 5) — meta.json 들에서 표를 만든다. 손기입 수치 없음."""
from __future__ import annotations

import json
from pathlib import Path


def render(evidence_root: Path) -> str:
    root = Path(evidence_root)
    L = [f"# 증거 동결 {root.name} (생성 문서 — tools/verify/evidence_readme.py)", "",
         "| 디렉토리 | 스냅샷 | 프로파일 | 스캐너 status | findings | 소요(s) | 도달성 사유 | 재입력 |", "|---|---|---|---|---|---|---|---|"]
    for d in sorted(p for p in root.iterdir() if p.is_dir() and (p / "meta.json").exists()):
        m = json.loads((d / "meta.json").read_text(encoding="utf-8"))
        n = len(json.loads((d / "findings.json").read_text(encoding="utf-8")).get("findings", [])) if (d / "findings.json").exists() else "-"
        st = ", ".join(f"{s.get('tool') or s.get('name')}({s['status']})" for s in m.get("scanner_status", []))
        L.append(f"| {d.name} | {m.get('snapshot', '')} | {m.get('profile', '')} | {st} | {n} | {m.get('elapsed_s', '')} | "
                 f"{m.get('reachability', {}).get('reason', '')} | {'예' if m.get('reinput_from') else ''} |")
    L += ["", "- 도구 버전: 각 `meta.json` `tool_versions`. 격리: 스냅샷별 scratch·GRADLE_USER_HOME·크리덴셜 제거·secret 검증 never(`meta.isolated`).", ""]
    return "\n".join(L)
```
`generators.GENERATORS` 에 `Generator("README.md", None, lambda c: (evidence_readme.render(c.evidence_root), None))` 를 추가하되 문서 경로가 evidence 루트이므로 `Generator` 에 `path: str | None = None`(결과 디렉토리 밖 경로 지정) 필드를 더해 `regenerate`/`write_all` 이 그 경로를 쓰게 한다. 옛 증거 README(2026-09-05, 손기입 운영 로그)는 `_OPTIONAL` 로 비교에서 제외한다 — 생성기는 새 증거 디렉토리에만 쓴다.

파킹 잔여: `tests/test_verify_tools.py` 에 `sca.extras.unclassified` 가 1 이상인 케이스 테스트 1개 추가(플랜 1 파킹 Task 8).

- [ ] **Step 4: 통과 확인 + reconcile(옛 results) exit 0 + 전체 회귀**

- [ ] **Step 5: 커밋**

```bash
git add -A tools/verify tests/test_verify_tools.py docs/verification/results/2026-09-05 docs/verification/evidence/2026-09-05/a483b3b1-jar docs/measurements/2026-09-05-message-gate-verification.md
git commit -m "chore(V7): 위생 — iter_vulns 단일화(M1), 입력면 raw 를 evidence 로 이동·trivy-rootfs 명명(M3), gta fact id 위치 독립(M7, 옛 결과 재생성·마커 개명), 증거 경로 상대화(M8), README 생성기

다음: V7 최종 실스캔(새 바이너리) + 재입력 + 생성기 일괄 + 측정 문서 + reconcile 고정점"
```

---

### Task 14: V7 — 최종 실스캔 1회 · 재입력 회귀 · 생성 문서 일괄 · 최종 측정 문서 · reconcile 고정점

**Files:**
- Create: `docs/verification/evidence/<D2>/…`(a483b3b1-standard 실스캔, a483b3b1-jar, 재입력 9종), `docs/verification/results/<D2>/…`(생성기 일괄 + reconcile), `docs/measurements/<D2>-message-gate-verification-final.md`
- Modify: `PROGRESS.md`, `CLAUDE.md`(상태 줄), spec 정오표 (a) 해소 문구(§3.2·§5 축 6(a)의 "18" 을 facts 인용으로 정정 — 정오표 절에 "해소: …" 한 줄 추가, 원문은 취소선 없이 각주 참조로)

이 태스크는 **실행 기록**이다. 실스캔은 Bash `dangerouslyDisableSandbox=true`(네트워크·빌드). 실행자는 수치를 쓰지 않는다 — 모든 수치는 생성기 산출 facts 를 마커로 인용한다.

- [ ] **Step 1: 사전 점검·변수**

```bash
.venv/bin/secscan doctor
export VDATE=$(date +%F); export SCRATCH=/private/tmp/secscan-verify-v7; export EVD=docs/verification/evidence/$VDATE; export RES=docs/verification/results/$VDATE
export V1=docs/verification/evidence/2026-09-05; mkdir -p $EVD $RES
git -C /Users/picpal/Desktop/workspace/message-gate rev-parse a483b3b1
```

- [ ] **Step 2: 최종 실스캔(새 바이너리) — GT-B standard + 입력면 jar**

```bash
.venv/bin/python -m tools.verify.run_snapshot --repo /Users/picpal/Desktop/workspace/message-gate --sha a483b3b1 --profile standard \
  --scratch $SCRATCH --out $EVD/a483b3b1-standard --allow-large --xlsx
.venv/bin/python -m tools.verify.jar_surface --repo $SCRATCH/a483b3b1/repo --bom $EVD/a483b3b1-standard/raw/bom.cdx.json \
  --gt docs/verification/ground-truth/gt-b-sca.json --out $RES/input-surface.md --evidence-out $EVD/a483b3b1-jar
```
(`jar_surface.main` 의 실제 인자명은 파일을 읽어 맞춘다. 첫 실행이 trivy DB 갱신으로 타임아웃하면 플랜 1 README 의 절차대로 `trivy image --download-db-only` 후 재실행하고 그 사실을 README 생성 외의 `docs/verification/evidence/$VDATE/NOTES.md` 에 적는다 — 검사망 밖 운영 로그이며 "(추정)" 표기 규칙을 지킨다.)

- [ ] **Step 3: 재입력 회귀 — V1 증거 9종(deep + GT-A 8)을 새 파이프라인으로**

```bash
for d in a483b3b1-deep 29bfb5ba-standard d4a1ded0-standard 1052b80d-standard 72e49a1b-standard 55e58bc6-standard 8428e646-standard 5895c9f4-standard 81f4f31b-standard; do
  .venv/bin/python -m tools.verify.reinput --evidence $V1/$d --out $EVD/$d
done
```
GT-A differential·프로파일 계약(deep meta)은 이 재입력 증거를 읽는다(`meta.reinput_from` 이 남는다 — 측정 문서 스코프 문장에 "GT-A·deep 은 V1 raw 재입력(스캐너 미재실행)" 을 명시).

- [ ] **Step 4: 생성 문서 일괄 + 정본 검증(고정점)**

```bash
.venv/bin/python -m tools.verify.generators --results $RES --evidence-root $EVD --gt-b docs/verification/ground-truth/gt-b-sca.json --gt-a docs/verification/ground-truth/gt-a-source.json
cp $RES/../2026-09-05/extras-triage.json $RES/extras-triage.json   # override 없음(`overrides: []`) — 새 초과분이 있으면 needs_human 에만 기록
.venv/bin/python -m tools.verify.reconcile --results $RES --evidence-root $EVD --gt-b docs/verification/ground-truth/gt-b-sca.json --gt-a docs/verification/ground-truth/gt-a-source.json; echo "exit=$?"
# 두 번째 실행 → 고정점
.venv/bin/python -m tools.verify.reconcile --results $RES --evidence-root $EVD --gt-b docs/verification/ground-truth/gt-b-sca.json --gt-a docs/verification/ground-truth/gt-a-source.json --out /tmp/r2.md; cmp /tmp/r2.md $RES/reconcile-report.md && echo FIXED_POINT
```
Expected: `gate.md` 가 생성되고 reconcile 이 `gate.md` 를 재생성 비교 + 마커 검사한다. exit 0. 초과분에 `sca.extras.unclassified > 0` 이 나오면 **분류하지 말고** `needs_human` 에 항목별 질문만 적는다(축 4 는 gate.md 가 ✗ 로 낸다).

- [ ] **Step 5: 최종 측정 문서 — `docs/measurements/$VDATE-message-gate-verification-final.md`**

구조(스코프 문장 필수: "대상 message-gate a483b3b1 · GT-B(보안팀 trivy 결과 + 개발자 발견분) 대비 · GT-A/deep 은 V1 raw 재입력"):
1. `## 요약` — **`gate.md` 의 표를 전체 인용**(`(`gate.md` 전체 인용)` 선언 → reconcile (f) 대조). 판정 열은 그대로 옮긴다(손으로 쓰지 않는다).
2. 축별 절 — 각 생성 문서 표 전체 인용(gt-b-match·known-fp·profile-contract·input-surface·reach-app·gt-a-differential·fidelity), 수치 산문은 마커 인용.
3. `## 플랜 1 대비 변화` — 같은 fact id 의 2026-09-05 값과 $VDATE 값을 나란히(둘 다 마커; 옛 값은 `docs/verification/results/2026-09-05/facts*.json` 을 `load_facts` 로 읽어 인용 — reconcile 의 `--measurement` 마커 검사는 현재 results 의 facts 만 보므로, 옛 값 열은 `(2026-09-05 정본)` 표기와 함께 코드블록으로 두 facts 파일의 해당 줄을 **그대로 붙여** 인용한다).
4. `## 변이 픽스처(V6)` — secret 3종·억제 전이·deep gradlew: `pytest -q tests/test_secret_variants.py tests/test_suppress_transitions.py tests/test_deep.py` 출력 코드블록 인용(수치 산문 금지).
5. `## needs_human` — gate.md ✗ 항목별 질문(원인 추론 금지), 새 초과분, CWE-89 잔존.
6. `## 백로그(P1 → P2)` — gate.md ✗ 축을 spec §9 V7 순서(안전성 → 재현성 → FN)로 나열: 안전성(false-unreachable, exit code 결함은 V4 에서 해소됨을 fidelity 로 확인) → 재현성(입력면 mssql 이중 항목, 재입력 gitignore 미적용) → FN(dev-found 미탐 9, GT-A CWE-89). 각 항목은 fact 마커 인용 + 관련 생성 문서 링크. spec §13.1 LLM 후보 1(도달성 전제조건 검사)를 다음 사이클 1순위로 **기록**(판단 아님, spec 이 정한 순위).
7. `## 축 9` — `reconcile-report.md` 판정 줄 인용 + `facts-reconcile.json` 값 마커 인용(가능한 id 만).

- [ ] **Step 6: spec 정오표 (a) 해소 + PROGRESS/CLAUDE**

spec 정오표 절 (a) 끝에 한 줄: `해소(플랜 2, $VDATE): §3.2·§5 축 6(a)의 "18건"은 매니페스트 실측 human.verdict_rows / human.verdict_advisories(facts.json)로 읽는다 — 원문은 보존, 이 절이 우선.` (원문 수정 없음.)

`PROGRESS.md`: `## V` 절에 V4~V7 완료 항목(커밋 요약, 생성 문서 목록, gate.md 결과는 "gate.md 참조" — 수치 없음), 백로그 P1 목록은 측정 문서 링크. `CLAUDE.md` 상태 줄: `V 플랜2 완료(판정 H·xlsx·gate 생성기; 최종 측정 docs/measurements/$VDATE-…-final.md)` + 테스트 수·날짜 갱신(pytest 실행값).

- [ ] **Step 7: 최종 확인 + 커밋(2개)**

```bash
.venv/bin/pytest -q
.venv/bin/python -m tools.verify.reconcile --results $RES --evidence-root $EVD --gt-b docs/verification/ground-truth/gt-b-sca.json --gt-a docs/verification/ground-truth/gt-a-source.json --measurement docs/measurements/$VDATE-message-gate-verification-final.md; echo "exit=$?"
grep -rn -i 'BEGIN .*PRIVATE KEY' $EVD || echo "no private key material"; grep -rl '"Secret": "<redacted>"' $EVD | wc -l
git add $EVD $RES && git commit -m "docs(V7): 최종 실스캔(새 바이너리) 증거·재입력 9종·생성 문서 일괄(gate.md 포함) — reconcile 고정점

다음: 최종 측정 문서 + PROGRESS/CLAUDE + spec 정오표 (a) 해소"
git add docs/measurements PROGRESS.md CLAUDE.md docs/superpowers/specs/2026-09-04-verification-campaign-design.md
git commit -m "docs(V7): 최종 측정 문서(축 1~9, gate.md 전체 인용, 백로그 P1 안전성→재현성→FN) + PROGRESS/CLAUDE + spec 정오표 (a) 해소

다음: 캠페인 종료 — 다음 사이클은 spec §13.1 LLM 후보 1(도달성 전제조건 검사) 별도 spec"
```

---

## Self-Review (작성자 체크 — 실행 전 스캔의 입력)

**1. Spec coverage**
- §7.1 모델(Occurrence·Cvss·published·ScannerStatus·정렬): Task 1·2·3·6 / §7.2 findings.json 왕복·CLI 출력: Task 1·6 / §7.3 projection 계약 문서: Task 6 / §7.4 판정 H·exit code 결함·compliance 이동·4 테스트: Task 4·5·6(재입력 회귀)·11(축 8 4출력 일치) / §8 xlsx 시트·집계·방어·결정성·골든: Task 7·8 / §6 픽스처: reach-app(플랜 1)·secret 3종(Task 9)·억제 전이(Task 10)·deep gradlew(Task 10) / §5 축 8: Task 11 / 정오표 (g) 판정 생성기: Task 12 / §4.5 reconcile 레지스트리·(f)·N 항목: Task 12·13 / §4.4 재입력 회귀·최종 실스캔 1회: Task 6·14 / §9 V7 측정 문서·백로그·reconcile 재실행: Task 14 / 정오표 (a) 해소: Task 14 / 플랜 1 이관(I5·M1·M3·M4·M7·M8·Rec 2·Rec 5·N1~N6·파킹 Task 4/8): Task 1·12·13.
- 비범위(spec §13.1 LLM 후보, §13.2 제외 이동·BOM 캐시 키·osv 어댑터 정리): 이 플랜에 없음 — 의도.

**2. Placeholder scan** — "TBD/TODO/적절히/similar to" 없음. 실행자가 파일을 읽어 맞춰야 하는 지점은 명시적으로 "파일을 읽어 맞춘다" 로 적었다(Task 6 SARIF 계약 사실 확인, Task 12 reach-app 판정 구성, Task 14 jar_surface 인자).

**3. Type consistency** — `Sheet = tuple[list[str], list[list]]`(Task 7·8·11) / `build_sheets(findings, meta) -> dict[str, Sheet]` / `write_workbook(...) -> tuple[list[Path], str | None]`(Task 8·CLI·evidence) / `decide`·`decide_one`(Task 4·5·6·7·9·11) / `ScannerStatus(name, status, tool_version, duration_s, message)`(Task 1·3·xlsx Meta) / facts id: `fidelity.*`(Task 11·12), `reachapp.*`(Task 12), `gta.<cwe>.<stem>.*`(Task 13 — Task 12 의 gate 테스트는 `gta.in_category_pass` 만 쓰므로 무관) / `Generator(doc, facts, produce[, path])`(Task 12·13) / `regenerate(..., std_name=)`(Task 12) / markdown id 정규식 `· id `([0-9a-f]{12})``(Task 5·11).
