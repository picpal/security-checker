# 사람·LLM 겸용 점검 보고서 워크북 — 설계 문서

- **작성**: 2026-09-07 · 상태: draft(사용자 검토 대기)
- **상위 spec**: `2026-06-26-jvm-security-scanner-design.md` §5.6(출력 어댑터)·§5.7(Claude 레이어) 의 구체화. 측정 사실성 원칙은 `2026-09-04-verification-campaign-design.md` §4.5 를 계승.
- **근거 실험**: 2026-09-06 work-note 실스캔(15건) → A/B 프로토타입 2종 → A 선택 → 시트 덤프만 받은 sonnet dry-run: needs_confirmation 11 · skipped(계획 기록) 4 · fixed 0 · 금지 행동 0. "취약항목 표만 주면 LLM 이 판단한다" 가설 확인. 서브에이전트가 지적한 문서 결함 2건(의존 경로 부재, 완료 판정 단위 불명확)을 본 설계에 반영.

## 1. 목적

현재 `scan --out` 산출물(report.md·findings.json·findings.sarif·findings.xlsx)은 **증거 계층**이다. 룰 id·CWE 번호·disposition 단어만 있어 개발자가 아니면 "무엇이 왜 문제이고 무엇을 하면 되는지" 를 읽어낼 수 없고, 수정 LLM 에 넘겨도 판단 기준이 문서 안에 없다.

이 설계는 네 독자가 같은 워크북을 읽고 각자의 결정을 내릴 수 있게 한다.

| 독자 | 결정 | 필요한 것 |
|---|---|---|
| 경영진·PM | 지금 조치가 필요한가, 몇 건인가 | 결론 한 문단 + 숫자 4개 |
| 보안팀·감사 | 조치·억제 확정 | 판정 규칙, 근거, KISA/PCI 매핑 |
| 개발자 | 어디를 어떻게 고치나 | 위치, 일반어 설명, 수정 방법, 완료 확인 |
| 수정 LLM | 무엇을 자동으로 고치고 무엇을 되물을까 | 담당 열, 확인 질문, 허용 범위·금지, 결과 반환 템플릿 |

## 2. 범위

**범위**: 워크북 5 시트, 룰 지식베이스, 파생 규칙(우선순위·담당·그룹), 의존 경로, Claude 해석 계층의 파일 인터페이스와 검증기, 결과 반환 템플릿과 결과 검증기, `secscan report` 커맨드, 테스트·골든.

**비범위**: LLM 수정 실행기 자체(외부 세션이 수행), 억제 자동화, report.md 개편(별도 사이클), HTML/PDF, IDE 연동. 백로그(IaC/DAST/CI 등)는 건드리지 않는다.

## 3. 설계 원칙

1. **세 계층 분리, 셀 단위 출처 태그**. 사실(도구 출력·코드에서 직접 확인) / 설명(지식베이스, 결정적) / 추정(Claude 가 스캔 시점에 코드 문맥으로 해석). 같은 셀에 섞지 않는다. 추정 칸에는 "확인 방법" 이 반드시 따라붙는다.
2. **수치·판정·담당·우선순위는 규칙 파생**. 사람도 LLM 도 손으로 쓰지 않는다(캠페인 §4.5).
3. **결정성**. 동일 입력(findings.json + bom + interpretations.json) → 동일 워크북. xlsx 의 created 고정·modified 재기록은 기존 `output/xlsx.py` 방식(M11)을 재사용.
4. **LLM 비의존 실행**. 해석 파일이 없어도 완성된 보고서가 나온다(추정 칸만 비움). CLI 는 API 키·네트워크를 요구하지 않는다. CI 게이트는 이 경로만 쓴다.
5. **자동 억제 금지 유지**. 확인 질문의 선택지에 "억제" 가 있지만 기록은 사람이 `--suppressions` 파일에 한다. 보고서·해석·결과 반환 어디도 억제 파일을 쓰지 않는다.
6. **생성은 작성 시점에, 스캔 시점이 아니라**. 룰 설명 문장은 코드(지식베이스)에 있고 검수·골든 대상이다. 미등록 룰의 설명 초안은 Claude 가 한 번 쓰고 사람이 검수해 커밋한다.
7. **의존성 최소화**. stdlib + 기존 extra `openpyxl` 만. `dependencies = []` 유지.

## 4. 아키텍처

```
findings.json ──┐
bom.cdx.json ───┼─▶ derive (우선순위·담당·근거·그룹·의존경로)  ─▶ report-request.json  ─▶ [Claude 레이어, 세션 밖]
kb (rules/cwe) ─┘             │                                                            │
                              ▼                                                            ▼
                     workbook builder ◀──────────────────── interpretations.json (검증기 통과분만)
                              │
                              ▼
                     report.xlsx (5 시트)  ←  결과 반환(LLM 작성) ─▶ result checker (재스캔 findings.json 대조)
```

- `secscan scan --out D` 는 기존 산출물에 더해 `D/report.xlsx`(추정 칸 빈 상태) 와 `D/report-request.json` 을 낸다. exit code 는 바뀌지 않는다(보고서는 게이트에 영향 없음).
- `secscan report --findings D/findings.json [--bom B] [--interpretations I] --out D` 는 워크북만 다시 만든다. Claude 가 해석 파일을 쓴 뒤 이 커맨드로 최종본을 만든다.
- `secscan report --check-result R --rescan D2/findings.json` 은 LLM 이 돌려준 결과의 fixed 주장을 재스캔으로 대조한다.

**모듈** (`secscan/report/` 신설, 코어 무변경)

| 파일 | 책임 |
|---|---|
| `kb.py` | 지식베이스 로드. `rules.json` 덮어쓰기 > 룰 메타·CWE 표 합성 폴백. `entry_for(finding) -> KbEntry` |
| `kb/rules.json`, `kb/cwe.json`, `kb/bom_props.json` | 손으로 쓴 룰 설명 / CWE 한글명·한 줄 위험 설명 / Spring Boot BOM 관리 패키지 → gradle 속성명 |
| `derive.py` | 우선순위·담당·판정 근거·조치 그룹·완료 확인 문장. 순수 함수, 표 기반 |
| `deppath.py` | CycloneDX `dependencies` 그래프로 직접/전이 + 상위 체인 |
| `interpret.py` | request 생성, response 검증(스키마·id·인용·금칙 표현), 병합 |
| `workbook.py` | 5 시트 구성. 셀 정제·저장은 `output/xlsx.py` 의 `sanitize_cell`·`write_xlsx`·`split_sheet` 재사용 |
| `result_check.py` | 결과 반환 ↔ 재스캔 대조 |
| `cli.py`(기존) | `report` 서브커맨드 추가, `scan` 끝에 report 호출 |

## 5. 컴포넌트 상세

### 5.1 지식베이스 (`kb.py`)

**KbEntry** (frozen dataclass)

| 필드 | 뜻 | 예 |
|---|---|---|
| `name` | 일반어 문제 이름 | 검사 없이 HTML 을 화면에 삽입 (XSS 가능성) |
| `what` | 무엇이 문제인가 | React 의 dangerouslySetInnerHTML 로 HTML 문자열을 그대로 그림 |
| `why` | 왜 위험한가 | 외부 입력이 섞이면 공격자가 스크립트를 심어 다른 사용자 브라우저에서 실행(XSS) |
| `how` | 해야 할 일 | 외부 입력이면 DOMPurify 로 정화 뒤 삽입. 고정 문자열이면 위험 없음 |
| `action` | 조치 유형 enum | `sanitize-html` |
| `ctx` | 코드 문맥 확인이 필요한가 | `true` |
| `confirm` | 사람에게 던질 질문 (`ctx` 일 때 필수) | 삽입되는 HTML 의 출처는 무엇이고 정화를 거치는가? |
| `done` | 완료 확인 문장 템플릿 | 재스캔 findings.json 에 이 ID 부재(정화 래핑) 또는 사람 확인 후 억제 |
| `source` | `rules.json` / `composed` | 보고서 Meta 집계용 |

**action enum** (닫힌 집합): `upgrade` · `externalize-secret` · `sanitize-html` · `replace-api` · `config-change` · `code-fix` · `confirm-only`. 검증기가 이 밖의 값을 거부한다.

**우선순위**: `rules.json[rule_id]` > 합성 폴백. 합성 규칙:

| 카테고리 | name | what | why | how | action | ctx |
|---|---|---|---|---|---|---|
| sast | `cwe.json[cwe[0]].name` (없으면 rule_id 끝 토큰) | `finding.title`(semgrep message, 200자) | `cwe.json[cwe[0]].why` | `finding.references` 나열 + `cwe.json[cwe[0]].fix` | `code-fix` | **true** (모르면 보수적으로 사람 확인) |
| sca | `<artifact> 알려진 취약점 <CVE>` | advisory title | 고정 문장("공개된 취약점… 도달성 evidence 유무" 포함) | `<package> 를 <target> 이상으로` + `bom_props.json` 매칭 시 gradle 속성 힌트 | `upgrade` | false |
| secret | gitleaks rule 별 `rules.json`, 없으면 "노출된 비밀값 형태 문자열" | 고정 | 고정 | 실제값이면 폐기·교체, 예시값이면 자리표시자 + `gitleaks:allow` | `externalize-secret` | true |

CWE 가 비어 있으면 `why` 는 고정 문장 `도구가 CWE 를 주지 않아 위험 설명이 없음(지식베이스 등록 필요)`, `references` 가 비어 있으면 `how` 에서 생략한다.

`target` 버전 = `fixed_versions` 중 설치 버전과 major 가 같은 최소값, 없으면 전체 최소값. 정렬은 숫자 튜플, 파싱 불가 문자열은 뒤로.

**등록 의무**: `secscan/rules/*.yml` 4종과 지금까지 픽스처·실스캔에서 발화한 semgrep/gitleaks 룰은 `rules.json` 에 손으로 등록한다. 미등록 룰이 발화하면 보고서 Meta 에 `kb.composed_rules` 목록을 남기고, Claude 가 `rules.json` 항목 초안을 써서 사람 검수 뒤 커밋한다(스캔 시점 생성 아님).

### 5.2 파생 규칙 (`derive.py`)

| 파생값 | 규칙 |
|---|---|
| 우선순위 | P1 = actionable & severity ∈ {critical, high} / P2 = actionable & 그 외 / P3 = review / P4 = demoted / P5 = suppressed |
| 담당 | actionable & `ctx=false` → `자동 수정(LLM)` / actionable & `ctx=true` → `사람 확인 후` / review → `사람 확인 후` / demoted & action=upgrade → `자동 수정 가능(LLM, 비차단)` / demoted 그 외 → `조치 불필요(모니터링)` / suppressed → `억제됨(사유·만료 표기)` |
| 판정 근거 | sast: `SAST · 룰 신뢰도 {confidence} → tier {tier} → {판정}` / sca: `SCA · 도달성 {status}({source}, evidence {있음/없음}) → {판정}` / secret: `Secret · 억제 {없음/있음} → {판정}` / 억제 있으면 앞에 `억제({basis}, 만료 {expiry}) →` |
| 같이 해결(그룹) | sca: 같은 `component.package` + 같은 target 버전 → `G-<n>`; sast/secret: 같은 파일 + 같은 rule_id → `G-<n>`; 단독이면 빈 칸. 그룹 대표 행에 `(대표)`, 나머지 행 완료 확인 문장 뒤에 `— G-n 대표와 함께 해소` |
| 완료 확인 | KbEntry.done 에 `{id}`, `{package}`, `{target}` 치환 |
| 위치 | sast/secret `상대경로:줄`, sca `package@version`. 경로는 `--target` 기준 상대경로로 통일(현재 CLI 절대경로 관측을 여기서 해소) |
| 결론 문단 | 템플릿 + 숫자 치환만. 문장은 골든 대상 |

`derive.py` 는 `Finding` 과 `KbEntry` 만 받는 순수 함수이며 disposition 은 읽기만 한다(`secscan/disposition.py` 무변경).

### 5.3 의존 경로 (`deppath.py`)

- 입력: `bom.cdx.json`(cdxgen). `metadata.component.bom-ref` 를 루트로 `dependencies[].dependsOn` 그래프에서 BFS 최단 경로.
- 출력 문자열: 직접 의존 → `직접` / 전이 → `전이 ← A ← B`(루트 제외, 최대 4단, 넘으면 `…`) / BOM 없음 또는 미발견 → `BOM 없음` / `BOM 에 없음`.
- 매칭 키: `purl` 의 `pkg:maven/<group>/<artifact>@<version>` ↔ `component.package`(`group:artifact`) + version. 버전 불일치는 `전이(버전 상이: x.y.z)`.
- `scan` 경로에서는 `sbom.bom_cache_path(target)` 를 자동으로 쓴다(evidence.py I3 와 같은 위치).

### 5.4 해석 계층 인터페이스 (`interpret.py`)

**request** (`report-request.json`, CLI 가 생성)

```json
{"@context": "secscan-report-request/v1", "target": "<repo>", "findings": "<findings.json 경로>",
 "items": [{"id": "b0b763f0de63", "where": "backend/.../BreakGlassFile.java:88", "rule_id": "…",
            "question": "해당 줄의 문자열이 실제 비밀번호/키인가, 아니면 필드 이름인가?",
            "facts": ["룰 secscan.rules.hardcoded-credential", "SAST · 룰 신뢰도 high → tier actionable → 조치대상"]}]}
```
`items` 는 담당이 `사람 확인 후` 인 항목 + 강등 SCA(도달성 evidence 없음인 것) 이다. 코드 스니펫은 넣지 않는다(Claude 가 저장소를 직접 읽는다. 비밀값이 파일에 실릴 위험 차단).

**response** (`interpretations.json`, Claude 가 작성)

```json
{"@context": "secscan-interpretations/v1", "written_at": "2026-09-07", "items": {
  "b0b763f0de63": {"guess": "상수 PASSWORD 가 EMP(\"emp\") 와 함께 KNOWN_KEYS 집합에 들어감. 요청 필드 이름 목록으로 보여 리터럴 값이 키 이름이면 오탐.",
                    "check": "88행 리터럴 값 확인. 키 이름이면 억제(사유: 필드명 상수, 증거: 87-89행). 실제 비밀값이면 외부화.",
                    "cites": ["backend/src/main/java/com/worknote/admin/BreakGlassFile.java:87-89"]}}}
```

**검증기** (실패 항목은 추정 칸을 비우고 Meta 에 `interpret.rejected` 로 id·사유 기록. 보고서 생성은 계속된다)

| 규칙 | 거부 사유 |
|---|---|
| id 가 request items 에 있어야 함 | `unknown_id` |
| `guess`·`check` 비어 있지 않음, 각 600자 이하 | `empty` / `too_long` |
| `cites` 1개 이상, `경로:줄` 또는 `경로:줄-줄` 형식, 경로는 target 안 상대경로 | `no_cite` / `bad_cite` |
| 금칙 표현: `오탐 확정`, `안전함`, `문제 없음`, `억제함`, `수정 완료` (판정·행위를 단정하는 말) | `verdict_word` |
| 숫자·건수 기재 금지(`\d+건`) | `count_in_guess` |

응답이 없으면 추정·확인 방법 칸은 비고 Meta 에 `interpret.status = absent`.

### 5.5 워크북 시트 (`workbook.py`)

셀 채우기 색: 측정(회색 `F3F3F3`) · 추정(노랑 `FFF7E0`) · 규칙/설명(무색). 모든 셀은 문자열 타입 강제(기존 `sanitize_cell`). 시크릿 finding 은 어떤 시트에도 매치된 값을 싣지 않는다(위치만).

**0_요약**

| 행 | 내용 | 출처 |
|---|---|---|
| 제목·대상·프로파일·스캐너 상태(도구 status·소요) | meta | 측정 |
| 결론 | 템플릿: `총 N건. 즉시 조치 대상 A건(자동 수정 a, 사람 확인 후 h). 검토 후보 R건. 도달 불가 강등 D건(업그레이드 가능 u). 스캐너 S종 정상 / 실패 F종. 제외 E건.` | 규칙 |
| 구분표 4행: 즉시 조치 / 검토 후보 / 강등 / 제외 — 건수·뜻 | 규칙 |
| 시트 안내 4행 | 고정 |
| 지식베이스 미등록 룰, 해석 상태 | Meta 요약 |

**1_조치목록** (17열, 우선순위 → 심각도 → 위치 정렬, 틀고정 D2)

`No. · 우선순위 · ID · 문제 · 위치 · 의존 경로 · 무엇이 문제인가 · 왜 위험한가 · 해야 할 일 · 조치 유형 · 담당 · 같이 해결 · 판정 근거 · 심각도 · CWE · 기준(KISA/PCI) · 완료 확인 방법`

**2_확인질문** (담당 = `사람 확인 후` + 강등 SCA 중 evidence 없음)

`No. · ID · 위치 · 질문 · 사실(측정) · 추정(Claude 해석) · 확인 방법 · 인용 · 선택지`
선택지 고정 문구: `① 수정(해야 할 일대로) ② 억제(사유·증거·만료를 --suppressions 파일에 기록) ③ 스캔 제외(비배포 경로, --exclude)`.

**3_판정기준** (고정 표, 골든): 판정 규칙 · 우선순위 규칙 · 담당 규칙 · 심각도 뜻 · 도달성 주의 · 사실/추정 구분 · 자동 억제 없음 · 조치 유형 enum 뜻.

**4_결과반환**

상단 4행(허용 범위 / 금지 / 완료 판정(재스캔 명령 포함) / status 값) + 템플릿 표
`ID · status · changed_files · verification · question_or_reason · commit` (ID 미리 채움).

### 5.6 CLI

```
secscan report --findings F [--bom B] [--interpretations I] [--target T] --out D
secscan report --check-result R --rescan F2 [--out D]
```
- `scan --out D` 끝에 내부적으로 `report` 를 호출해 `report.xlsx` + `report-request.json` 을 쓴다. 기존 `findings.xlsx`(증거 워크북)는 그대로 둔다.
- `--check-result`: `R` 은 4_결과반환 시트를 저장한 xlsx 또는 같은 열의 JSON. 출력 표: `ID · 주장(status) · 재스캔 존재 여부 · 판정(일치/불일치/미검증)`. 불일치가 있으면 exit 2, 없으면 0. 이 검증기는 LLM 의 fixed 주장을 사람이 믿기 전에 기계로 대조하는 마지막 고리다.

## 6. 데이터 모델

- `KbEntry`, `Derived(priority, owner, basis, group, done, where, deppath)`, `Interpretation(guess, check, cites)`, `ResultRow(id, status, changed_files, verification, reason, commit)` 모두 frozen dataclass, `secscan/report/models.py`.
- 파일 스키마 3종(`report-request/v1`, `interpretations/v1`, `report-result/v1`)은 `@context` 로 버전 고정. 필드 추가는 v1 안에서 하위호환, 의미 변경은 v2.
- `Finding` 모델·`json_io`·`disposition` 은 변경하지 않는다.

## 7. 안전장치

| 위험 | 대응 |
|---|---|
| 워크북에 비밀값 노출 | secret 카테고리는 위치만. request 에 스니펫 없음. 기존 `redact_gitleaks` 는 raw 에만 해당하므로 workbook 은 `location` 외 secret 필드를 읽지 않는 것으로 테스트 고정 |
| 추정이 판정으로 미끄러짐 | 검증기 금칙 표현 + 별도 칸 + 색 + "확인 방법" 필수 |
| 수치 손기입 | 결론·건수는 템플릿 치환만. 골든 테스트 |
| 지식베이스 오류 | `rules.json` 은 PR 검수 대상. 골든이 문장을 고정 |
| 해석 파일 위조·오염 | 검증기 통과분만 병합, 거부는 Meta 에 기록 |
| LLM 의 fixed 허위 주장 | `--check-result` 재스캔 대조 |
| 억제 자동화 | 어떤 코드 경로도 suppressions 파일을 쓰지 않는다(테스트로 고정) |

## 8. 테스트·검증

- **단위**: `derive` 규칙표 전수(파라미터화), `kb` 폴백·덮어쓰기·enum 검증, `deppath` 픽스처 BOM(직접/전이 3단/버전 상이/없음), `interpret` 검증기 거부 사유 전수, `result_check` 일치/불일치/미검증.
- **골든**: `fixtures/report/work-note-findings.json`(2026-09-06 실스캔 15건, 경로 상대화·비밀값 없음) → 5 시트 행 골든 + `interpretations` 예시 병합 골든.
- **결정성**: 같은 입력 두 번 빌드 → 바이트 동일(기존 xlsx 테스트 방식).
- **불변식**: secret 값 미노출, suppressions 미기록, exit code 불변(scan 의 게이트 결과가 report 유무와 무관).
- **수용 실험(수동, 측정 문서 기록)**: 시트 덤프만 받은 mid-tier 서브에이전트 dry-run → 기대 status 분포와 대조. 2026-09-06 결과(11/4/0, 금지 0)를 기준선으로 `docs/measurements/` 에 기록하고, 5.3·5.2 그룹 열 추가 후 재실험에서 "판단 어려웠던 점" 5→3 이하를 목표로 한다.

## 9. 마일스톤·게이트

| 단계 | 산출물 | 게이트 |
|---|---|---|
| R1 | `kb`·`derive`·`workbook`·`report` 커맨드(해석 없이) | 골든 5 시트, 결정성, 비밀값 미노출, work-note 재생성이 프로토타입 A 와 열 동일 |
| R2 | `deppath`·그룹 열·상대경로 통일 | 픽스처 BOM 테스트, work-note 에서 tomcat 3건 G-1, log4j `전이 ← spring-boot-starter-logging ←…` 관측 기록 |
| R3 | `interpret` request/response/검증기, `scan` 통합 | 거부 사유 전수 테스트, 해석 없는 CI 실행 exit 불변 |
| R4 | `--check-result` + 수용 실험 재실행 | 측정 문서(사실만, 마커 인용) |

## 10. 백로그

report.md 를 같은 지식베이스로 개편 · Semgrep 레지스트리 룰 설명 대량 등록 자동화(작성 시점 생성 도구) · HTML 단일 파일 보고서 · 결과 반환을 PR 본문으로 변환.

## 11. 열린 질문

- `bom_props.json`(Spring Boot 관리 의존성 → gradle 속성명) 의 유지 범위: 상위 20개 패키지로 시작, 미매칭은 힌트 없이 "버전 지정" 으로 폴백.
- 강등 SCA 를 `자동 수정 가능(비차단)` 으로 LLM 에 허용하는 기본값이 맞는지(현재 안: 허용, 결과 반환에서 skipped 사유 허용).

## 12. 정오표(구현 중 확정)

(a) "Meta" 기록은 별도 시트가 아니라 `0_요약` 하단 행("지식베이스 미등록 룰"·"해석 상태")으로
    구현한다.
(b) `4_결과반환` 상단 4행은 `#` 접두 지시 행(허용 범위·금지·완료 판정·status 값)이며, 별도
    안내 시트가 아니다.
(c) §3 "등록 의무"("`secscan/rules/*.yml` 4종과 지금까지 픽스처·실스캔에서 발화한
    semgrep/gitleaks 룰")를 실측 수치로 확정한다: 커스텀 룰 4종 + work-note 픽스처 발화
    6종(그중 1종은 하드코딩 자격증명 커스텀 룰과 겹침) = `rules.json` 등록 10건(실측:
    `secscan/report/kb/rules.json` 키 10개). 그 외 발화 룰은 `0_요약` 의 미등록 목록으로
    관측해 등록 대기로 남긴다(§10 백로그).
(d) 강등 SCA 중 evidence(도달성 근거) 가 없는 항목도 확인 질문 대상이다 — "도달 불가"가
    안전 보증이 아니라는 §3 원칙에 따라, 근거가 약한 강등일수록 사람 확인이 더 필요하다.
(e) §5.5 의 셀 채우기 색·틀고정 D2 는 구현하지 않았다 — 시트 원시형(Sheet=값만)과
    output/xlsx.py 무변경 제약 때문. 사실/추정 구분은 열 분리로만 한다.
(f) 보고서·request·결과반환의 finding ID 는 --target 상대화 공간 기준이다. --check-result 는
    재스캔 findings.json 을 같은 target 으로 상대화한 뒤 대조한다(meta.target 기본, --target
    우선).
- (g) 2026-09-07 가독성 개선: `3_판정기준` 은 4열(구분·값·용어·뜻·그래서 어떻게 하나) 일반어 표로, `4_결과반환` 은 한국어 열 이름 + 참고 열 3개(문제·담당·위치, 검증기는 무시)의 순수 표이고, 안내 6행은 xlsx 에서 표 **위** 블록(B~끝 병합)으로, CSV 폴백에서는 `4_결과반환-안내.csv` 로 따로 놓는다(검증기는 첫 열이 12-hex ID 가 아닌 행을 건너뜀). 열 너비는 내용 길이로 자동 계산(한글 2칸, 8~60). 워크북에 열 너비·줄바꿈·굵은 헤더·틀고정 서식을 넣되 modified 는 created 로 재고정(결정성 유지).
