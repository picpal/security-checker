# 커스텀 룰셋(D) — 설계 (2026-06-28)

> 수정 대상은 **security-checker(secscan) 프로젝트뿐**이다. message-gate 는 read-only
> 정답지로만 참조하며 코드를 복사/이식하지 않는다(취약 *패턴*을 최소 재현한 픽스처를
> 직접 작성).

## 1. 배경·목표
갭 지도(`docs/measurements/2026-06-28-gap-map.md`)가 coderay 격차의 정체를 규명했다:
secscan 이 못 잡는 취약점 중 **저FP·고가치 3종**은 OSS 도구의 룰 부재 때문이며 커스텀
룰로 메울 수 있다. 본 설계는 그 3종을 semgrep 커스텀 룰로 구현하고, 취약 커밋을 정답지로
한 회귀 게이트를 세운다.

대상 3종:
1. **MyBatis `${}` SQL injection** (CWE-89) — semgrep 기본 팩 미탐(XML mapper)
2. **Java 코드 내 하드코딩 자격증명** (CWE-798/259) — gitleaks 저엔트로피 미탐
3. **zero/고정 salt** (CWE-760) — secret·SAST 패턴 부재

## 2. 비목표 (갭 지도가 명시적으로 제외)
- **broad-catch·null 가드·리소스(CWE-476/754/404)**: IDE 인스펙션(coderay) 고유 영역.
  semgrep 패턴으로는 *의도적 swallow 가 정당한* 케이스와 구분 불가 → FP 폭발. 룰화 안 함.
- **cross-file/함수간 taint (C)**: PoC 로 불필요 확정. 본 설계 범위 아님.
- 커스텀 룰은 **패턴 매칭**이다. 데이터플로우(입력이 실제 미검증인지)는 판정하지 않으며,
  그 한계를 tier(식별자 위치=review)와 보고서로 표현한다(원칙2: 결정적/LLM 경계).

## 3. 통합 (원칙6: 어댑터 1개 영향, 코어 무변경)
- **룰 위치**: `secscan/rules/` (패키지 동봉, 버전관리)
- **로드**: `SemgrepAdapter.build_argv` 에 `--config <rules_dir>` 추가. 기본 팩(p/java 등)과
  **항상 함께 로드** → semgrep 이 도는 모든 프로파일(standard/deep)에 자동 적용. (quick 은
  semgrep 미포함이라 미적용 — 의도된 동작)
- **경로 해석**: `rules_dir` 는 `Path(__file__)` 기준 `secscan/rules/` 절대경로. 설치 위치
  무관.
- **정규화**: `normalize/semgrep.py` 무변경. 룰 `metadata.cwe/confidence/owasp` 자동 추출.
- **컴플라이언스**: `compliance.py` 무변경. CWE-89/259/760/798 기매핑 → KISA/PCI 자동.

## 4. 룰 명세

공통: 각 룰 YAML 에 `metadata: {cwe: [...], confidence: HIGH|LOW, owasp: [...]}`,
`severity: ERROR|WARNING`, `message`(한글, 조치 안내) 명시. confidence 는 normalize 가
소문자화하므로 대문자로 적어도 무방.

### 4.1 `mybatis-sqli-value` (actionable)
- languages: [generic], paths.include: `*.xml`
- 패턴: SQL 비교/LIKE 의 **값 위치** `${...}` — `= '${...}'`, `LIKE '${...}'`,
  `IN (${...})` 등. 값 위치는 `#{}` 바인딩이 가능하므로 `${}` 사용은 거의 항상 취약.
- severity: ERROR, confidence: HIGH → `sast_tier`=actionable
- cwe: [CWE-89], owasp: [A03:2021]

### 4.2 `mybatis-sqli-identifier` (review)
- languages: [generic], paths.include: `*.xml`
- 패턴: **식별자 위치** `${...}` — `FROM ..._${...}`, `ORDER BY ${...}`, `TABLE ${...}`.
  `#{}` 바인딩이 불가한 테이블/컬럼명 → `${}` 불가피할 수 있음. 검증 관문 존재는 사람 확인.
- severity: WARNING, confidence: LOW → `sast_tier`=review
- message: "식별자 치환 ${} — 입력 화이트리스트 검증 관문 존재를 확인하라(#305 패턴)"
- cwe: [CWE-89]

### 4.3 `hardcoded-credential` (actionable / test→review)
- languages: [java]
- 패턴: 자격증명 변수/상수에 **문자열 리터럴 할당** — 변수명이
  `(?i)(password|passwd|pwd|secret|apikey|api_key|token|credential)` 류 + 우변이
  비어있지 않은 문자열 리터럴. `@Value`/환경변수/`System.getenv`/`#{}` 주입은 제외.
- severity: ERROR, confidence: HIGH
- cwe: [CWE-798, CWE-259]
- 보완 관계: gitleaks 와 상보(yml/key/고엔트로피=gitleaks, Java 저엔트로피=커스텀). 실제
  중복은 드물며, 발생 시 merge dedup 에 맡긴다.

### 4.4 `zero-salt` (actionable / test→review)
- languages: [java]
- 패턴: salt 로 쓰이는 값이 **고정/예측가능** — 리터럴 `"...".getBytes()` 를 salt 로,
  `new byte[N]`(zero-init) 을 salt 인자로, 또는 상수 SALT 필드.
- severity: ERROR, confidence: HIGH
- cwe: [CWE-760]

## 5. tier 분기 (결정적)
두 축, 둘 다 기존 `sast_tier()` 경유:
1. **위치(value/식별자)**: 룰 confidence 로 인코딩(HIGH/LOW). 기존 sast_tier 로직
   (conf∈{high,medium}∧sev∈{critical,high,medium}→actionable, else review) 그대로. **코드
   변경 없음.**
2. **test/loadtest 경로**: `sast_tier(f)` 에 규칙 추가 — `f.location.file` 이 test 경로
   패턴(`/test/`, `/androidTest/`, `loadtest`, `*Test.java`, `*Tests.java`, `*IT.java`)
   이면 결과를 review 로 강등. **모든 SAST 에 일반 적용**(커스텀 한정 아님, 일관·단순).
   - 순수 헬퍼 `is_test_path(path) -> bool` 신설(단위 테스트 대상).
   - 기존 222 테스트 영향은 TDD 로 확인(현 픽스처에 test 경로 finding 이 없으면 무영향).

## 6. 회귀 게이트 (외부 repo 비의존)
`fixtures/custom-rule-app/` 신규. message-gate 코드를 **복사하지 않고** 취약 패턴만 최소
재현(직접 작성):
- `mapper/Sample.xml`: value 위치 `${}`(양성) + 식별자 위치 `${}`(양성·review) +
  `#{}` 바인딩(음성)
- `Creds.java`: 하드코딩 자격증명(main 양성) + 환경변수/`@Value` 주입(음성)
- `test/CredsTest.java`: 하드코딩(test → review 강등 확인)
- `Hashing.java`: zero/고정 salt(양성) + `SecureRandom` 계정별 salt(음성)

골든 테스트(`tests/test_custom_rules.py`):
- 각 룰이 **양성 픽스처에서 의도한 finding + 정확한 tier** 산출
- **음성 픽스처에서 0건**(FP 게이트 — 원칙1)
- TDD: Red(룰 없음→실패) → Green(룰 추가→통과)

## 7. 부분실패 (원칙5)
룰 YAML 문법 오류 시 semgrep 이 해당 스캔을 실패할 수 있다. 룰 문법은 **골든 테스트로
사전 검증**(CI 게이트)하며, 런타임 실패는 semgrep 어댑터의 기존 격리로 다른 스캐너 결과를
보존한다. (doctor 에 룰 로드 스모크 추가는 선택.)

## 8. 완료 기준 (게이트)
- [ ] 4개 룰 YAML + `--config` 통합, semgrep 정상 로드(스모크)
- [ ] 양성 픽스처: 4종 전부 탐지 + tier 정확(value=actionable / 식별자=review / test=review)
- [ ] 음성 픽스처: `#{}`·주입·`SecureRandom` 0건 (FP 0)
- [ ] `is_test_path` 단위 테스트 + `sast_tier` test 강등 테스트
- [ ] 기존 222 테스트 green 유지
- [ ] compliance 자동 매핑 확인(예: CWE-89 → KISA/PCI)
- [ ] 취약 커밋 대조: #305(식별자 review)·CWE-259(하드코딩)·CWE-760(salt) 패턴이 픽스처에서
      재현·탐지됨
