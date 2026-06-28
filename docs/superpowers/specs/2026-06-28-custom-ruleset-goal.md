# 구현 Goal — 커스텀 룰셋 (D)

> 실행: **Claude Code 세션.** 기존 secscan 코드베이스(M0~M5 + post-M5 + B 완료, 222 tests)
> 에 이어서 작업한다. 신규 스캐너가 아니라 **기존 Semgrep 경로에 로컬 룰을 더하는** 강화다.
> 수정 대상은 **security-checker 프로젝트뿐** — message-gate 는 read-only 정답지로만 보고,
> 코드를 복사/이식하지 않는다(취약 *패턴*을 최소 재현한 픽스처를 직접 작성).

---

## 목표

갭 지도가 확정한 저FP·고가치 3종(MyBatis `${}` SQLi / Java 하드코딩 자격증명 / zero-salt)을
**semgrep 커스텀 룰**로 메운다. 신규 어댑터 없이 `secscan/rules/` 를 더하고, 늘어나는 신호를
**위치·경로 기반 tier 분기**로 계층화해 FP 를 통제한다. 룰의 CWE 는 이미 구축된 컴플라이언스
매핑으로 KISA/PCI 에 자동 연결된다.

## 필독 (시작 전 + 매 단계 시작 시)

이 설계 스펙이 **최우선 기준**이다(이 goal 과 충돌하면 스펙을 따른다):
```
docs/superpowers/specs/2026-06-28-custom-ruleset-design.md        ← D 설계 (최우선)
docs/measurements/2026-06-28-gap-map.md                           ← 근거(격차 정체·정답지)
docs/superpowers/specs/2026-06-26-jvm-security-scanner-design.md  ← 전체 설계(§10.2 SAST)
CLAUDE.md · PROGRESS.md                                            ← 현 상태/원칙
```

## 세션 운영 (이미 셋업됨 — 갱신 모드)

`CLAUDE.md`·`PROGRESS.md` 는 이미 존재한다. 새로 만들지 말고 **갱신**한다.
- 단계 완료마다 `PROGRESS.md` 체크 + 작은 단위 커밋(메시지 마지막 줄 `다음: <할 일>`).
- context 60% 근접 시 `PROGRESS.md` 최신화 → 커밋 → compact.
- 복귀 시: `CLAUDE.md` → 이 goal → D 설계 스펙 → `PROGRESS.md` → `git log --oneline`.
- 실제 semgrep 실행(룰 검증)은 `Bash dangerouslyDisableSandbox=true`.

## 핵심 원칙 (위반 금지)

1. **정확도 우선** — 룰을 더하되 FP 는 **계층 분리**. value 위치만 actionable, 식별자
   위치·test 경로는 review 로 강등. **음성 픽스처 0건**이 게이트.
2. **결정적/LLM 경계** — 룰은 **패턴 매칭**(결정적)이다. 입력이 실제 미검증인지(데이터
   플로우)는 판정하지 않으며, 그 한계를 tier·메시지로 표현한다. LLM 은 탐지하지 않는다.
3. **typed model canonical** — tier 는 `Finding`+룰 metadata 에서 파생. 한글 severity·계층
   섹션은 출력 레이어에서만. SARIF level 영문.
4. **부분 실패는 정상** — 룰 문법 오류·semgrep 런타임 실패를 숨기지 않는다(기존 격리 보존).
5. **어댑터 1개 영향, 코어 무변경**(원칙6) — `normalize/semgrep.py`·`compliance.py`·
   `merge.py` 는 손대지 않는다(metadata 자동 추출·자동 매핑에 맡긴다).

---

## 단계 (순차 — TDD, 각 게이트 통과 후 다음)

TDD: **테스트 먼저(RED) → 최소 구현(GREEN) → 리팩터**. 단위 게이트는 **커밋된 골든/픽스처**로.
라이브 semgrep 실행은 통합 스모크로 별도 확인(flaky 하므로 단위 게이트로 쓰지 않되, 룰 문법은
픽스처 골든으로 사전 검증).

### D1 — tier 인프라 (룰보다 먼저, 기반)
- `models.py`: 순수 헬퍼 `is_test_path(path) -> bool` (`/test/`, `/androidTest/`,
  `loadtest`, `*Test.java`, `*Tests.java`, `*IT.java`).
- `models.py`: `sast_tier(f)` 에 규칙 추가 — `f.location.file` 이 test 경로면 review 로
  강등. **모든 SAST 일반 적용**(커스텀 한정 아님).
- **게이트**: `is_test_path` 경로 패턴 단위 + `sast_tier` test→review 단위(high+main→
  actionable, high+test→review) + **기존 222 tests green 유지**.

### D2 — 룰 로드 통합 + MyBatis 2룰 (위치 분기)
- `secscan/rules/` 디렉토리 신설. `adapters/semgrep.py build_argv` 에 `--config <rules_dir>`
  추가(`Path(__file__)` 기준 절대경로, 기본 팩과 함께 항상 로드).
- 룰: `mybatis-sqli-value.yml`(generic/`*.xml`, value 위치 `= '${}'`·`LIKE '${}'`,
  severity ERROR, confidence HIGH, cwe [CWE-89]) +
  `mybatis-sqli-identifier.yml`(식별자 위치 `FROM ..._${}`·`ORDER BY ${}`, WARNING,
  confidence LOW, cwe [CWE-89]).
- 픽스처: `fixtures/custom-rule-app/mapper/Sample.xml` — value 양성 + 식별자 양성 +
  `#{}` 바인딩 음성.
- **게이트**: value → actionable, 식별자 → review, `#{}` → **0건**. 룰 로드 스모크(semgrep
  이 로컬 룰을 읽음).

### D3 — hardcoded-credential + zero-salt (경로 분기)
- 룰: `hardcoded-credential.yml`(java, 자격증명 변수명 + 리터럴 할당, `@Value`/env/`#{}`
  주입 제외, cwe [CWE-798, CWE-259]) + `zero-salt.yml`(java, 고정/zero salt, cwe [CWE-760]).
- 픽스처: `Creds.java`(main 양성 + 주입 음성), `test/CredsTest.java`(test → review),
  `Hashing.java`(고정 salt 양성 + `SecureRandom` 음성).
- **게이트**: 4종 탐지 + tier 정확(main actionable / test review / 식별자 review) +
  음성(`#{}`·주입·`SecureRandom`) **0건**.

### D4 — 통합 검증·실증·문서
- 전체 테스트 green. `compliance` 자동 매핑 확인(CWE-89/259/760/798 → KISA/PCI).
- **취약 커밋 대조**(scratchpad, read-only): #305(식별자→review)·CWE-259(하드코딩)·
  CWE-760(salt) 패턴이 픽스처에서 재현·탐지됨을 확인. message-gate 무수정.
- `CLAUDE.md`(아키텍처에 커스텀 룰 한 줄)·`PROGRESS.md`(D 완료) 갱신.
- **게이트**: 전체 green + tier/FP 게이트 + compliance 매핑 + 부분실패 정직 보고.

---

## 하지 말 것

- **비목표(갭 지도 제외)**: broad-catch·null 가드·리소스(CWE-476/754/404 = IDE 인스펙션
  영역) 룰화, cross-file/함수간 taint(C), 도달성의 SAST 적용 — 전부 별도 spec.
- **식별자 위치·test 경로·unknown 을 actionable 로 승격**(원칙1 위반 — review 유지).
- `normalize/semgrep.py`·`compliance.py`·`merge.py` **재설계**(metadata/자동매핑에 맡김).
- message-gate **코드 복사/이식**(패턴 최소 재현만). 내부 severity 를 한글로 바꾸기.
- secret 팩 추가(gitleaks 중복) / Claude 자동 억제 / SARIF 를 내부 모델로 사용.

## 완료 기준

- [ ] D1~D4 각 게이트 통과(TDD, 전체 테스트 green, 단위는 커밋 골든/픽스처).
- [ ] 룰 4개 + `secscan/rules/` `--config` 통합(semgrep 로컬 룰 로드 스모크).
- [ ] tier: value=actionable / 식별자=review / test·loadtest=review. unknown 미승격.
- [ ] `is_test_path` 단위 + `sast_tier` test 강등 단위.
- [ ] **음성 픽스처 FP 0**(`#{}`·환경변수/`@Value` 주입·`SecureRandom`).
- [ ] 기존 222 tests green 유지 + `normalize`/`compliance`/`merge` 무변경.
- [ ] compliance 자동 매핑(CWE-89/259/760/798 → KISA/PCI) 확인.
- [ ] 취약 커밋 대조로 3종 패턴 재현·탐지(message-gate read-only).
- [ ] `CLAUDE.md`/`PROGRESS.md` 갱신.
