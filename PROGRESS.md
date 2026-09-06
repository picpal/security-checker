# 진행 상황

현재 마일스톤: **전체 완료 — 마무리 검증**

## 인프라 (M0보다 먼저)
- [x] CLAUDE.md 생성
- [x] PROGRESS.md 생성
- [x] Python 패키지 스캐폴딩 (pyproject, secscan/, tests/, venv)

## M0 — doctor ✅
- [x] 스캐너 설치 점검 (trivy / osv-scanner / depscan / atom)
- [x] 런타임 점검 (Java 21 / Node / 가용 메모리)
- [x] 누락 시 설치 가이드 출력
- [x] CLI `secscan doctor` 렌더링 + exit code (정상 0 / 문제 1)
- [x] **게이트 통과**: 미설치 4종 정확 탐지 + Java21/Node/메모리 인식 (22 tests green)

## M1 — 정확한 SCA (★정확도 증명)
- [x] Trivy 어댑터
- [x] osv-scanner 어댑터 (v2 `scan source`, exit1=취약점발견)
- [x] typed finding 모델 (spec §6) — secscan/models.py
- [x] 정규화 raw→typed (골든 테스트: trivy/osv 실제 출력)
- [x] 합의 dedup (Trivy ∪ osv + consensus score) — merge_consensus
- [x] 취약 픽스처 (commons-text=도달가능 / snakeyaml=도달불가) + golden 캡처
- [x] 오케스트레이터 (병렬 · status · 자원 거버넌스 · 부분실패 격리)
- [x] dep-scan 도달성 엔진 (4중 안전장치) + usage-슬라이스 provider
- [x] SARIF 2.1.0 출력 (도달성 주석, 자동억제 X)
- [x] Markdown 보고서 출력 (도달가능 우선 + 사각지대 명시)
- [x] scan CLI 커맨드 (`secscan scan --profile --target --out`)
- [x] 도달성 on/off FP 감소 + 비용 실측 리포트 (docs/measurements/2026-06-27-m1-*)
- [x] **게이트 통과**: unreachable 표기 ✓ + FP 89%↓(9→1) ✓ + ground-truth 100% ✓ + unknown 폴백 ✓ + 90 tests green

### M1 실측 결과 (게이트 증명)
- 실제 E2E: `secscan scan --target fixtures/vuln-maven-app --profile accurate-sca`
- 조치대상 9→1 (노이즈 89% 감소), 도달성 ground-truth 100% (commons-text 도달가능 / snakeyaml 도달불가)
- dep-scan ~45s(fresh), 슬라이스 캐시 재사용 시 즉시

## M2 — Secret ✅
- [x] Gitleaks 어댑터 (위치형 finding, raw 시크릿 미저장)
- [x] opt-in TruffleHog (`--verify-secrets` / `--network-off` / never-validate)
- [x] **게이트 통과**: 3건 탐지 · 검증 opt-in · network-off 차단 (E2E 3정책 확인, 116 tests)

## M3 — SAST ✅
- [x] Semgrep CE 어댑터 (p/java + p/security-audit)
- [x] taint intraprocedural 한계 보고서 명시 (markdown _SAST_NOTE, spec §10.2)
- [x] **게이트 통과**: SQL injection(CWE-89) 탐지 + typed 통합 (E2E, 125 tests). CE 한계로 인자경유 command injection 미탐지(문서화)

## M4 — 억제 ✅
- [x] 억제 엔트리 (provenance / evidence / expiry / scope 필수 검증)
- [x] baseline (기존 이슈 일괄 억제, 신규만 알림)
- [x] 영속화 JSON(OpenVEX 영감) + propose(제안만, 자동 억제 없음)
- [x] stale 무효화 (만료 / 의존성 버전(dedup_key) / 도달성 unreachable→reachable)
- [x] SARIF suppressions emit(사람 확정만) + markdown 억제 섹션 + cli 플래그
- [x] **게이트 통과**: 재발 억제 + 버전/도달성 변경 무효화 + 제안만 (146 tests)

## M5 — deep (experimental) ✅
- [x] SpotBugs + FindSecBugs 어댑터 (빌드 연동: mvn/gradle compile → 바이트코드)
- [x] 빌드 실패 partial 격리 (예외도 skipped 로 안전 처리)
- [x] **게이트 통과**: 바이트코드가 COMMAND_INJECTION(CWE-78, Semgrep CE 놓친 것)+SQL(CWE-89) 탐지 + 빌드실패 안전격리 (154 tests)

## M5+ — 실전 강화 (post-spec, 도그푸딩 + 실프로젝트 message-gate 기반)
- [x] detect: fixtures/vendor/build/VCS 제외 + root-first build_tool (자기 스캔 오탐 수정)
- [x] exclude.py: 기본 제외(build/target/.git/node_modules…) + `.gitignore` 존중
      (#1 precision — message-gate 빌드 노이즈 41건 제거)
- [x] BOM 기반 SCA: cdxgen BOM → `trivy sbom` (#2 recall — 락파일 없는 gradle SCA **0→34건**)
- [x] SARIF locations emit (도그푸딩으로 발견한 자체 버그 수정)
- [x] **컴플라이언스 매핑**: CWE→KISA49(7분류)/PCI-DSS 6.2.4 — compliance.py 순수 매핑,
      scan enrich + markdown 라벨/롤업 + SARIF properties + CLI 요약. 결정적 파생(판정 아님).
      message-gate 실증: KISA 7건·PCI 7건(역직렬화/경로조작/SSRF/인가/TOCTOU) 매핑.
- [x] **SAST 룰 확대 + 신뢰도 계층화 (B)** — spec/goal 2026-06-27. Semgrep 팩 확대
      (owasp-top-ten/cwe-top-25) + confidence 추출·정규화 + sast_tier(actionable/review,
      missing→review 원칙1) + severity 한글(심각/위험/보통/일반/미상) + exit-code 게이팅
      (review 비차단) + merge 보수적 + doctor 런타임 점검. **codex 검토(P1×4,P2×8) 전량 반영.**
      실증: message-gate SAST 0(잘 짜인 Spring→패턴 SAST 무효 = C 필요 음성증거),
      sast-app E2E(actionable·exit 1·KISA SQL삽입 코드레벨 매핑).
- [x] **커스텀 룰셋 (D)** — spec/goal 2026-06-28~29. semgrep 커스텀 룰 3종(secscan/rules/):
      MyBatis ${} value(actionable)/identifier(review) 위치분기 + 하드코딩 자격증명(CWE-798/259)
      + zero-salt(CWE-760). `--config` 통합(코어무변경) + is_test_path 경로강등(test/loadtest→
      review, 전 SAST) + 외부repo비의존 픽스처(fixtures/custom-rule-app) 회귀게이트(양성+음성 FP0).
      d4a1ded 취약시점 대조로 갭 3종 실증(gitleaks/semgrep 미탐→커스텀룰 탐지).
      logback FP는 mapper paths 한정으로 제거.

## 프로파일
- [x] quick / accurate-sca / standard / deep

## 전체 완료 기준 ✅
- [x] M0~M5 각 검증 게이트 통과 (160 tests green)
- [x] 프로파일(quick/accurate-sca/standard/deep) 동작
- [x] 취약 픽스처 E2E + 도달성 정확도/비용 실측 리포트(docs/measurements/2026-06-27-m1-*)
- [x] 정규화 골든 테스트 + 부분실패 테스트 green
- [x] 자연어 "이 프로젝트 점검해줘" → 스택 감지(maven/java) → 프로파일(standard) → typed findings → 보고서 시연
- [x] CLAUDE.md / PROGRESS.md 최종 갱신

## 상태: M0~M5 + post-M5 + **D(커스텀 룰셋)** 완료 (**234 tests green**, 2026-06-29).
**갭 지도 완성(2026-06-28)** — `docs/measurements/2026-06-28-gap-map.md`. message-gate 취약
커밋 부모를 clone→secscan→coderay 대조로 전수 검증. 결론: coderay 격차 = (1) injection/secret/
crypto 안티패턴 → **커스텀 룰(D)** (3종: MyBatis `${}`/하드코딩/zero-salt), (2) broad-catch 등
코드 스멜 → **IDE 인스펙션 고유 영역**(억지 룰화 시 FP). **C(함수간 taint) 불필요 재확정**
— spotbugs 가 빌드·실행돼도 CWE-476/754/404 미탐(범주 공백, taint 아님).
**D 완료(2026-06-29)**: coderay 격차의 커스텀룰 영역 3종 메움(d4a1ded 실증).
다음 = 백로그(IaC/DAST/CI/주기점검) 또는 IDE 인스펙션 통합(broad-catch 코드스멜 = coderay 잔여격차).

## V — 검증 캠페인 (spec 2026-09-04) — 플랜 1(V0~V3) ✅
- [x] V0 정답지 매니페스트 3종 + 대조기(match_ground_truth/classify_extras)
- [x] V1 TraceSink 단계 추적 + findings.json + tools/verify 격리 하네스 + 증거 동결(docs/verification/evidence/<date>)
- [x] V2 SCA 실측: CVE recall N/46 · known-FP 3단계 · 프로파일 계약 · 초과분 triage · 입력면 교차
- [x] V3 도달성 쌍 픽스처(reach-app, false-unreachable xfail) + GT-A differential — 정본 검증(reconcile ✓, docs/verification/results/2026-09-05/reconcile-report.md)
- [x] 최종 전브랜치 리뷰 수정 라운드(Important 8건 전부 해소): I1 attrition 부호 정정(normalize(합계)
  합성 행) · I2 미탐 전건 단계 귀속(sca.missed_by_stage.*) · I3 facts-profile.json 재생성 비교 연결 ·
  I4 known-FP 축 3 값 fact id 부여 · I5 는 spec 정오표(g)로 플랜 2 이관 · I6 raw↔typed 카디널리티
  마커화 · I7 reconcile 자기참조 순서(2단계 계산, 직전 실행 값 신뢰 금지) · I8 인용 표 대조
  (reconcile.quote_mismatch). Minor 중 M2/M5/M6/M9/M10/M11/M12 도 함께 해소. `_facts.py`(facts_text)
  로 4곳 직렬화 통일.
- 플랜 2 이관(의도적 미착수): I5 의 `tools/verify/gate.py`(판정 생성기) · M1(trivy 순회 통합) ·
  M3(축 5 원시 산출물을 evidence/ 로 이동) · M4(reconcile 증거 부재 시 degrade) · M7(`gta.row{i}` id
  위치 독립화) · M8(증거 경로 상대화) · 생성기 인터페이스(`render_doc`+`collect_facts`) 6종 통일 ·
  evidence/README.md 생성기화. 최종 재리뷰 잔여(Low 6, 검사 약화·값 변동 없음): N1 인용 선언 regex 20자 창 ·
  N2 missed_stage 가 alias 미비교(dedup_key 에 alias 없음) · N3 attrition 행 순서가 trace 순서 아닌 partition ·
  N4 reconcile-report 인용표 대조 표 헤더 `|` 렌더 · N5 실패 실행 시 marker_mismatch 기록값이 비교값보다 클 수 있음 ·
  N6 facts-profile regen 이 deep meta 부재 시 무기록 스킵(M4 계열).
- [x] V4~V7 → 플랜 2 (판정 단계 H · 모델 확장 · xlsx · 변이 픽스처 · 최종 문서) ✅ 2026-09-06
  - V4 모델·판정 단계 H: `Occurrence`·`Cvss`·`ScannerStatus`, `Advisory.cvss/published`,
    `Finding.occurrences/disposition/tier` + lossless 직렬화 · trivy 정규화가 CVSS 전 소스·
    PublishedDate·Occurrence 보존 · `decide`(억제 우선→tier→도달성→actionable), `compliance` 를
    판정 단계로 이동(replace, 입력 불변) · exit code 가 disposition/tier 만 읽도록 재구성(억제된
    secret 이 exit 0 을 못 내던 결함 수정) · `findings.json` lossless 출력 + 안정 정렬 + projection
    계약(포맷별 프로브 문서) · V1 증거 재입력 회귀(reinput: 73키 동일·disposition 1:1 매핑 확인).
  - V5 xlsx: 시트 빌더(순수 함수, formula injection·절단·불법 문자 sanitizer, 7 시트, 보안팀
    Deduped_CVEs 12열 1:1 + secscan 열, 결정성) + writer(openpyxl 지연 import, CSV 폴백) + CLI/증거
    출력 + `secscan[xlsx]` extra.
  - V6 변이 픽스처 + 축 8: `secret-app` 저엔트로피(커스텀 룰 탐지·gitleaks 미탐 기록)·인라인
    allowlist·history-only(dir 미탐/git 탐지) · 억제 전이 3종 현행 동작 고정(만료·버전상향 조용한
    재노출·도달성 변화) · deep gradlew 픽스처(spotbugs 가 시스템 gradle 대신 `gradlew` 우선, 빌드
    실패 SKIPPED 격리) · 축 8 보고서 충실성 생성기(왕복·projection id 집합·disposition 일치·
    결정성·Meta status → `fidelity.md`).
  - V7 최종 실스캔 + gate 생성기 + 최종 문서: `tools/verify/gate.py`(spec §5 상수를 코드로 갖고
    `facts*.json` 과 비교해 게이트 문서 전체를 생성 — 정오표 (g) 해소) + 생성기 레지스트리
    (`tools/verify/generators.py`, 예외 격리) + `reach-app` 정본화(축 6(b)) · 위생(trivy 순회
    `iter_vulns` 단일화, 입력면 raw 산출물을 `evidence/`로 이동·`trivy-rootfs.json` 명명, GT-A
    fact id 위치 독립화, 증거 경로 상대화, README.md 생성기화) · message-gate `a483b3b1` 최종
    실스캔(새 바이너리, 1회 성공) + jar 입력면 재생성 + V1 raw 증거 9종(deep·GT-A 8) 재입력 회귀 +
    생성 문서 일괄 산출(gt-b-match·known-fp·profile-contract·input-surface·reach-app·
    gt-a-differential·fidelity·gate·README) + reconcile 고정점(2회 실행 바이트 동일) — gate.md
    결과는 "gate.md 참조"(수치 없음). 최종 측정 문서:
    `docs/measurements/2026-09-06-message-gate-verification-final.md`(축 1~9, `## 요약` =
    gate.md 표 전체 인용, 플랜 1 대비 변화, 변이 픽스처 V6 pytest 결과, needs_human, 백로그
    P1(안전성→재현성→FN 순, spec §9), reconcile `--measurement` 통과) — 백로그 상세는 이 문서
    참조. spec 정오표 (a)("18건") 해소 문구 추가(원문 보존).
- 최종 브랜치 리뷰(플랜 2) 잔여 Minor — 플랜 3/백로그 후보(검사 약화·값 변동 없음): M2 fidelity.deterministic 은 동일 프로세스 2회 렌더 비교(프로세스 간 비교 아님) · M3 xlsx 계약이 `source` 를 손실로 선언하나 레거시 경로(occurrence 없는 SCA)에서 실림 · M4 spec §7.4 "네 출력 actionable 집합 동일" 을 xlsx 포함 한 테스트로 관통하지 않음(fidelity 생성기가 실측으로 대체) · M5 gate._ratio 가 `a/b` 아닌 fact 에 예외(write_all 은 격리 없음) · M6 레거시 gate-v2/v3 에 "판정 열 손기입" 표시 없음 · M7 플랜 1 대비 비교의 옛 값은 검사 밖(마커 정규식 `:` 배제) · M8 파일 중간·함수 안 import 산재 · M9 테스트의 `Finding(**{**f.__dict__})` 패턴 · M10 CLI 가 워크북을 항상 쓰고 폴백 시 성공 줄이 CSV 한 장만 가리킴 · M12 Summary 시트 행 레이아웃 테스트 미고정. 툴링 갭: 마커 id `:` 미지원(attrition.normalize:*), reconcile-report 인용표 헤더 `|`(플랜 1 N4 계열).

## 보고서 워크북(2026-09-07)

> spec: `docs/superpowers/specs/2026-09-07-report-workbook-design.md`(정오표 §12 포함). 플랜:
> `.superpowers/sdd/2026-09-07-report-workbook/`(태스크 11 개, R1~R4).

- [x] **R1**(Task 1~5): `secscan/report/{models,kb,derive,workbook,cli}.py` — `Finding` 을
  `Derived`/`Interpretation`/`ResultRow` 로 감싸는 보고서 모델, 지식베이스(`rules.json` 10건
  덮어쓰기 > CWE 표·advisory 합성 폴백), 파생 규칙(우선순위 P1~P5·담당 5종·판정 근거·그룹·정렬·
  확인질문 대상·결론 템플릿), 5 시트 빌더(0_요약·1_조치목록 17열·2_확인질문·3_판정기준·
  4_결과반환 `#` 지시 4행), `secscan report --findings --out` 커맨드. `scan` 끝에 report.xlsx
  자동 생성.
- [x] **R2**(Task 6~7): `deppath.py` — CycloneDX BOM 그래프 BFS 로 SCA 의존 경로(직접/전이
  `←` 체인 4단 절단/버전 상이/BOM 없음) 산출, `--bom` 배선(scan 은 sbom 캐시 자동 사용), 상대경로
  통일, 그룹 열(G-n) 확장.
- [x] **R3**(Task 8~9): `interpret.py` — report-request 생성(코드 스니펫 없음), interpretations
  파일 검증기(거부 사유 8종 + 부재/오염 처리), `--interpretations` 배선(검증 통과분만
  2_확인질문 병합, 0_요약 에 해석 상태·거부 사유 기록). `scan`/`report` 가 `report-request.json`
  을 항상 함께 씀.
- [x] **R4**(Task 10~11): `result_check.py` — `--check-result <result.json|xlsx> --rescan
  <findings.json>` 로 LLM 의 `fixed` 주장을 재스캔 결과에 해당 ID 가 더 이상 없는지로만 인정(불일치
  exit 2, 판정은 재스캔이 하지 LLM 자기 보고를 신뢰하지 않음). 문서(이 태스크): README 사용법
  2줄, 이 절, CLAUDE.md 상태 줄, spec 정오표 §12, work-note 측정 문서.
- **등록 대기 룰**: 측정 문서 `docs/measurements/2026-09-07-report-workbook-work-note.md` —
  work-note 픽스처(15건)와 message-gate 증거(2026-09-06 a483b3b1-standard) 양쪽 다
  "지식베이스 미등록 룰: 없음"(현재 `rules.json` 10건이 두 데이터셋의 발화 룰을 모두 커버).
  향후 새 스캐너/룰 추가 시 0_요약 의 "지식베이스 미등록 룰" 행으로 등록 대기를 관측하고
  `rules.json` 에 등록한다(spec 정오표 (c)).
- **불변식**: report 패키지 어떤 모듈도 `secscan.suppress` 를 import 하지 않는다(자동 억제
  금지, spec §7 "억제 자동화" 대응 — grep 으로 확인 가능, 회귀 시 이 불변식이 깨진 것).
- **백로그**: report.md 를 같은 지식베이스로 개편 · Semgrep 레지스트리 룰 설명 대량 등록
  자동화(작성 시점 생성 도구) · HTML 단일 파일 보고서 · 결과 반환을 PR 본문으로 변환.
- **최종 리뷰 fix 웨이브(2026-09-07)**: FR-1(Critical, `--check-result` ID 공간 불일치 —
  `paths.py` 분리 + 재스캔 상대화) · FR-2(scan 의 report 실패가 exit code 를 삼키던 문제 —
  try/except 격리) · FR-3(check-result 가 못 읽은 입력에 exit 0 을 내던 문제 — 스키마/0행/시트
  부재 exit 2) · FR-4(불변식 테스트 2개 신설) · FR-5(폴백 `"-"` → `"해당없음"`) · FR-6
  (`build_report` 호환 래퍼 제거) · FR-7(이 절의 측정 문서에 재생성 스크립트 포함)을 반영했다
  (`.superpowers/sdd/2026-09-07-report-workbook/final-fix-report.md`). 아래 이연 목록은 그
  반영 이후 잔여분이다.
- **이연 Minor(검사 약화·값 변동 없음)**: (1) 0_요약 `duration_s == 0` 일 때 단위 `"s"` 미표기 ·
  (2) `paths.py::_rel` 의 공백 오타(`str(Path(target)) .rstrip(...)`, FR-1 로 `report/cli.py`
  에서 이설) · (3) `deppath.py` 다중 버전 동률일 때 선택 기준이 문자열 정렬(결정적이나 의미
  없음) · (4) `interpret.py` 의 `bad_cite` `..` 검사가 인용 문자열 첫 `:` 앞부분만 봄 · (5)
  `result_check.py` 가 `load_workbook` 를 닫지 않음 · (6) `test_report_derive.py` 의 미사용
  import `REVIEW` · (7) Task 2 커밋 메시지의 "12건" 은 계수 오기(실제 `rules.json` 은 10건,
  "등록 대기 룰" 항목과 spec 정오표 (c) 참조) · (8) `count_in_guess`(interpretations 거부
  사유)가 `--check-result` 쪽에는 대응되는 검증이 없음 · (9) `--out` 이 check 모드에서 무시됨
  (인자는 받되 사용 안 함) · (10) `workbook.py` 가 `output/xlsx.py` 의 private
  `_openpyxl_available` 를 import · (11) 0_요약 `duration_s` 가 `None` 일 때(0 이 아니라
  누락) 숫자 없이 단위 `"s"` 만 남는 표시 · (12) report.xlsx 재생성 시 바이트 동일성(산출물
  결정성)을 직접 확인하는 테스트 부재 · (13) `interpret.py::FORBIDDEN` 금칙어 5개는 얇은
  방어 — 그 단어를 피하면서 판정을 단정하는 `guess` 는 통과한다(spec §5.4 설계 선택, 결함
  아님) · (14) `derive.py` 의 `done` 치환은 `{id}`·`{package}` 만 지원하고 `{target}` 은
  지원하지 않음(현재 `rules.json` 에는 안 쓰여 실피해 없음) · (15) `kb.py::validate_rules`
  (커스텀 룰 메타데이터 검증)가 테스트에서만 호출되고 report 파이프라인 런타임에서는 호출되지
  않음 · (16) 담당 `자동 수정(LLM)` 경로가 work-note 픽스처에는 0건(MyBatis 픽스처 추가가
  커버 후보).
