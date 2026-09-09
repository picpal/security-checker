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
  확인질문 대상·결론 템플릿), 5 시트 빌더(0_요약·1_취약점 목록 17열·2_확인질문·3_용어와 대응(구 3_판정기준)·
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

## BOM 캐시 무효화 수정(2026-09-09)
- [x] **결함(실측)**: `bom_cache_path` 의 캐시 키가 대상 경로 문자열뿐이라, 의존성을 올려도
  `ensure_bom` 이 옛 BOM 을 영원히 재사용 → 조치 전·후 스캔이 같은 CVE 를 보고(tomcat-embed-core
  10.1.55→10.1.59, log4j-api 2.24.3→2.25.5 에서 옛 버전 CVE 4건 잔존, trivy 8.7s→0.5s 가 단서).
  반대 방향(새로 추가된 취약 의존성을 "깨끗함"으로 보고)이 더 위험 — 원칙 1(정확도 우선) 위반.
- [x] **수정**: 캐시 키 = `sha1(대상 절대경로)/manifest_fingerprint(...)`. 지문은 의존성 매니페스트
  (`pom.xml`·`*.gradle`·`*.gradle.kts`·`gradle.properties`·`*.versions.toml`·`*.lockfile`)의
  (상대경로, 내용 sha1) 해시 — mtime 미사용(git checkout 이 mtime 을 바꿔 캐시를 무의미하게 함).
  탐색은 `exclude.DEFAULT_EXCLUDES` 로 디렉토리 가지치기(node_modules/build/.git 오염 방지).
  docstring 의 거짓("코드 해시 캐시") 정정. 코어 인터페이스 무변경(`ensure_bom` 시그니처 동일).
- [x] 회귀 게이트: 버전 상향 재스캔 시 cdxgen 재실행 + 새 버전 BOM 반환(실측 시나리오 재현),
  내용 동일 시 캐시 유지(mtime 변경 포함), 대상별 분리, 매니페스트 9종 파라미터, 제외 디렉토리 무시.
  **544 passed, 2 xfailed** (신규 15건).
- 남은 한계였던 "매니페스트 불변 + 결과 변동" 경로는 아래 후속에서 처리. 지문이 바뀌면 옛 캐시
  디렉토리는 그대로 남는다(자동 삭제 안 함).

### 후속: 동적 버전 자동 우회 + `--no-bom-cache` (2026-09-09)
- [x] **`dynamic_versions(target)`** — 매니페스트에서 해석 시점마다 달라질 수 있는 선언을 탐지:
  동적 버전(`2.+`·`latest.release`·`[1.0,2.0)`)·SNAPSHOT·**원격** parent pom. maven 은
  ElementTree 로 `dependency`/`parent` 만 보고 `<properties>` 참조를 해석한다.
  FP 방어 2종이 핵심 — 프로젝트 **자기 버전** SNAPSHOT(`<version>0.0.1-SNAPSHOT</version>`,
  gradle.properties `version=`)과 **로컬** parent(멀티모듈 집합체)는 제외. 이걸 안 하면 개발 중
  프로젝트 대부분이 캐시를 못 쓴다. 실증: 스프링부트 maven/gradle 프로젝트·이 저장소·픽스처 5종 모두 0건 오탐.
- [x] **정책 (a) 자동 우회 채택** — 탐지되면 캐시를 우회하고 그 사실·근거를 출력 +
  `findings.json` `meta.bom_cache{refresh,reason}` 에 기록. 근거: 경고만 하면(b) 이미 나간 보고서가
  틀린 채로 남고, 바로잡으려면 전체 재스캔(더 비쌈)이 필요하다. 실측 비용은 스캔당 **+3.3s**
  (캐시적중 0.27s vs 자동우회 3.58s, spring-boot web+jpa 65 컴포넌트 gradle).
  탐지 실패는 캐시 정책 유지 + 경고(원칙 5).
- [x] `--no-bom-cache`(scan 전용) 수동 강제 우회. 우회해도 결과는 캐시에 기록돼 다음 스캔이 이득.
- [x] `generate_sbom` 임시파일+`os.replace` 원자적 교체 — 우회 재생성이 실패했을 때 같은 경로의
  **옛 BOM 을 성공으로 오인**하던 경로 차단(스테일 재발 방지). 실패 시 SKIPPED, 기존 캐시는 비파괴.
- [x] 회귀 46건 추가(**590 passed, 2 xfailed**). 기존 테스트 더블 5개(`ensure_bom`×3,
  `build_adapters`×2)는 넓어진 시그니처에 맞춰 갱신.

### codex 리뷰 P1 3건 반영 — fail-open → fail-closed (2026-09-09)
> 지적의 뿌리 하나: **해석 못 한 버전 표현을 "고정"으로 단정**해 캐시를 유지했다. 3건 모두 재현됨.
- [x] **P1-1 지문 범위** — `collect_manifests()` 신설: 대상 안 매니페스트 + **빌드가 실제로 읽는
  대상 밖 파일**(maven 로컬 parent pom 체인, gradle 빌드 루트의 `build.gradle`·`gradle.properties`·
  `gradle/` 카탈로그). 모듈만 스캔할 때 `../pom.xml`·루트 스크립트가 바뀌어도 캐시 키가 안 움직이던
  구멍을 닫았다. parent 억제 조건도 "로컬에 있다" → **"지문에 실제로 들어갔다"** 로 교체.
- [x] **P1-2 maven 프로퍼티** — `_pom_properties()` 가 로컬 parent 체인과 profile `<properties>` 까지
  모아 해석. 해석되면 그 값으로 판정, **끝내 못 풀면 동적**(`${lib.version}` 그대로 보고).
  자기 버전 계열(`project.version`·`revision` 등)과 버전 미기재(BOM 관리형)는 판단 대상에서 제외.
- [x] **P1-3 gradle 보간** — 프로젝트 전역 심볼표(`def/val/var/ext`·`ext['k']`·`gradle.properties`)로
  `$v`·`${rootProject.ext.v}` 를 해석. `libs.*` 는 카탈로그 참조(카탈로그 자체가 지문에 있고 동적
  항목은 TOML 스캔이 잡음)라 해석됨으로 취급. 미해석은 동적.
- [x] 보고 값 계약: 풀렸으면 해석값(`2.+`), 못 풀었으면 원문(`$mysteryVersion`) — 왜 우회했는지 읽힌다.
- [x] **오탐 0 실측 15개 대상**: work-note(루트/backend)·이 저장소·스프링부트 maven/gradle·
  **멀티모듈 maven 3(집합체/core/web)·멀티모듈 gradle 2(루트/서브프로젝트)**·픽스처 5.
  work-note 사본에서 tomcat 핀 10.1.59→10.1.60 시 키 변경·복원까지 확인. 탐지 비용 0.4~25ms.
  회귀 20건 추가(**610 passed, 2 xfailed**).

### codex 리뷰 라운드2 P1 4건 — 정규식 확장 대신 구조로 (2026-09-09)
- [x] **P1-A(정규식 버그, 그냥 고침)** — 좌표 정규식이 `${property('x')}` 의 따옴표에서 잘려
  보간으로도 동적으로도 안 보였다. `${...}` 덩어리를 먼저 삼키도록 수정.
- [x] **P1-B(그냥 고침)** — `../pom.xml` 이 있어도 좌표(groupId/artifactId/version)가 declared parent
  와 다르면 maven 은 원격에서 받는다. 후보 pom 을 파싱해 대조하고, 다르면 원격 취급.
  후보가 **생략**한 필드(상속)는 대조에서 제외 — 없는 걸 불일치로 보면 멀티모듈이 캐시를 잃는다.
- [x] **P1-C·D 는 파서 확장(선택지 1)을 거부하고 구조적 처리(선택지 3 = 2 + 최소 확장)** :
  - **C(모호)**: 후보 값이 갈리면(상호배타 profile 등) 값을 고르지 않고 **모호 → 우회**.
    단 의미론이 확정적인 우선순위는 보존한다 — maven 은 자식 pom 이 부모를 덮고, gradle 은
    자기 스크립트의 정의가 전역보다 앞선다. 이걸 안 지키면 정상 프로젝트가 전부 모호해진다.
  - **D(지문 범위)**: applied script 를 "따라가는" 대신 **gradle 빌드 루트 하위 전체**의
    매니페스트를 지문·심볼에 넣는다(중첩 스크립트·중첩 카탈로그·buildSrc/convention 플러그인이
    한 번에 들어온다). 과잉 무효화 방향이라 안전하고, 루트를 스캔할 때와 같은 집합이다.
  - **불확실 신호 = 우회** 로 일반화: `DynamicVersion.kind` 5종(dynamic/unresolved/ambiguous/
    unparsable/external-script). 파싱 실패를 조용히 넘기던 것(=고정으로 단정)도 이제 우회 사유다.
  - **BOM TTL(기본 24h, `--bom-max-age`)** — 정적 분석이 **원리적으로** 못 보는 변화의 하한선.
    캐시 파일 mtime 기준(우리가 만든 파일의 생성 시각이라 "키에 mtime 금지"와 무관).
- [x] 오탐 0 재실측 16개 대상(work-note 루트·backend, 이 저장소, 스프링부트 maven/gradle,
  멀티모듈 maven 3·gradle 2, 픽스처 5, **관용구 종합**(apply from `$rootDir`·중첩 공유 스크립트·
  버전 카탈로그 `libs.versions.x.get()`·buildSrc convention)). E2E 캐시적중 0.27s 유지,
  `--bom-max-age 0` 강제 재생성 4.46s. 회귀 11건 추가(**621 passed, 2 xfailed**).

### 정적 분석으로 **원리적으로** 못 잡는 부류 (숨기지 않는다 — 원칙 5)
> 아래는 매니페스트를 아무리 정교하게 파싱해도 알 수 없다. gradle/maven 을 **실행해야**
> 확정되기 때문이다. 유일한 방어선은 BOM TTL(기본 24h)과 `--no-bom-cache` 다.
1. **실행 시점 주입값** — `-PlibVersion=…`·`-D`·환경변수·`System.getenv`·`providers.exec`,
   파일/네트워크에서 읽어오는 버전.
2. **코드가 만드는 좌표** — `"$g:$a:$v"`(좌표 전체가 변수), 반복문·조건문으로 조립하는 의존성,
   gradle 명명인자 표기(`group: 'x', name: 'y', version: '2.+'`).
3. **플러그인이 주입하는 의존성** — spring-dependency-management·protobuf·kapt/ksp 등이
   해석 시점에 추가하는 좌표(매니페스트에 문자열로 존재하지 않는다).
4. **buildSrc/convention 플러그인·included build 의 *내용*** — 파일 변경은 지문이 잡지만(→캐시
   무효화) 그 코드가 무엇을 선언하는지는 해석하지 않는다. `includeBuild` 로 붙는 다른 저장소도 마찬가지.
5. **원격 상태 변화** — *고정* 버전 아티팩트 재배포, 미러·프록시 변조, 원격 parent/BOM import 의
   내용 변경, 플러그인 포털 해석 결과.
6. **해상도 규칙** — resolutionStrategy·force·exclude·충돌 해결이 바꾸는 최종 그래프.
7. **maven profile 활성화** — activeByDefault·OS/JDK 조건·`-P`. 우리는 "모호"로 보고 우회하지만
   어느 값이 실제로 쓰일지는 모른다.
8. **gradle 심볼 가시성** (codex R3 P1, 의도적 미수정) — 전역 심볼표는 *적용되지 않은* 스크립트나
   다른 서브프로젝트의 정의까지 병합한다. 그래서 실제로는 런타임에 주입되는 값이 "고정"으로 보여
   우회를 놓칠 수 있다. **고치지 않기로 판단했다**: 스크립트 가시성(어느 스크립트가 어느 프로젝트에
   적용되는지)은 빌드를 실행해야 확정되고, 모르면 우회하는 쪽으로 밀면 멀티프로젝트가 통째로 캐시를
   잃는다. **오탐 폭발은 스테일보다 나쁜 실패다** — 모두가 캐시를 못 쓰면 도구를 안 쓰게 되고, 그러면
   정확도 자체가 0이 된다. 이 잔여분의 하한선이 **BOM TTL 24h** 이고, 즉시 확실히 하려면
   `--no-bom-cache` 다. (위 1~7 도 같은 백스톱을 공유한다.)

### codex 리뷰 라운드3 (2026-09-09) — 리뷰 예산 종료
- [x] **P1-2 parent 실효 좌표** — 후보 pom 이 groupId/version 을 상속으로 생략하면 자기 `<parent>`
  에서 채운 **실효 GAV** 로 대조한다(artifactId 는 상속되지 않는다). 실효 좌표를 못 구하면 로컬이라
  단정하지 않는다(fail-closed). 멀티모듈 maven 3종 오탐 0 유지 확인.
- [x] **P2 결정 지점 일원화** — `build_adapters(profile, target=…)` 가 BOM 우회를 스스로 판정한다.
  CLI 는 안내 출력 때문에 명시 인자를 계속 넘기고, `tools/verify/run_snapshot.py` 는 target 을 넘겨
  자동 우회를 받는다(증적이 옛 BOM 으로 굳던 경로).
- [x] **P2 `$rootDir` 스코프** — 루트 스코프 변수는 탐지된 gradle 빌드 루트 기준으로 푼다. 지문에
  이미 있는 스크립트를 external-script 로 몰아 **매 스캔 재생성**시키던 성능 오탐 제거
  (실측: 서브프로젝트 재스캔 2.97s → **0.16s**).
- [x] **P2 증적 위장 차단** — `write_evidence` 는 BOM SCA 가 OK 일 때만 캐시 BOM 을 정본으로 복사한다.
  TTL 재생성 실패 시 어댑터는 SKIPPED 인데 증적만 성공처럼 남던 것을 막았다(원칙 5).
- [x] 오탐 0 재실측 **19개 대상**(work-note 2·이 저장소·스프링부트 2·멀티모듈 maven 3·gradle 2·
  관용구 2·`$rootDir` 2·픽스처 5). **628 passed, 2 xfailed**(회귀 7건 추가).
