# message-gate 검증 캠페인 측정 문서 (플랜 1: V0~V3, 중간본)

**대상**: message-gate `a483b3b1` · **정답지**: GT-B(보안팀 trivy 결과 + 개발자 발견분) / GT-A(외부 소스 점검 fix 커밋) 대비 — 절대 recall 이 아니다.

본 문서의 모든 측정값은 `docs/verification/results/2026-09-05/facts.json` · `facts-profile.json` · `facts-knownfp.json` · `facts-gta.json` · `facts-surface.json` · `facts-reconcile.json` (이하 정본)에서 그대로 옮겼다(spec §4.5). 인용 수치 옆에는 `fact:` 로 시작하는 HTML 주석 마커가 정본 위치를 가리킨다. 이 문서는 원인·해석을 담지 않는다 — 게이트 미통과는 `docs/superpowers/specs/2026-09-04-verification-campaign-design.md` §5 에 따라 캠페인 실패가 아니라 백로그 P1 등록 사유다.

축 8(보고서 충실성)은 spec §9 실행 순서상 V6(플랜 2) 범위이므로 이 문서에 포함하지 않는다.

## 요약

| 축 | 기준 | 측정값 | 판정 |
|---|---|---|---|
| 1 프로파일 계약 | spec §5: 드리프트 전건 문서화 + spec 갱신 백로그 | profile-contract.md 행 수 4 <!-- fact:profile.rows -->건 · 드리프트 3 <!-- fact:profile.drift -->건(전건 `osv-scanner` 누락) | ✓ (문서화됨) |
| 2 SCA recall(GT-B 대비) | spec §5: CVE 단위 GT-B 합산 ≥ 44/46, HIGH/Important 미탐 ≤ 1, 미탐 전건 단계 특정(origin 별 병기 필수) | 합산 37/46 <!-- fact:sca.recall_cve --> · team 34/34 <!-- fact:sca.recall_cve.team --> · dev-found 3/12 <!-- fact:sca.recall_cve.dev-found --> · HIGH/Important 미탐 3 <!-- fact:sca.missed_high_important -->건 · 미탐 단계: scanner 9 <!-- fact:sca.missed_by_stage.scanner --> · normalize 0 <!-- fact:sca.missed_by_stage.normalize --> | ✗ → 백로그 P1 후보 |
| 3 SCA known-FP(CVE-2025-59250, mssql-jdbc) | spec §5: 3단계(component_present/version_preserved/not_reported) 모두 True | component_present: True <!-- fact:knownfp.component_present --> · version_preserved: True <!-- fact:knownfp.version_preserved --> · not_reported: True <!-- fact:knownfp.not_reported --> | ✓ |
| 4 SCA 초과분 분류 | spec §5: 미분류 0 | 초과 1 <!-- fact:sca.extras -->건 · inventory-diff 1 <!-- fact:sca.extras.inventory-diff -->건 · 미분류 0 <!-- fact:sca.extras.unclassified -->건 | ✓ |
| 5 입력면 교차 | spec §5: 인벤토리 차 전건 원인 특정, 해석 버전 불일치 0 | BOM 전용 77 <!-- fact:surface.bom_only -->건 · jar 전용 9 <!-- fact:surface.jar_only -->건 · 버전 차이 1 <!-- fact:surface.version_differs -->건 · 정답지 대비 일치 BOM 16/16 <!-- fact:surface.gt_match_bom --> / jar 15/16 <!-- fact:surface.gt_match_jar --> | ✗ → 백로그 P1 후보* |
| 6 도달성 | spec §5: false-unreachable = 0(프레임워크 활성화 케이스 포함) | reach.reachable 0 <!-- fact:reach.reachable --> · reach.unreachable 48 <!-- fact:reach.unreachable --> · reach.unknown 0 <!-- fact:reach.unknown --> (findings.sca 48 <!-- fact:findings.sca -->) · false-unreachable 목록은 `gate-v3.md` 코드블록 참조 | ✗ → 백로그 P1 |
| 7 GT-A differential(범주 내) | spec §5: 범주 내 출현·소멸 100% | gta.in_category_pass 2/4 <!-- fact:gta.in_category_pass --> | ✗ → 백로그 P1 후보 |
| 9 측정 사실성(정본 검증) | spec §5: 재생성 불일치 0 · 마커 불일치 0 · 출처 불명 0 · 비인가 override 0 | 재생성 불일치 0 <!-- fact:reconcile.regen_mismatch -->건 · 마커 불일치 0 <!-- fact:reconcile.marker_mismatch -->건 · 출처 불명 0 <!-- fact:reconcile.unmarked -->건 · 비인가 override 0 <!-- fact:reconcile.provenance_violations -->건 · 인용 표 불일치 0 <!-- fact:reconcile.quote_mismatch -->건 · raw↔typed 불일치 0 <!-- fact:reconcile.raw_typed_mismatch -->건 | ✓ |

\* 축 5 는 `gate-v2.md`/`gate-v3.md` 에 판정이 없다 — 두 문서가 작성될 시점에는 축 5 의 정본 수치(`facts-surface.json`)가 없었다(이 문서와 같은 태스크에서 사후 추가). 위 판정은 spec §5 축 5 기준을 `facts-surface.json` 수치에 기계적으로 적용한 결과다: 버전 차이(`surface.version_differs`)가 0 이 아니고, 인벤토리 차(BOM 전용/jar 전용) 개별 항목에 원인 분류가 부여되어 있지 않다(아래 축 5 절 참조).

## 환경·격리·도구 버전

스냅샷별 커밋·프로파일·스캐너 status·소요 시간·피크 메모리·도구 버전·trivy DB 시점은 `docs/verification/evidence/2026-09-05/README.md` 표를 참조한다(해당 수치에 대응하는 fact 가 없어 이 문서에는 옮기지 않는다). 격리는 스냅샷별 별도 클론 디렉토리, 전용 `GRADLE_USER_HOME`, 크리덴셜 환경변수 제거, secret 검증 `never` 로 수행됐다(README.md 참조). 전 스냅샷 `scanner_status` 전 도구 `ok`, `partial_failures` 없음(README.md 참조).

## 축 1 — 프로파일 계약

출처: `docs/verification/results/2026-09-05/profile-contract.md` (전체 인용).

| 프로파일 | spec §8 | 구현 | 누락 | 초과 | 실제 status |
|---|---|---|---|---|---|
| quick | gitleaks, trivy | gitleaks, trivy | - | - | gitleaks=ok, trivy=ok |
| accurate-sca | osv-scanner, trivy | trivy | osv-scanner | - | trivy=ok |
| standard | gitleaks, osv-scanner, semgrep, trivy | gitleaks, semgrep, trivy | osv-scanner | - | gitleaks=ok, semgrep=ok, trivy=ok |
| deep | gitleaks, osv-scanner, semgrep, spotbugs, trivy | gitleaks, semgrep, spotbugs, trivy | osv-scanner | - | gitleaks=ok, semgrep=ok, spotbugs=ok, trivy=ok |

## 축 2~4 — SCA (GT-B 대비)

인용 스코프(spec §4.5): 아래 recall 은 message-gate `a483b3b1` 단일 스냅샷을 GT-B(보안팀 trivy 결과 + 개발자 발견분) 매니페스트와 대조한 값이며, 절대 recall 이 아니다.

### 단계별 attrition (`gt-b-match.md` 인용)

raw: trivy=ok(313797B), gitleaks=ok(9393B), semgrep=ok(57924B)

| 단계 | 건수 | 증감 |
| --- | --- | --- |
| normalize:gitleaks | 13 |  |
| normalize:semgrep | 15 |  |
| normalize:trivy | 48 |  |
| normalize(합계) | 76 |  |
| merge | 73 | -3 |
| exclude | 73 | 0 |
| compliance | 73 | 0 |
| reachability | 73 | 0 |
| final | 73 | 0 |

위 표는 생성 문서(`gt-b-match.md`)의 전체 인용이며 `facts.json` 의 `attrition.<stage>` 값과 동일하다(개별 마커는 아래 SCA 절 본문 수치에만 붙인다).

### 정답지 대조 (`gt-b-match.md` 인용)

- CVE 단위 recall(GT-B 합산): 37/46 <!-- fact:sca.recall_cve -->
- origin 별 CVE recall: dev-found 3/12 <!-- fact:sca.recall_cve.dev-found --> · team 34/34 <!-- fact:sca.recall_cve.team --> (spec §5 축 2: team = 보안팀 trivy 결과의 재현율, dev-found = 독립 증거)
- 항목 단위 recall: strict 47/56 <!-- fact:sca.recall_entry_strict --> · loose(version-mismatch 포함) 47/56 <!-- fact:sca.recall_entry_loose -->

### 미탐 (`gt-b-match.md` 표 전체 인용) — 9 <!-- fact:sca.missed -->건

| advisory | 패키지 | 설치 | 심각도(보안팀) | origin | 단계 |
|---|---|---|---|---|---|
| CVE-2026-68763 | org.apache.tomcat.embed:tomcat-embed-core | 11.0.22 | Important | dev-found | scanner |
| CVE-2026-68569 | org.apache.tomcat.embed:tomcat-embed-core | 11.0.22 | Important | dev-found | scanner |
| CVE-2026-65927 | org.apache.tomcat.embed:tomcat-embed-core | 11.0.22 | Important | dev-found | scanner |
| CVE-2026-65637 | org.apache.tomcat.embed:tomcat-embed-core | 11.0.22 | Moderate | dev-found | scanner |
| CVE-2026-73180 | org.apache.tomcat.embed:tomcat-embed-core | 11.0.22 | Low | dev-found | scanner |
| CVE-2026-66422 | org.apache.tomcat.embed:tomcat-embed-core | 11.0.22 | Low | dev-found | scanner |
| CVE-2026-66299 | org.apache.tomcat.embed:tomcat-embed-core | 11.0.22 | Low | dev-found | scanner |
| CVE-2026-65183 | org.apache.tomcat.embed:tomcat-embed-core | 11.0.22 | Low | dev-found | scanner |
| CVE-2026-19880 | ch.qos.logback:logback-core | 1.5.32 | - | dev-found | scanner |

HIGH/Important 미탐 3 <!-- fact:sca.missed_high_important -->건(CVE-2026-68763·CVE-2026-68569·CVE-2026-65927).

### 초과 탐지 (`gt-b-match.md` 표 전체 인용) — 1 <!-- fact:sca.extras -->건

| advisory | 패키지 | 설치 | 분류 |
|---|---|---|---|
| CVE-2026-40992 | org.springframework.boot:spring-boot-starter-mail | 4.0.6 | inventory-diff |

분류별: inventory-diff 1 <!-- fact:sca.extras.inventory-diff -->건 · 미분류 0 <!-- fact:sca.extras.unclassified -->건. `extras-triage.json`(`docs/verification/results/2026-09-05/extras-triage.json`) — overrides: 없음 · needs_human: 없음.

### known-FP 3단계 (`known-fp.md` 전체 인용)

| 단계 | 결과 |
|---|---|
| component_present | True |
| version_preserved | True |
| not_reported | True |
| found_version | 13.2.1.jre11 |

## 축 5 — 입력면 교차

정본: `docs/verification/results/2026-09-05/facts-surface.json`(이 태스크에서 신설, `jar_surface.collect_facts`). 대상 스냅샷 `a483b3b1-standard`: jar 빌드·스캔 성공 True <!-- fact:surface.jar_ok -->, BOM 인벤토리 195 <!-- fact:surface.bom_packages -->개 패키지, jar 인벤토리 127 <!-- fact:surface.jar_packages -->개 패키지, jar 표면의 정답지 패키지 취약점 부착 행 48 <!-- fact:surface.vuln_rows_gt -->건.

인벤토리 차(BOM 전용 77 <!-- fact:surface.bom_only -->건 · jar 전용 9 <!-- fact:surface.jar_only -->건)의 개별 패키지 목록과, 버전 차이 1 <!-- fact:surface.version_differs -->건(`com.microsoft.sqlserver:mssql-jdbc`)의 상세, jar 표면 취약점 부착 버전 48 <!-- fact:surface.vuln_rows_gt -->건 표는 `docs/verification/results/2026-09-05/input-surface.md` 참조.

### 정답지 설치버전 대조 (`input-surface.md` 표 전체 인용)

| 패키지 | 보안팀 | BOM | jar |
|---|---|---|---|
| com.fasterxml.jackson.core:jackson-core | 2.21.2 | 2.21.2 | 2.21.2 |
| tools.jackson.core:jackson-core | 3.1.2 | 3.1.2 | 3.1.2 |
| com.microsoft.sqlserver:mssql-jdbc | 13.2.1.jre11 | 13.2.1.jre11 | 13.2.1 / 13.2.1.jre11 |
| com.fasterxml.jackson.core:jackson-databind | 2.21.2 | 2.21.2 | 2.21.2 |
| tools.jackson.core:jackson-databind | 3.1.2 | 3.1.2 | 3.1.2 |
| io.micrometer:micrometer-core | 1.16.5 | 1.16.5 | 1.16.5 |
| org.springframework.data:spring-data-commons | 4.0.5 | 4.0.5 | 4.0.5 |
| org.springframework:spring-webmvc | 7.0.7 | 7.0.7 | 7.0.7 |
| org.springframework:spring-expression | 7.0.7 | 7.0.7 | 7.0.7 |
| org.springframework:spring-web | 7.0.7 | 7.0.7 | 7.0.7 |
| org.springframework.security:spring-security-web | 7.0.5 | 7.0.5 | 7.0.5 |
| org.apache.logging.log4j:log4j-api | 2.25.4 | 2.25.4 | 2.25.4 |
| org.springframework.boot:spring-boot-autoconfigure | 4.0.6 | 4.0.6 | 4.0.6 |
| org.springframework:spring-core | 7.0.7 | 7.0.7 | 7.0.7 |
| ch.qos.logback:logback-core | 1.5.32 | 1.5.32 | 1.5.32 |
| org.apache.tomcat.embed:tomcat-embed-core | 11.0.22 | 11.0.22 | 11.0.22 |

BOM 열은 정답지 16행 전부와 일치해 16/16 <!-- fact:surface.gt_match_bom -->. jar 열은 `mssql-jdbc` 1행이 이중 버전 병기(`13.2.1 / 13.2.1.jre11`)로 불일치해 15/16 <!-- fact:surface.gt_match_jar -->.

## 축 6 — 도달성

### 6(a) 판정 근거 비교표 (일치율 산출 안 함 — 방법이 다름)

`gt-b-match.md` 하단 "사람 도달성 판정 비교" 표 참조(행 수 34 <!-- fact:human.verdict_rows --> · 고유 advisory 24 <!-- fact:human.verdict_advisories -->). 우리 판정은 패키지 prefix 존재(atom usage 슬라이스), 사람 판정은 CVE 별 활성화 조건(config-gated/api-unused/impl-absent) 기준이라 일치율은 산출하지 않는다(spec §5).

### 6(b) false-unreachable (`fixtures/reach-app`)

`gate-v3.md` 인용 — pytest -v 출력(`tests/test_reach_app.py`, 4건):

```
tests/test_reach_app.py::test_vulnerable_api_use_is_reachable PASSED     [ 25%]
tests/test_reach_app.py::test_used_library_with_mismatched_prefix_must_not_be_unreachable XFAIL [ 50%]
tests/test_reach_app.py::test_framework_activated_library_must_not_be_unreachable XFAIL [ 75%]
tests/test_reach_app.py::test_current_engine_false_unreachable_modes_documented PASSED [100%]
```

xfail(strict) 항목: `test_used_library_with_mismatched_prefix_must_not_be_unreachable`(prefix 불일치) · `test_framework_activated_library_must_not_be_unreachable`(프레임워크 활성화). 기준(spec §5): false-unreachable = 0.

### 6(c) 증거의 SCA 도달성 분포 (게이트 없음 — 부수 측정)

reach.unknown / findings.sca = 0 <!-- fact:reach.unknown --> / 48 <!-- fact:findings.sca -->. reach.reachable / findings.sca = 0 <!-- fact:reach.reachable --> / 48 <!-- fact:findings.sca -->. reach.unreachable / findings.sca = 48 <!-- fact:reach.unreachable --> / 48 <!-- fact:findings.sca -->.

## 축 7 — GT-A differential

기대 룰이 취약 스냅샷에서 출현하고 수정 스냅샷에서 소멸했는지(범주 내 4행)를 `gate-v3.md` 에서 인용한다.

| # | CWE | 파일 | passed | fixed_residual |
|---|---|---|---|---|
| row0 | CWE-259 | LoadtestSeederConfig.java | True <!-- fact:gta.row0.CWE-259.passed --> | 0 <!-- fact:gta.row0.CWE-259.fixed_residual --> |
| row1 | CWE-760 | LoadtestSeederConfig.java | True <!-- fact:gta.row1.CWE-760.passed --> | 0 <!-- fact:gta.row1.CWE-760.fixed_residual --> |
| row2 | CWE-89 | LgCarrierMapper.xml | False <!-- fact:gta.row2.CWE-89.passed --> | 8 <!-- fact:gta.row2.CWE-89.fixed_residual --> |
| row3 | CWE-89 | OldLgCarrierMapper.xml | False <!-- fact:gta.row3.CWE-89.passed --> | 5 <!-- fact:gta.row3.CWE-89.fixed_residual --> |

범주 내 통과: 2/4 <!-- fact:gta.in_category_pass -->.

측정 후 분류(measure-then-classify, 게이트 없음 — 결과 기록만): CWE-489 관측 없음 <!-- fact:gta.row4.CWE-489.observed -->, CWE-497 관측 없음 <!-- fact:gta.row5.CWE-497.observed -->.

전체 행(범주 외 포함, `gt-a-differential.md` 전체 인용):

| CWE | 분류 | 파일 | 룰 | 취약에서 출현 | 수정에서 소멸 | tier(기대) | 판정 |
|---|---|---|---|---|---|---|---|
| CWE-259 | in-category | LoadtestSeederConfig.java | hardcoded-credential | True | True | review (ok) | PASS |
| CWE-760 | in-category | LoadtestSeederConfig.java | zero-salt | True | True | review (ok) | PASS |
| CWE-89 | in-category | LgCarrierMapper.xml | mybatis-sqli-identifier | True | False | review (ok) | FAIL |
| CWE-89 | in-category | OldLgCarrierMapper.xml | mybatis-sqli-identifier | True | False | review (ok) | FAIL |
| CWE-489 | measure-then-classify | application.yml | - | 관측: 없음 | - | - | 기록 |
| CWE-497 | measure-then-classify | TestDbReset.java | - | 관측: 없음 | - | - | 기록 |
| CWE-676 | out-of-category | TestDbReset.java | - | 관측: 없음 | - | - | 기록 |
| CWE-754 | out-of-category | - | - | 관측: 없음 | - | - | 기록 |
| CWE-476 | out-of-category | - | - | 관측: 없음 | - | - | 기록 |
| CWE-397 | out-of-category | - | - | 관측: 없음 | - | - | 기록 |
| CWE-398 | out-of-category | - | - | 관측: 없음 | - | - | 기록 |

## 축 9 — 측정 사실성 (정본 검증)

정본 검증기(`tools/verify/reconcile.py`)를 `docs/verification/results/2026-09-05/` 의 생성 문서·게이트 문서·이 문서에 대해 실행했다. 전체 결과는 `docs/verification/results/2026-09-05/reconcile-report.md`(전체 인용 아님 — 요약만) 참조.

- **생성 문서 재생성 비교**(`gt-b-match.md`·`facts.json`·`gt-a-differential.md`·`facts-gta.json`·`known-fp.md`·`facts-knownfp.json`·`profile-contract.md`·`facts-profile.json`·`input-surface.md`·`facts-surface.json` 10건 — 이번 수정 라운드에서 `facts-knownfp.json`/`facts-profile.json` 이 재생성 비교 대상에 새로 합류했다, I3·I4): 전건 동일 바이트 재생성 — 불일치 0 <!-- fact:reconcile.regen_mismatch -->건.
- **fact 마커 대조**(`gate-v2.md`·`gate-v3.md`·이 문서 `## 요약` 절): 전 마커가 정본과 일치 — 불일치 0 <!-- fact:reconcile.marker_mismatch -->건.
- **출처 불명 수치**(`gate-v2.md`·`gate-v3.md`·이 문서 `## 요약` 절의 측정값/값 열): 0 <!-- fact:reconcile.unmarked -->건(최초 실행에서 `gate-v3.md` 축 6(b) 손기입 수치 "2건" 1건이 잡혀 마커 없이 정본화할 수 없는 값이므로 문서에서 제거하고 pytest 코드블록 인용만 남겼다 — 축 9 스스로가 찾은 위반이며, 이 문서에서 발견 사실로 남긴다).
- **override provenance**(`extras-triage.json`): override 없음 — 비인가(비 `human:`) override 0 <!-- fact:reconcile.provenance_violations -->건.
- **raw↔typed 카디널리티**(`a483b3b1-standard`): raw trivy 고유 VulnerabilityID 38 <!-- fact:reconcile.raw_count -->건 = typed SCA 고유 advisory 38 <!-- fact:reconcile.typed_count -->건 — 불일치 0 <!-- fact:reconcile.raw_typed_mismatch -->건(spec §5 축 9 의 4개 기준에는 포함되지 않는 부수 기록이나, 정본 검증기가 산출하므로 함께 인용한다).
- **인용 표 대조**(spec §4.5 (f)): 측정 문서가 표를 빠짐없이 그대로 옮겨 적었다고 선언한 곳을 원본 결과 문서의 동일 헤더 표와 마커 제거 후 행 단위로 대조 — 불일치 0 <!-- fact:reconcile.quote_mismatch -->건(Task 12 N1 — 인용 선언 탐지가 줄 단위로 강화되며, 이 항목의 예전 설명문이 이 검사의 트리거 문구를 그대로 담고 있어 파일명 없는 선언으로 스스로 오탐되는 것을 축 9 가 찾아 표현을 바꿨다).

판정: ✓ 통과(spec §5: 4개 기준 모두 0).

## 부수 측정 (시간·메모리, 게이트 없음)

스냅샷별 소요 시간·피크 메모리(`elapsed_s`, `children_max_rss_bytes`)는 `docs/verification/evidence/2026-09-05/README.md` 표를 참조한다(대응 fact 없음 — 옮기지 않음). 같은 문서에 1차 실행의 trivy DB 콜드캐시 타임아웃과 컨트롤러의 DB 사전 다운로드·도달성 캐시 선생성 경위가 기록되어 있다.

## 백로그 후보 (우선순위)

플랜 2(V4~V7)에서 확정.

**P1 — 게이트 미통과**

- 축 2 SCA recall — fact: `sca.recall_cve` 합산 37/46 <!-- fact:sca.recall_cve -->, `sca.missed_high_important` 3 <!-- fact:sca.missed_high_important -->건.
- 축 5 입력면 교차 — fact: `surface.version_differs` 1 <!-- fact:surface.version_differs -->건(인벤토리 차 개별 항목 원인 미분류).
- 축 6(b) 도달성 false-unreachable: `tests/test_reach_app.py` xfail(strict) 항목(위 축 6(b) 코드블록). spec §11: "도달성 축 6 은 현 엔진이 게이트를 통과하지 못할 가능성이 높다. 이는 캠페인의 결과이지 실패가 아니다."
- 축 7 GT-A differential(범주 내) — fact: `gta.in_category_pass` 2/4 <!-- fact:gta.in_category_pass -->, `gta.row2.CWE-89.fixed_residual` 8 <!-- fact:gta.row2.CWE-89.fixed_residual -->건, `gta.row3.CWE-89.fixed_residual` 5 <!-- fact:gta.row3.CWE-89.fixed_residual -->건.

**P2 — 관측된 갭(게이트 없음, 기록 대상)**

- 축 1 프로파일 드리프트 — fact: `profile.drift` 3 <!-- fact:profile.drift -->건 전건 `osv-scanner` 누락 — spec §8 갱신 백로그(기준에 이미 명시).

## needs_human (사람 확정 필요)

`gate-v3.md` 인용:

- `8428e646`에서 `mybatis-sqli-identifier`가 `LgCarrierMapper.xml`에 8건 <!-- fact:gta.row2.CWE-89.fixed_residual -->, `OldLgCarrierMapper.xml`에 5건 <!-- fact:gta.row3.CWE-89.fixed_residual --> 잔존 — 룰 범위인가, 수정 범위인가, GT-A 기대 정의인가?

`extras-triage.json` 인용: overrides — 없음 · needs_human — 없음.
