# message-gate 검증 캠페인 측정 문서 (플랜 2: V4~V7, 최종본)

**대상 message-gate `a483b3b1`** · **GT-B(보안팀 trivy 결과 + 개발자 발견분) 대비** · **GT-A/deep 은 V1 raw 재입력**(스캐너 미재실행) — 절대 recall 이 아니다.

본 문서의 모든 측정값은 `docs/verification/results/2026-09-06/facts.json` · `facts-gta.json` · `facts-knownfp.json` · `facts-profile.json` · `facts-surface.json` · `facts-reachapp.json` · `facts-fidelity.json` · `facts-reconcile.json`(이하 정본)에서 그대로 옮겼다(spec §4.5). 인용 수치 옆 `fact:` HTML 주석 마커가 정본 위치를 가리킨다. 이 문서는 원인·해석을 담지 않는다 — 게이트 미통과는 `docs/superpowers/specs/2026-09-04-verification-campaign-design.md` §5 에 따라 캠페인 실패가 아니라 백로그 P1 등록 사유다.

축 1~5·8 은 message-gate `a483b3b1` 최종 실스캔(새 바이너리, `docs/verification/evidence/2026-09-06/a483b3b1-standard`·`a483b3b1-jar`) 결과다. 축 6(a) 사람 판정 비교와 축 7 GT-A differential, 축 8 의 deep 메타 일부는 V1 증거(`docs/verification/evidence/2026-09-05/`)의 raw 산출물을 새 파이프라인으로 재입력한 결과이며(`meta.reinput_from` — `a483b3b1-deep` + GT-A 8 스냅샷), 스캐너를 다시 실행하지 않았다. 격리 실행(스냅샷별 clone·전용 `GRADLE_USER_HOME`·크리덴셜 환경변수 제거·secret 검증 `never`)·도구 버전·소요 시간은 `docs/verification/evidence/2026-09-06/README.md`·`NOTES.md`(대응 fact 없어 이 문서에는 옮기지 않음) 참조.

## 요약

`docs/verification/results/2026-09-06/gate.md` 표 전체 인용(reconcile (f) 대조 대상). 판정 열은 생성기(`tools/verify/gate.py`) 출력을 그대로 옮겼다(정오표 (g), 손으로 쓰지 않음).

| 축 | 기준(spec §5) | 측정값 | 판정 |
|---|---|---|---|
| 1 프로파일 계약 | 드리프트 전건 문서화 + spec 갱신 백로그 — 기계 판정 없음(문서화는 생성 문서 profile-contract.md 존재로 충족) | rows 4 <!-- fact:profile.rows --> · drift 3 <!-- fact:profile.drift --> | 기록 |
| 2 SCA recall(GT-B 대비) | CVE 단위 합산 ≥ 44/46 · HIGH/Important 미탐 ≤ 1 · 미탐 전건 단계 특정(origin 별 병기) | recall_cve 37/46 <!-- fact:sca.recall_cve --> · recall_cve.team 34/34 <!-- fact:sca.recall_cve.team --> · recall_cve.dev-found 3/12 <!-- fact:sca.recall_cve.dev-found --> · missed 9 <!-- fact:sca.missed --> · missed_high_important 3 <!-- fact:sca.missed_high_important --> · missed_by_stage.scanner 9 <!-- fact:sca.missed_by_stage.scanner --> · missed_by_stage.normalize 0 <!-- fact:sca.missed_by_stage.normalize --> | ✗ → 백로그 P1 |
| 3 SCA known-FP(mssql-jdbc CVE-2025-59250) | 3단계 모두 True | component_present True <!-- fact:knownfp.component_present --> · version_preserved True <!-- fact:knownfp.version_preserved --> · not_reported True <!-- fact:knownfp.not_reported --> · found_version 13.2.1.jre11 <!-- fact:knownfp.found_version --> | ✓ |
| 4 SCA 초과분 분류 | 미분류 0 | extras 1 <!-- fact:sca.extras --> · extras.unclassified 0 <!-- fact:sca.extras.unclassified --> | ✓ |
| 5 입력면 교차 | 해석 버전 불일치 0 (인벤토리 차 원인은 input-surface.md 표 참조) | bom_only 77 <!-- fact:surface.bom_only --> · jar_only 9 <!-- fact:surface.jar_only --> · version_differs 1 <!-- fact:surface.version_differs --> · gt_match_bom 16/16 <!-- fact:surface.gt_match_bom --> · gt_match_jar 15/16 <!-- fact:surface.gt_match_jar --> | ✗ → 백로그 P1 |
| 6 도달성 | false-unreachable = 0 (프레임워크 활성화 케이스 포함) | cases 3 <!-- fact:reachapp.cases --> · false_unreachable 2 <!-- fact:reachapp.false_unreachable --> · reachable 0 <!-- fact:reach.reachable --> · unreachable 48 <!-- fact:reach.unreachable --> · unknown 0 <!-- fact:reach.unknown --> | ✗ → 백로그 P1 |
| 7 GT-A differential(범주 내) | 범주 내 출현·소멸 100% | in_category_pass 2/4 <!-- fact:gta.in_category_pass --> | ✗ → 백로그 P1 |
| 8 보고서 충실성 | 왕복 동일 · id 집합 동일 · 판정 불일치 0 · 결정성 | roundtrip_identical True <!-- fact:fidelity.roundtrip_identical --> · id_set_mismatch 0 <!-- fact:fidelity.id_set_mismatch --> · disposition_mismatch 0 <!-- fact:fidelity.disposition_mismatch --> · deterministic True <!-- fact:fidelity.deterministic --> · meta_scanner_status_rows 3 <!-- fact:fidelity.meta_scanner_status_rows --> · undecided 0 <!-- fact:fidelity.undecided --> | ✓ |
| 9 측정 사실성 | reconcile 검사 전항 0 — 값은 reconcile-report.md 참조(이 문서를 재생성하는 검증기 자신의 결과라 여기 인용하지 않음) | reconcile-report.md 참조 | 기록 |

## 축 1 — 프로파일 계약

출처: `docs/verification/results/2026-09-06/profile-contract.md` (표 전체 인용).

| 프로파일 | spec §8 | 구현 | 누락 | 초과 | 실제 status |
|---|---|---|---|---|---|
| quick | gitleaks, trivy | gitleaks, trivy | - | - | gitleaks=ok, trivy=ok |
| accurate-sca | osv-scanner, trivy | trivy | osv-scanner | - | trivy=ok |
| standard | gitleaks, osv-scanner, semgrep, trivy | gitleaks, semgrep, trivy | osv-scanner | - | gitleaks=ok, semgrep=ok, trivy=ok |
| deep | gitleaks, osv-scanner, semgrep, spotbugs, trivy | gitleaks, semgrep, spotbugs, trivy | osv-scanner | - | gitleaks=ok, semgrep=ok, spotbugs=ok, trivy=ok |

행 4 <!-- fact:profile.rows -->건 중 드리프트 3 <!-- fact:profile.drift -->건(전건 `osv-scanner` 누락) — spec §5 축 1 은 기계 판정이 아니라 문서화로 충족(위 표 존재).

## 축 2~4 — SCA (GT-B 대비)

인용 스코프(spec §4.5): 아래 recall 은 message-gate `a483b3b1` 단일 스냅샷을 GT-B(보안팀 trivy 결과 + 개발자 발견분) 매니페스트와 대조한 값이며, 절대 recall 이 아니다.

### 단계별 attrition (`gt-b-match.md` 표 전체 인용)

raw: trivy=ok(313797B), gitleaks=ok(10852B), semgrep=ok(58066B)

| 단계 | 건수 | 증감 |
| --- | --- | --- |
| normalize:gitleaks | 15 |  |
| normalize:semgrep | 15 |  |
| normalize:trivy | 48 |  |
| normalize(합계) | 78 |  |
| merge | 75 | -3 |
| exclude | 73 | -2 |
| reachability | 73 | 0 |
| disposition | 73 | 0 |
| final | 73 | 0 |

위 표는 생성 문서(`gt-b-match.md`)의 전체 인용이며 `facts.json` 의 `attrition.<stage>` 값과 동일하다. 단계명이 `compliance`→`disposition`(판정 단계 H, V4)으로 바뀌었고 `merge`·`normalize:gitleaks` 값이 플랜 1과 다르다 — 상세는 아래 "## 플랜 1 대비 변화" 참조.

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

분류별: inventory-diff 1 <!-- fact:sca.extras.inventory-diff -->건 · 미분류 0 <!-- fact:sca.extras.unclassified -->건. `extras-triage.json`(`docs/verification/results/2026-09-06/extras-triage.json`, 플랜 1 그대로 승계) — overrides: 없음 · needs_human: 없음.

### known-FP 3단계 (`known-fp.md` 표 전체 인용)

| 단계 | 결과 |
|---|---|
| component_present | True |
| version_preserved | True |
| not_reported | True |
| found_version | 13.2.1.jre11 |

## 축 5 — 입력면 교차

정본: `docs/verification/results/2026-09-06/facts-surface.json`. 대상 스냅샷 `a483b3b1-standard`: jar 빌드·스캔 성공 True <!-- fact:surface.jar_ok -->, BOM 인벤토리 195 <!-- fact:surface.bom_packages -->개 패키지, jar 인벤토리 127 <!-- fact:surface.jar_packages -->개 패키지, jar 표면의 정답지 패키지 취약점 부착 행 48 <!-- fact:surface.vuln_rows_gt -->건.

인벤토리 차(BOM 전용 77 <!-- fact:surface.bom_only -->건 · jar 전용 9 <!-- fact:surface.jar_only -->건)의 개별 패키지 목록과 버전 차이 1 <!-- fact:surface.version_differs -->건(`com.microsoft.sqlserver:mssql-jdbc`)의 상세, jar 표면 취약점 부착 버전 48 <!-- fact:surface.vuln_rows_gt -->건 표는 `docs/verification/results/2026-09-06/input-surface.md` 참조.

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

`gt-b-match.md` 하단 "사람 도달성 판정 비교" 표 참조(행 수 34 <!-- fact:human.verdict_rows --> · 고유 advisory 24 <!-- fact:human.verdict_advisories -->). 우리 판정은 패키지 prefix 존재(atom usage 슬라이스), 사람 판정은 CVE 별 활성화 조건(config-gated/api-unused/impl-absent) 기준이라 일치율은 산출하지 않는다(spec §5). spec 정오표 (a) 해소(2026-09-06, 아래 spec 정오표 참조): §3.2·§5 축 6(a)의 "18건"은 이 `human.verdict_rows`/`human.verdict_advisories` 로 읽는다.

### 6(b) false-unreachable — `fixtures/reach-app` (`reach-app.md` 표 전체 인용)

| 케이스 | 패키지 | CVE | 현 엔진 판정 | 기대 충족 |
|---|---|---|---|---|
| reachable | commons-text | CVE-2022-42889 | reachable | True |
| must_not_be_unreachable | jackson-databind | CVE-2022-42003 | unreachable | False |
| must_not_be_unreachable | tomcat-embed-core | CVE-2021-41079 | unreachable | False |

케이스 3 <!-- fact:reachapp.cases -->건 중 false-unreachable 2 <!-- fact:reachapp.false_unreachable -->건, reachable 기대 적중 1/1 <!-- fact:reachapp.reachable_expected_hit -->. 기준(spec §5): false-unreachable = 0.

### 6(c) 증거의 SCA 도달성 분포 (게이트 없음 — 부수 측정)

reach.unknown / findings.sca = 0 <!-- fact:reach.unknown --> / 48 <!-- fact:findings.sca -->. reach.reachable / findings.sca = 0 <!-- fact:reach.reachable --> / 48 <!-- fact:findings.sca -->. reach.unreachable / findings.sca = 48 <!-- fact:reach.unreachable --> / 48 <!-- fact:findings.sca -->.

## 축 7 — GT-A differential

스코프: 이 축은 V1 raw 재입력 결과다(스캐너 미재실행, `meta.reinput_from`). 기대 룰이 취약 스냅샷에서 출현하고 수정 스냅샷에서 소멸했는지(범주 내 4행)를 `gt-a-differential.md` 에서 인용한다.

| # | CWE | 파일 | passed | fixed_residual |
|---|---|---|---|---|
| row0 | CWE-259 | LoadtestSeederConfig.java | True <!-- fact:gta.CWE-259.LoadtestSeederConfig.passed --> | 0 <!-- fact:gta.CWE-259.LoadtestSeederConfig.fixed_residual --> |
| row1 | CWE-760 | LoadtestSeederConfig.java | True <!-- fact:gta.CWE-760.LoadtestSeederConfig.passed --> | 0 <!-- fact:gta.CWE-760.LoadtestSeederConfig.fixed_residual --> |
| row2 | CWE-89 | LgCarrierMapper.xml | False <!-- fact:gta.CWE-89.LgCarrierMapper.passed --> | 8 <!-- fact:gta.CWE-89.LgCarrierMapper.fixed_residual --> |
| row3 | CWE-89 | OldLgCarrierMapper.xml | False <!-- fact:gta.CWE-89.OldLgCarrierMapper.passed --> | 5 <!-- fact:gta.CWE-89.OldLgCarrierMapper.fixed_residual --> |

범주 내 통과: 2/4 <!-- fact:gta.in_category_pass -->.

측정 후 분류(measure-then-classify, 게이트 없음 — 결과 기록만): CWE-489 관측 없음 <!-- fact:gta.CWE-489.application.observed -->, CWE-497 관측 없음 <!-- fact:gta.CWE-497.TestDbReset.observed -->.

전체 행(범주 외 포함, `gt-a-differential.md` 표 전체 인용):

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

## 축 8 — 보고서 충실성 (V6, 생성 문서)

`fidelity.md` 표 전체 인용(3개 표):

| 검사 | 값 |
|---|---|
| findings.json 왕복 동일 | True |
| 결정성(md/SARIF/xlsx 2회 동일) | True |
| 미판정(disposition None) | 0 |
| Meta 스캐너 status 행 | 3 |
| exit code(판정 기준) | 1 |

`fidelity.md` 표 전체 인용(id 집합):

| 포맷 | id 수 | findings.json 과 동일 |
|---|---|---|
| findings | 73 | True |
| markdown | 73 | True |
| sarif | 73 | True |
| xlsx | 73 | True |

`fidelity.md` 표 전체 인용(actionable 집합):

| 포맷 | actionable 수 | findings.json 과 동일 |
|---|---|---|
| findings | 14 | True |
| markdown | 14 | True |
| sarif | 14 | True |
| xlsx | 14 | True |

왕복 동일성 True <!-- fact:fidelity.roundtrip_identical -->, id 집합 불일치 0 <!-- fact:fidelity.id_set_mismatch -->, 판정(disposition) 불일치 0 <!-- fact:fidelity.disposition_mismatch -->(exit code 결함 §7.4 이 V4 에서 해소됐음을 뒷받침 — exit code 1 <!-- fact:fidelity.exit_code -->), 결정성 True <!-- fact:fidelity.deterministic -->, 미판정 0 <!-- fact:fidelity.undecided -->건, Meta 스캐너 status 행 3 <!-- fact:fidelity.meta_scanner_status_rows -->개, actionable 14 <!-- fact:fidelity.actionable.findings -->건(전 포맷 동일).

## 플랜 1 대비 변화

같은 fact id 를 2026-09-05(플랜 1)와 2026-09-06(이 문서, 플랜 2 V7)의 facts 파일에서 나란히 비교한다. 새 값은 이 문서의 정본(`docs/verification/results/2026-09-06/facts*.json`) 마커로 인용한다. reconcile 의 `--measurement` 마커 검사는 현재 results 의 facts 만 보므로, 옛 값은 마커를 붙이지 않고 `docs/verification/results/2026-09-05/facts.json`(플랜 1 정본, `load_facts` 로 읽음)의 해당 줄을 코드블록으로 그대로 붙여 인용한다(`(2026-09-05 정본)` 표기).

`facts.json` 두 시점을 바이트 diff 한 결과, 아래 3개 키만 다르고 나머지는 전부 동일하다. `facts-gta.json`·`facts-knownfp.json`·`facts-profile.json`·`facts-surface.json`·`facts-reconcile.json` 은 5개 파일 모두 두 디렉토리 사이에 바이트 차이가 없다(diff 결과 없음).

**attrition.disposition(구 attrition.compliance)** — 판정 단계 H 재구성(V4)으로 키 이름이 바뀌었다(값은 동일).

새 값: 73 <!-- fact:attrition.disposition -->

(2026-09-05 정본, `facts.json`):
```
"attrition.compliance": 73,
```

**attrition.merge**

새 값: 75 <!-- fact:attrition.merge -->

(2026-09-05 정본, `facts.json`):
```
"attrition.merge": 73,
```

**attrition.normalize:gitleaks** — 이 fact id 는 `:` 를 포함해 reconcile 마커 정규식(`[A-Za-z0-9_.\-/가-힣]+`, 콜론 미포함)이 `-->` 앞에서 값을 닫지 못한다. 인라인 마커로 표현할 수 없어 새·옛 값 모두 코드블록으로 그대로 인용한다.

(2026-09-06 정본, `facts.json`):
```
"attrition.normalize:gitleaks": 15,
```

(2026-09-05 정본, `facts.json`):
```
"attrition.normalize:gitleaks": 13,
```

`facts-reachapp.json`·`facts-fidelity.json` 은 플랜 2(V4·V6)에서 신설된 생성기(`reach_app`·`fidelity`) 산출물이라 2026-09-05 시점에는 파일 자체가 없다 — 비교 대상 없음.

## 변이 픽스처(V6)

`pytest -v tests/test_secret_variants.py tests/test_suppress_transitions.py tests/test_deep.py` 출력(코드블록 인용, 수치 산문 없음):

```
============================= test session starts ==============================
platform darwin -- Python 3.14.6, pytest-9.1.1, pluggy-1.6.0
rootdir: /Users/picpal/Desktop/workspace/security-checker
configfile: pyproject.toml
collected 15 items

tests/test_secret_variants.py ....                                       [ 26%]
tests/test_suppress_transitions.py ...                                   [ 46%]
tests/test_deep.py ........                                              [100%]

============================== 15 passed in 0.53s ==============================
```

## needs_human (사람 확정 필요)

- 축 2 SCA recall: GT-B 대비 미탐 9 <!-- fact:sca.missed -->건(tomcat-embed-core·logback-core, 전건 origin=dev-found, 단계=scanner)은 이번 사이클에서 조치 대상인가, 아니면 축 1 프로파일 드리프트(`osv-scanner` 누락 3 <!-- fact:profile.drift -->건)와 함께 별도로 남겨둘 대상인가?
- 축 5 입력면 교차: `surface.gt_match_jar` 15/16 <!-- fact:surface.gt_match_jar -->(mssql-jdbc 가 jar 스캔에서 `13.2.1`/`13.2.1.jre11` 이중 항목으로 잡히는 현상, known-FP 축 3 의 근거이기도 함)을 입력면 축 5 게이트를 위해 정규화할 것인가, 축 3 근거로 그대로 둘 것인가?
- 축 6 도달성: `reachapp.false_unreachable` 2 <!-- fact:reachapp.false_unreachable -->/`reachapp.cases` 3 <!-- fact:reachapp.cases -->(prefix 불일치·프레임워크 활성화 케이스)에 대해 spec §13.1 우선 1위 후보(도달성 전제조건 검사)를 다음 사이클 착수 대상으로 확정하는가?
- 축 7 GT-A differential: `8428e646`에서 `mybatis-sqli-identifier`가 `LgCarrierMapper.xml`에 8 <!-- fact:gta.CWE-89.LgCarrierMapper.fixed_residual -->건, `OldLgCarrierMapper.xml`에 5 <!-- fact:gta.CWE-89.OldLgCarrierMapper.fixed_residual -->건 잔존 — 룰 범위인가, 수정 범위인가, GT-A 기대 정의인가?
- 새 초과분: `sca.extras.unclassified` 0 <!-- fact:sca.extras.unclassified -->건 — 없음(`extras-triage.json` overrides: [], needs_human: [] 를 플랜 1 그대로 승계).

## 백로그(P1 → P2)

spec §9 V7 순서(안전성 → 재현성 → FN)로 gate.md ✗ 축을 나열한다.

**안전성**

- 축 6 도달성 false-unreachable — fact: `reachapp.false_unreachable` 2 <!-- fact:reachapp.false_unreachable -->/`reachapp.cases` 3 <!-- fact:reachapp.cases -->. 관련 문서: `reach-app.md`.
- exit code 결함(spec §13.3)은 V4 에서 해소됨을 fidelity 로 확인 — fact: `fidelity.disposition_mismatch` 0 <!-- fact:fidelity.disposition_mismatch -->, `fidelity.exit_code` 1 <!-- fact:fidelity.exit_code -->. 관련 문서: `fidelity.md`.

**재현성**

- 입력면 mssql 이중 항목 — fact: `surface.gt_match_jar` 15/16 <!-- fact:surface.gt_match_jar -->, `surface.version_differs` 1 <!-- fact:surface.version_differs -->. 관련 문서: `input-surface.md`.
- 재입력 gitignore 미적용 — 재입력 9종 증거의 `meta.reinput_note` 그대로 인용(예: `docs/verification/evidence/2026-09-06/29bfb5ba-standard/meta.json`):
  ```
  raw 재입력 — 스캐너 미재실행, .gitignore 제외 미적용, 도달성은 V1 판정 carry-over
  ```

**FN**

- dev-found 미탐 9 — fact: `sca.missed` 9 <!-- fact:sca.missed -->, `sca.missed_by_stage.scanner` 9 <!-- fact:sca.missed_by_stage.scanner -->. 관련 문서: `gt-b-match.md`.
- GT-A CWE-89 잔존 — fact: `gta.CWE-89.LgCarrierMapper.fixed_residual` 8 <!-- fact:gta.CWE-89.LgCarrierMapper.fixed_residual -->건, `gta.CWE-89.OldLgCarrierMapper.fixed_residual` 5 <!-- fact:gta.CWE-89.OldLgCarrierMapper.fixed_residual -->건. 관련 문서: `gt-a-differential.md`.

spec §13.1 LLM 개입 후보 표의 우선 1위(도달성 전제조건 검사)를 다음 사이클 1순위로 기록한다(spec 이 정한 순위, 이 문서의 판단이 아니다) — message-gate 사람 판정 34 <!-- fact:human.verdict_rows -->행(고유 advisory 24 <!-- fact:human.verdict_advisories -->건) 전건이 이 유형이며, spec §13.1 근거란은 "축 6 이 'config-gated = unknown' 으로 끝나면 다음 사이클 1순위"라고 명시한다.

## 축 9 — 측정 사실성 (정본 검증)

`docs/verification/results/2026-09-06/reconcile-report.md` 판정 줄 인용:

```
## 판정: ✓ 통과
```

`facts-reconcile.json` 값 마커 인용(가능한 id 만 — `reconcile.regen_mismatch`·`marker_mismatch`·`unmarked`·`provenance_violations`·`quote_mismatch` 는 이 문서 자신을 대상으로 하는 `--measurement` 실행이 방금 재계산한 값이라 이 문서 안에서 인용하면 자기참조가 된다(reconcile.py 의 `load_facts` 가 `facts-reconcile.json` 을 로드에서 제외하는 이유와 동일) — 값은 위 판정 줄과 `reconcile-report.md` 본문을 참조): raw_count 38 <!-- fact:reconcile.raw_count --> · typed_count 38 <!-- fact:reconcile.typed_count -->.
