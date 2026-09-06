# 게이트 (생성 문서 — spec §5 상수 vs facts*.json, tools/verify/gate.py)

판정 열은 생성기 출력이다(정오표 (g)). 게이트 미통과는 캠페인 실패가 아니라 백로그 P1 등록 사유(spec §5).

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

## 요약
- 통과: 3 SCA known-FP(mssql-jdbc CVE-2025-59250), 4 SCA 초과분 분류, 8 보고서 충실성
- 미통과(백로그 P1): 2 SCA recall(GT-B 대비), 5 입력면 교차, 6 도달성, 7 GT-A differential(범주 내)
- 기록만: 1 프로파일 계약, 9 측정 사실성
- 미측정: 없음
