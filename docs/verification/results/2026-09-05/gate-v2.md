# 게이트 V2 (정본: facts.json, facts-profile.json, facts-knownfp.json)

인용 출처: `docs/verification/results/2026-09-05/facts.json`, `docs/verification/results/2026-09-05/facts-profile.json`, `docs/verification/results/2026-09-05/facts-knownfp.json`, `docs/verification/results/2026-09-05/known-fp.md`, `docs/verification/results/2026-09-05/profile-contract.md`, `docs/verification/results/2026-09-05/gt-b-match.md`.

| 축 | 기준(spec §5) | 측정값 | 판정 |
|---|---|---|---|
| 1 프로파일 계약 | 드리프트 전건 문서화 + spec 갱신 백로그 | profile-contract.md 행 수 4 <!-- fact:profile.rows --> · 드리프트 3 <!-- fact:profile.drift --> (모두 `osv-scanner` 누락) — 전건 표에 기록됨 | ✓ (문서화됨) |
| 2 SCA recall | CVE 단위 GT-B 합산 ≥ 44/46, HIGH/Important 미탐 ≤ 1, 미탐 전건 단계 특정(origin 별 병기 필수) | 합산 37/46 <!-- fact:sca.recall_cve --> · team 34/34 <!-- fact:sca.recall_cve.team --> · dev-found 3/12 <!-- fact:sca.recall_cve.dev-found --> · HIGH/Important 미탐 3 <!-- fact:sca.missed_high_important --> (미탐 9 <!-- fact:sca.missed -->건 전체 목록·origin 은 gt-b-match.md 참조; 단계별: scanner 9 <!-- fact:sca.missed_by_stage.scanner --> · normalize 0 <!-- fact:sca.missed_by_stage.normalize -->) | ✗ → 백로그 P1 후보 |
| 3 known-FP | 3단계(component_present/version_preserved/not_reported) 모두 True | known-fp.md 참조 — component_present: True <!-- fact:knownfp.component_present --> · version_preserved: True <!-- fact:knownfp.version_preserved --> · not_reported: True <!-- fact:knownfp.not_reported --> (found_version: 13.2.1.jre11 <!-- fact:knownfp.found_version -->) | ✓ |
| 4 초과분 | 미분류 0 | 초과 1 <!-- fact:sca.extras --> · inventory-diff 1 <!-- fact:sca.extras.inventory-diff --> · 미분류 0 <!-- fact:sca.extras.unclassified --> | ✓ |

축 1 의 `profile.rows`/`profile.drift` 는 `profile_contract.collect_facts()` 가 `compare_profiles()` 의
missing/extra 리스트에서 직접 계산한다(렌더된 마크다운을 되파싱하지 않음) — `facts-profile.json` 참조.

## 요약

- 통과: 축 1(문서화 기준), 축 3(known-FP), 축 4(초과분 전건 분류).
- 미통과: 축 2(SCA recall) — CVE 합산 recall 37/46 <!-- fact:sca.recall_cve --> 이 기준(spec §5: ≥ 44/46) 미달, HIGH/Important 미탐 3 <!-- fact:sca.missed_high_important -->건이 기준(spec §5: ≤ 1건) 초과. spec §5에 따라 캠페인 실패가 아니라 백로그 P1 등록 사유.
