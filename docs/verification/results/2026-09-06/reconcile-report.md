# 정본 검증 (spec §4.5 · 축 9)

## 생성 문서 재생성 비교
| 문서 | 일치 | 비고 |
|---|---|---|
| gt-b-match.md | ✓ |  |
| facts.json | ✓ |  |
| gt-a-differential.md | ✓ |  |
| facts-gta.json | ✓ |  |
| known-fp.md | ✓ |  |
| facts-knownfp.json | ✓ |  |
| profile-contract.md | ✓ |  |
| facts-profile.json | ✓ |  |
| input-surface.md | ✓ |  |
| facts-surface.json | ✓ |  |
| fidelity.md | ✓ |  |
| facts-fidelity.json | ✓ |  |
| reach-app.md | ✓ |  |
| facts-reachapp.json | ✓ |  |
| gate.md | ✓ |  |
| README.md | ✓ |  |

## fact 마커 대조
| 문서 | id | 문서값 | 정본값 | 일치 |
|---|---|---|---|---|
| gate.md | profile.rows | 4 | 4 | ✓ |
| gate.md | profile.drift | 3 | 3 | ✓ |
| gate.md | sca.recall_cve | 37/46 | 37/46 | ✓ |
| gate.md | sca.recall_cve.team | 34/34 | 34/34 | ✓ |
| gate.md | sca.recall_cve.dev-found | 3/12 | 3/12 | ✓ |
| gate.md | sca.missed | 9 | 9 | ✓ |
| gate.md | sca.missed_high_important | 3 | 3 | ✓ |
| gate.md | sca.missed_by_stage.scanner | 9 | 9 | ✓ |
| gate.md | sca.missed_by_stage.normalize | 0 | 0 | ✓ |
| gate.md | knownfp.component_present | True | True | ✓ |
| gate.md | knownfp.version_preserved | True | True | ✓ |
| gate.md | knownfp.not_reported | True | True | ✓ |
| gate.md | knownfp.found_version | 13.2.1.jre11 | 13.2.1.jre11 | ✓ |
| gate.md | sca.extras | 1 | 1 | ✓ |
| gate.md | sca.extras.unclassified | 0 | 0 | ✓ |
| gate.md | surface.bom_only | 77 | 77 | ✓ |
| gate.md | surface.jar_only | 9 | 9 | ✓ |
| gate.md | surface.version_differs | 1 | 1 | ✓ |
| gate.md | surface.gt_match_bom | 16/16 | 16/16 | ✓ |
| gate.md | surface.gt_match_jar | 15/16 | 15/16 | ✓ |
| gate.md | reachapp.cases | 3 | 3 | ✓ |
| gate.md | reachapp.false_unreachable | 2 | 2 | ✓ |
| gate.md | reach.reachable | 0 | 0 | ✓ |
| gate.md | reach.unreachable | 48 | 48 | ✓ |
| gate.md | reach.unknown | 0 | 0 | ✓ |
| gate.md | gta.in_category_pass | 2/4 | 2/4 | ✓ |
| gate.md | fidelity.roundtrip_identical | True | True | ✓ |
| gate.md | fidelity.id_set_mismatch | 0 | 0 | ✓ |
| gate.md | fidelity.disposition_mismatch | 0 | 0 | ✓ |
| gate.md | fidelity.deterministic | True | True | ✓ |
| gate.md | fidelity.meta_scanner_status_rows | 3 | 3 | ✓ |
| gate.md | fidelity.undecided | 0 | 0 | ✓ |
| measurement | profile.rows | 4 | 4 | ✓ |
| measurement | profile.drift | 3 | 3 | ✓ |
| measurement | sca.recall_cve | 37/46 | 37/46 | ✓ |
| measurement | sca.recall_cve.team | 34/34 | 34/34 | ✓ |
| measurement | sca.recall_cve.dev-found | 3/12 | 3/12 | ✓ |
| measurement | sca.missed | 9 | 9 | ✓ |
| measurement | sca.missed_high_important | 3 | 3 | ✓ |
| measurement | sca.missed_by_stage.scanner | 9 | 9 | ✓ |
| measurement | sca.missed_by_stage.normalize | 0 | 0 | ✓ |
| measurement | knownfp.component_present | True | True | ✓ |
| measurement | knownfp.version_preserved | True | True | ✓ |
| measurement | knownfp.not_reported | True | True | ✓ |
| measurement | knownfp.found_version | 13.2.1.jre11 | 13.2.1.jre11 | ✓ |
| measurement | sca.extras | 1 | 1 | ✓ |
| measurement | sca.extras.unclassified | 0 | 0 | ✓ |
| measurement | surface.bom_only | 77 | 77 | ✓ |
| measurement | surface.jar_only | 9 | 9 | ✓ |
| measurement | surface.version_differs | 1 | 1 | ✓ |
| measurement | surface.gt_match_bom | 16/16 | 16/16 | ✓ |
| measurement | surface.gt_match_jar | 15/16 | 15/16 | ✓ |
| measurement | reachapp.cases | 3 | 3 | ✓ |
| measurement | reachapp.false_unreachable | 2 | 2 | ✓ |
| measurement | reach.reachable | 0 | 0 | ✓ |
| measurement | reach.unreachable | 48 | 48 | ✓ |
| measurement | reach.unknown | 0 | 0 | ✓ |
| measurement | gta.in_category_pass | 2/4 | 2/4 | ✓ |
| measurement | fidelity.roundtrip_identical | True | True | ✓ |
| measurement | fidelity.id_set_mismatch | 0 | 0 | ✓ |
| measurement | fidelity.disposition_mismatch | 0 | 0 | ✓ |
| measurement | fidelity.deterministic | True | True | ✓ |
| measurement | fidelity.meta_scanner_status_rows | 3 | 3 | ✓ |
| measurement | fidelity.undecided | 0 | 0 | ✓ |
| measurement | profile.rows | 4 | 4 | ✓ |
| measurement | profile.drift | 3 | 3 | ✓ |
| measurement | sca.recall_cve | 37/46 | 37/46 | ✓ |
| measurement | sca.recall_cve.dev-found | 3/12 | 3/12 | ✓ |
| measurement | sca.recall_cve.team | 34/34 | 34/34 | ✓ |
| measurement | sca.recall_entry_strict | 47/56 | 47/56 | ✓ |
| measurement | sca.recall_entry_loose | 47/56 | 47/56 | ✓ |
| measurement | sca.missed | 9 | 9 | ✓ |
| measurement | sca.missed_high_important | 3 | 3 | ✓ |
| measurement | sca.extras | 1 | 1 | ✓ |
| measurement | sca.extras.inventory-diff | 1 | 1 | ✓ |
| measurement | sca.extras.unclassified | 0 | 0 | ✓ |
| measurement | surface.jar_ok | True | True | ✓ |
| measurement | surface.bom_packages | 195 | 195 | ✓ |
| measurement | surface.jar_packages | 127 | 127 | ✓ |
| measurement | surface.vuln_rows_gt | 48 | 48 | ✓ |
| measurement | surface.bom_only | 77 | 77 | ✓ |
| measurement | surface.jar_only | 9 | 9 | ✓ |
| measurement | surface.version_differs | 1 | 1 | ✓ |
| measurement | surface.vuln_rows_gt | 48 | 48 | ✓ |
| measurement | surface.gt_match_bom | 16/16 | 16/16 | ✓ |
| measurement | surface.gt_match_jar | 15/16 | 15/16 | ✓ |
| measurement | human.verdict_rows | 34 | 34 | ✓ |
| measurement | human.verdict_advisories | 24 | 24 | ✓ |
| measurement | reachapp.cases | 3 | 3 | ✓ |
| measurement | reachapp.false_unreachable | 2 | 2 | ✓ |
| measurement | reachapp.reachable_expected_hit | 1/1 | 1/1 | ✓ |
| measurement | reach.unknown | 0 | 0 | ✓ |
| measurement | findings.sca | 48 | 48 | ✓ |
| measurement | reach.reachable | 0 | 0 | ✓ |
| measurement | findings.sca | 48 | 48 | ✓ |
| measurement | reach.unreachable | 48 | 48 | ✓ |
| measurement | findings.sca | 48 | 48 | ✓ |
| measurement | gta.CWE-259.LoadtestSeederConfig.passed | True | True | ✓ |
| measurement | gta.CWE-259.LoadtestSeederConfig.fixed_residual | 0 | 0 | ✓ |
| measurement | gta.CWE-760.LoadtestSeederConfig.passed | True | True | ✓ |
| measurement | gta.CWE-760.LoadtestSeederConfig.fixed_residual | 0 | 0 | ✓ |
| measurement | gta.CWE-89.LgCarrierMapper.passed | False | False | ✓ |
| measurement | gta.CWE-89.LgCarrierMapper.fixed_residual | 8 | 8 | ✓ |
| measurement | gta.CWE-89.OldLgCarrierMapper.passed | False | False | ✓ |
| measurement | gta.CWE-89.OldLgCarrierMapper.fixed_residual | 5 | 5 | ✓ |
| measurement | gta.in_category_pass | 2/4 | 2/4 | ✓ |
| measurement | gta.CWE-489.application.observed | 없음 | 없음 | ✓ |
| measurement | gta.CWE-497.TestDbReset.observed | 없음 | 없음 | ✓ |
| measurement | fidelity.roundtrip_identical | True | True | ✓ |
| measurement | fidelity.id_set_mismatch | 0 | 0 | ✓ |
| measurement | fidelity.disposition_mismatch | 0 | 0 | ✓ |
| measurement | fidelity.exit_code | 1 | 1 | ✓ |
| measurement | fidelity.deterministic | True | True | ✓ |
| measurement | fidelity.undecided | 0 | 0 | ✓ |
| measurement | fidelity.meta_scanner_status_rows | 3 | 3 | ✓ |
| measurement | fidelity.actionable.findings | 14 | 14 | ✓ |
| measurement | attrition.disposition | 73 | 73 | ✓ |
| measurement | attrition.merge | 75 | 75 | ✓ |
| measurement | sca.missed | 9 | 9 | ✓ |
| measurement | profile.drift | 3 | 3 | ✓ |
| measurement | surface.gt_match_jar | 15/16 | 15/16 | ✓ |
| measurement | reachapp.false_unreachable | 2 | 2 | ✓ |
| measurement | reachapp.cases | 3 | 3 | ✓ |
| measurement | gta.CWE-89.LgCarrierMapper.fixed_residual | 8 | 8 | ✓ |
| measurement | gta.CWE-89.OldLgCarrierMapper.fixed_residual | 5 | 5 | ✓ |
| measurement | sca.extras.unclassified | 0 | 0 | ✓ |
| measurement | reachapp.false_unreachable | 2 | 2 | ✓ |
| measurement | reachapp.cases | 3 | 3 | ✓ |
| measurement | fidelity.disposition_mismatch | 0 | 0 | ✓ |
| measurement | fidelity.exit_code | 1 | 1 | ✓ |
| measurement | surface.gt_match_jar | 15/16 | 15/16 | ✓ |
| measurement | surface.version_differs | 1 | 1 | ✓ |
| measurement | sca.missed | 9 | 9 | ✓ |
| measurement | sca.missed_by_stage.scanner | 9 | 9 | ✓ |
| measurement | gta.CWE-89.LgCarrierMapper.fixed_residual | 8 | 8 | ✓ |
| measurement | gta.CWE-89.OldLgCarrierMapper.fixed_residual | 5 | 5 | ✓ |
| measurement | human.verdict_rows | 34 | 34 | ✓ |
| measurement | human.verdict_advisories | 24 | 24 | ✓ |
| measurement | reconcile.raw_count | 38 | 38 | ✓ |
| measurement | reconcile.typed_count | 38 | 38 | ✓ |

## 출처 불명 수치(마커 없음)
- 없음

## 표 검사 범위(M6 — 값 열 없는 표는 출처 불명 검사에서 빠진다)
- gate.md: 검사 대상 표 1 / 값 열 없는 표 0
- measurement: 검사 대상 표 1 / 값 열 없는 표 0

## 인용 표 대조(spec §4.5 (f))
| 인용 | 원본 | 일치 |
|---|---|---|
| \| 축 \| 기준(spec §5) \| 측정값 \| 판정 \| | gate.md | ✓ |
| \| 프로파일 \| spec §8 \| 구현 \| 누락 \| 초과 \| 실제 status \| | profile-contract.md | ✓ |
| \| 단계 \| 건수 \| 증감 \| | gt-b-match.md | ✓ |
| \| 단계 \| 건수 \| 증감 \| | gt-b-match.md | ✓ |
| \| advisory \| 패키지 \| 설치 \| 심각도(보안팀) \| origin \| 단계 \| | gt-b-match.md | ✓ |
| \| advisory \| 패키지 \| 설치 \| 분류 \| | gt-b-match.md | ✓ |
| \| 단계 \| 결과 \| | known-fp.md | ✓ |
| \| 패키지 \| 보안팀 \| BOM \| jar \| | input-surface.md | ✓ |
| \| 케이스 \| 패키지 \| CVE \| 현 엔진 판정 \| 기대 충족 \| | reach-app.md | ✓ |
| \| CWE \| 분류 \| 파일 \| 룰 \| 취약에서 출현 \| 수정에서 소멸 \| tier(기대) \| 판정 \| | gt-a-differential.md | ✓ |
| \| 검사 \| 값 \| | fidelity.md | ✓ |
| \| 포맷 \| id 수 \| findings.json 과 동일 \| | fidelity.md | ✓ |
| \| 포맷 \| actionable 수 \| findings.json 과 동일 \| | fidelity.md | ✓ |

## override provenance
- override 없음

## raw↔typed 카디널리티 (a483b3b1-standard)
- raw trivy 고유 VulnerabilityID: 38
- typed SCA 고유 advisory: 38
- raw 에만: 없음
- typed 에만: 없음

## 판정: ✓ 통과
