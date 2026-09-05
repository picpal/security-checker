# 게이트 V3 (정본: facts.json, facts-gta.json)

인용 출처: `docs/verification/results/2026-09-05/facts.json`, `docs/verification/results/2026-09-05/facts-gta.json`, `docs/verification/results/2026-09-05/gt-b-match.md`, `docs/verification/results/2026-09-05/gt-a-differential.md`, `tests/test_reach_app.py`.

| 축 | 기준(spec §5) | 측정값 | 판정 |
|---|---|---|---|
| 6(a) 도달성 판정 근거 비교표 | 일치율은 산출하지 않음 — 판정 방법이 다름(우리: 패키지 prefix 존재 / 사람: CVE 별 활성화 조건) | `gt-b-match.md` 하단 "사람 도달성 판정 비교" 표 참조(18건, advisory×패키지) | 기록(게이트 없음) |
| 6(b) false-unreachable(`fixtures/reach-app`) | **false-unreachable = 0**(프레임워크 활성화 케이스 포함) | `tests/test_reach_app.py` xfail(strict) 2건 — 아래 pytest 코드블록 참조 | ✗ → 백로그 P1 |
| 6(c) 증거의 SCA 도달성 분포 | 게이트 없음(부수 측정 — unknown 기권 비율) | reach.reachable 0 <!-- fact:reach.reachable --> · reach.unreachable 48 <!-- fact:reach.unreachable --> · reach.unknown 0 <!-- fact:reach.unknown --> · findings.sca 48 <!-- fact:findings.sca --> | 기록 |
| 7 GT-A differential(범주 내) | 범주 내 출현·소멸 100% | gta.in_category_pass 2/4 <!-- fact:gta.in_category_pass --> | ✗ → 백로그 P1 후보 |
| 7 measure-then-classify | 결과 기록만(게이트 없음) | CWE-489 관측 없음 <!-- fact:gta.row4.CWE-489.observed --> · CWE-497 관측 없음 <!-- fact:gta.row5.CWE-497.observed --> | 기록 |

## 축 6(b) — pytest -v 출력(`tests/test_reach_app.py`, 4건)

```
tests/test_reach_app.py::test_vulnerable_api_use_is_reachable PASSED     [ 25%]
tests/test_reach_app.py::test_used_library_with_mismatched_prefix_must_not_be_unreachable XFAIL [ 50%]
tests/test_reach_app.py::test_framework_activated_library_must_not_be_unreachable XFAIL [ 75%]
tests/test_reach_app.py::test_current_engine_false_unreachable_modes_documented PASSED [100%]
```

xfail(strict) 2건: `test_used_library_with_mismatched_prefix_must_not_be_unreachable`(prefix 불일치) · `test_framework_activated_library_must_not_be_unreachable`(프레임워크 활성화).

## 축 6(c) — unknown 기권 비율 계산식

`reach.unknown / findings.sca` = 0 <!-- fact:reach.unknown --> / 48 <!-- fact:findings.sca --> = 0.0%. `reach.reachable / findings.sca` = 0 <!-- fact:reach.reachable --> / 48 <!-- fact:findings.sca --> = 0.0%. `reach.unreachable / findings.sca` = 48 <!-- fact:reach.unreachable --> / 48 <!-- fact:findings.sca --> = 100.0%.

## 축 7 — GT-A differential 행별 판정(범주 내 4행)

| # | CWE | 파일 | passed | fixed_residual |
|---|---|---|---|---|
| row0 | CWE-259 | LoadtestSeederConfig.java | True <!-- fact:gta.row0.CWE-259.passed --> | 0 <!-- fact:gta.row0.CWE-259.fixed_residual --> |
| row1 | CWE-760 | LoadtestSeederConfig.java | True <!-- fact:gta.row1.CWE-760.passed --> | 0 <!-- fact:gta.row1.CWE-760.fixed_residual --> |
| row2 | CWE-89 | LgCarrierMapper.xml | False <!-- fact:gta.row2.CWE-89.passed --> | 8 <!-- fact:gta.row2.CWE-89.fixed_residual --> |
| row3 | CWE-89 | OldLgCarrierMapper.xml | False <!-- fact:gta.row3.CWE-89.passed --> | 5 <!-- fact:gta.row3.CWE-89.fixed_residual --> |

전체 표는 `gt-a-differential.md` 참조(measure-then-classify·out-of-category 행 포함).

## 요약

- 통과: 없음(축 6·7 모두 미통과).
- 미통과: 축 6(b) false-unreachable — xfail(strict) 2건이 기준(spec §5: false-unreachable = 0) 미달. spec §11: "도달성 축 6 은 현 엔진이 게이트를 통과하지 못할 가능성이 높다. 이는 캠페인의 결과이지 실패가 아니다."
- 미통과: 축 7 GT-A differential(범주 내) — gta.in_category_pass 2/4 <!-- fact:gta.in_category_pass --> 가 기준(spec §5: 범주 내 출현·소멸 100%) 미달. row2·row3(CWE-89, `#305`)이 FAIL — fixed_residual 8건·5건(위 표).
- 기록만(게이트 없음): 축 6(a) 판정 근거 비교표, 축 6(c) 도달성 분포, 축 7 measure-then-classify 2행.
- spec §5에 따라 캠페인 실패가 아니라 백로그 P1 등록 사유.

## needs_human

- `8428e646`에서 `mybatis-sqli-identifier`가 `LgCarrierMapper.xml`에 8건 <!-- fact:gta.row2.CWE-89.fixed_residual -->, `OldLgCarrierMapper.xml`에 5건 <!-- fact:gta.row3.CWE-89.fixed_residual --> 잔존 — 룰 범위인가, 수정 범위인가, GT-A 기대 정의인가?
