# GT-A differential — 범주 내 2/4 PASS

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