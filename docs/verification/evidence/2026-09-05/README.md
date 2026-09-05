# 증거 동결 2026-09-05 — 현행 바이너리(커밋 bc20cd3)

message-gate(`/Users/picpal/Desktop/workspace/message-gate`) 실스캔 결과를 스냅샷별로 동결한 기록. 하네스는 `tools.verify.run_snapshot`(Task 5 산출물), 격리는 스냅샷별 `<scratch>/<sha>/` 클론 + 전용 `GRADLE_USER_HOME` + 크리덴셜 환경변수 제거 + secret 검증 `never`.

## 1차 실행 실패 및 환경 준비 (기록용)

1차 `a483b3b1-standard` 실행(04:09~04:35, `elapsed_s=1543.0`)은 trivy 가 900초 만에 타임아웃했다. 원인은 로컬 trivy DB(2026-08-06)가 오래되어 최초 스캔 시 trivy 가 자동으로 취약점 DB(대용량 Java DB 포함)를 내려받으려 했기 때문이며, BOM 생성(cdxgen) 자체는 정상(15초 만에 196개 컴포넌트, mssql 13.2.1.jre11·tomcat 11.0.22 보존)이었다. 같은 실행에서 도달성도 `reason=error` 로 실패했는데, 이는 depscan 이 엔진 예산 내에 사용처(usage) 슬라이스 산출을 마치지 못한 것으로, 엔진이 예외를 삼키고 `reason` 만 남기는 동작이다(백로그 후보로 별도 기록 필요).

컨트롤러가 측정 파이프라인 외부에서 다음 두 가지를 준비했다(하네스·제품 코드는 무변경, HEAD bc20cd3 그대로):

- **trivy DB 사전 다운로드**: Vulnerability DB `UpdatedAt 2026-09-05 01:12:13 UTC`, Java DB `UpdatedAt 2026-09-05 01:05:40 UTC` (다운로드 소요 약 251초). 재실행 시 캐시된 BOM 에 대한 `trivy sbom` 은 약 0초.
- **도달성 캐시 선(先)생성**: 동일 격리 환경에서 depscan 을 직접 실행해 `<scratch>/a483b3b1/reach/9b78b0a3cb422e72/java-usages.slices.json`(3.1MB, 1405 objectSlices)을 생성. 하네스의 `DepscanUsageProvider` 는 이 캐시를 재사용하므로 depscan 재실행 없이 도달성이 정상 처리됨.

1차 실패 결과물은 증거 디렉토리에서 제외하고 `/private/tmp/secscan-verify/logs/run1-timeout/a483b3b1-standard/` 로 보존했다(본 커밋에는 포함되지 않음).

trivy DB 시점(스캔 전 → 스캔 후):

| | Vulnerability DB UpdatedAt | Java DB UpdatedAt |
|---|---|---|
| 사전(1차 실행 전) | 2026-08-06 13:26:59 UTC | 2026-08-06 01:19:35 UTC |
| 사후(컨트롤러 준비 이후, 2차 실행부터 사용) | 2026-09-05 01:12:13 UTC | 2026-09-05 01:05:40 UTC |

## 스냅샷 결과

| 디렉토리 | 스냅샷 | 프로파일 | 스캐너 status | findings | 비고 |
|---|---|---|---|---|---|
| a483b3b1-standard | GT-B 취약(보안팀 스캔 2026-08-31 대응) | standard | trivy ok · gitleaks ok · semgrep ok | 73 | 도달성 ran=True, reason=ok (선생성 캐시 재사용). elapsed_s=8.5(재실행) |
| a483b3b1-deep | GT-B 취약 | deep | trivy ok · gitleaks ok · semgrep ok · spotbugs ok | 483 | `--no-reachability`(reason=off). elapsed_s=19.0 |
| 29bfb5ba-standard | GT-A CWE-259(#264)·CWE-489(#263) 취약(수정 커밋의 부모) | standard | gitleaks ok · semgrep ok · trivy ok | 85 | 도달성 off(`--no-reachability`). elapsed_s=42.9 |
| 72e49a1b-standard | GT-A CWE-259(#264) 수정 — LoadtestSeederConfig 하드코딩 암호 외부화 | standard | gitleaks ok · semgrep ok · trivy ok | 84 | 도달성 off. elapsed_s=32.6 |
| d4a1ded0-standard | GT-A CWE-760(#266) 취약(수정 커밋의 부모) — LoadtestSeederConfig zero-salt | standard | gitleaks ok · semgrep ok · trivy ok | 86 | 도달성 off. elapsed_s=34.1 |
| 55e58bc6-standard | GT-A CWE-760(#266) 수정 — SecureRandom 계정별 랜덤 솔트 | standard | gitleaks ok · semgrep ok · trivy ok | 85 | 도달성 off. elapsed_s=33.1 |
| 1052b80d-standard | GT-A CWE-89(#305, LgCarrierMapper/OldLgCarrierMapper.xml)·CWE-497·CWE-676(#303, TestDbReset.java) 취약(수정 커밋의 부모) | standard | gitleaks ok · semgrep ok · trivy ok | 82 | 도달성 off. elapsed_s=32.5 |
| 8428e646-standard | GT-A CWE-89(#305) 수정 — 월별 로그 테이블명 `${}` SQL 인젝션 방어 강화 | standard | gitleaks ok · semgrep ok · trivy ok | 87 | 도달성 off. elapsed_s=31.4 |
| 5895c9f4-standard | GT-A CWE-489(#263) 수정 — management 포트 인증 강화 | standard | gitleaks ok · semgrep ok · trivy ok | 85 | 도달성 off. elapsed_s=36.2 |
| 81f4f31b-standard | GT-A CWE-497·CWE-676(#303) 수정 — TestDbReset 리소스정리+자격증명 마스킹 | standard | gitleaks ok · semgrep ok · trivy ok | 82 | 도달성 off. elapsed_s=30.9 |

10개 스냅샷 전부 `scanner_status` 전 도구 `ok`, `partial_failures` 없음(부분 실패 0건). `excluded_count` 전부 0.

- 도구 버전: 각 디렉토리 `meta.json` 의 `tool_versions` 참조(trivy 0.71.2, cdxgen 12.7.0, semgrep 1.168.0, gitleaks 8.30.1, depscan 6.2.0, spotbugs 4.10.2, java 21.0.10 Corretto, gradle 9.5.1). trivy DB 시점은 위 표 참조.
- 격리: 스냅샷별 `<scratch>/<sha>/`, `GRADLE_USER_HOME` 분리, 크리덴셜 환경변수 제거, secret 검증 `never`.
- 비밀값 누출 검사(Step 6): gitleaks raw 10개 파일 전부 `"Secret"`·`"Match"` 필드 `<redacted>` 처리 확인, 비redaction 값 0건, private key 본문 0건.
- 증거 총 용량: 8.3MB (최대 파일 `a483b3b1-deep/findings.sarif` 512KB).
- 이 증거는 V4(모델 변경) 이후 회귀 입력으로 재사용한다(spec §4.4).
