# 검증 캠페인(V) 설계 — message-gate 정답지 대조 + xlsx 출력

- 작성: 2026-09-04
- 상태: 설계 승인(브레인스토밍 + Codex 독립 검토 반영). 구현 계획은 별도 문서.
- 근거 문서: `2026-06-26-jvm-security-scanner-design.md`(원 spec, 최우선), `docs/measurements/2026-06-28-gap-map.md`, `2026-09-04-verification-campaign-codex-review.md`(Codex 검토 원문)

---

## 1. 목적

secscan 의 각 탐지 프로세스(SCA·도달성·Secret·SAST·deep·병합·억제·컴플라이언스·출력)가
실프로젝트 **message-gate** 에서 실제로 무엇을 잡고 무엇을 놓치는지를 **재현 가능한 수치**로
남기고, 갭을 **우선순위가 붙은 보완 백로그**로 만든다. 동시에 보안팀 워크플로(Excel 교환)에
맞춰 스캔 산출물에 **xlsx 출력**을 추가한다.

원 spec §10.3 은 "의도적 취약 픽스처로 precision/recall 회귀 측정"만 규정한다. 이 캠페인은
거기에 **외부 감사자가 만든 정답지**(보안팀 SCA 점검 + 외부 소스코드 점검)를 더한다.

## 2. 범위 / 비범위

**범위**
1. 정답지 매니페스트 2종(GT-A 소스, GT-B SCA) + 보안팀 시트 스키마 골든
2. 측정 하네스(`tools/verify/`) + `run_scan` 단계 추적기 + `measure.match_ground_truth`
3. 측정 8축(§5)과 게이트, 측정 문서 `docs/measurements/2026-09-xx-message-gate-verification.md`
4. 모델·출력 확장: occurrences / CVSS source map / 스캐너 status 메타 / `findings.json`(lossless) / 포맷별 projection 계약
5. **판정 단계(H) 신설**(§7.4): disposition·tier·compliance 를 한 곳에서 계산해 Finding 에 저장, exit code 와 모든 출력이 그 필드만 읽음
6. xlsx 출력 어댑터(`secscan/output/xlsx.py`, openpyxl extra, CSV 폴백)
7. 변이 픽스처(도달성 쌍·secret 3종·전이 CVE·억제 전이·gradlew/빌드실패)
8. 우선순위 백로그(§13 에 초기 항목)

**비범위**
- 측정에서 드러난 갭의 **수정**(별도 사이클, 갭 지도 → D 와 같은 방식). 단 §7 의 모델·출력 확장은 이 캠페인의 전제이므로 포함.
- Claude 해석층(비결정적, 원칙 2). 자연어 시연은 검증 대상이 아니다.
- 백로그 항목(IaC/DAST/CI/주기점검/Opengrep/CodeQL/LSP).
- 2026-08-31 보안팀 스캔의 **역사적 재현**(당시 DB·raw JSON 부재로 불가 — §4.3). "현재 유효성" 측정으로 대체.

## 3. 대상과 정답지

### 3.1 message-gate 사실

| 항목 | 값 |
|---|---|
| 스택 | Spring Boot 4.0.x / Java 21 / Gradle wrapper 9.3.1 / MyBatis / Java 392 파일 / 락파일 없음 |
| GT-B 취약 스냅샷 | `a483b3b1` (#629 수정 직전, 2026-09-02). Spring Boot 4.0.6, `tomcat.version=11.0.22`, mssql-jdbc 버전 미지정(BOM 결정) |
| GT-B 수정 커밋 | `4e896200` (Boot 4.0.8) → 병합 `565eed2` |
| GT-A 스냅샷 | `29bfb5ba`(CWE-259·489) / `d4a1ded0`(CWE-760) / `1052b80d`(#305 SQLi·CWE-676·497) / `00c7e34b`(CWE-476) |
| GT-A 수정 커밋 | `72e49a1b`(259) / `55e58bc6`(760) / `8428e646`(#305: `LgCarrierMapper.xml`·`OldLgCarrierMapper.xml`) / `5895c9f4`(489) / `81f4f31b`(676·497) / `b742368e`(476) |

### 3.2 GT-B — 보안팀 SCA 점검 (2026-08-31)

- 도구: **trivy 의 jar 분석기(rootfs 또는 image 모드)** 를 배포 jar 에 실행 → JSON 후처리 xlsx. (초안의 "trivy fs" 는 오기 — fs 모드는 jar 를 스캔하지 않음, 2026-09-05 실측. rootfs 실측에서 mssql-jdbc 가 `13.2.1`·`13.2.1.jre11` 두 항목으로 잡히고 CVE-2025-59250 이 `13.2.1` 에 붙어 보안팀 known-FP 가 정확히 재현됨 → 축 5 사실.) 근거: `Targets=Java`, `CVSS Source`(nvd/redhat/ghsa) 열, `Severity` 가 CVSS 순서와 무관(벤더 등급), `Finding Count`/`Deduped_CVEs` 집계.
- 원본 xlsx·JSON 은 **확보 불가**. 근거는 message-gate `docs/security/05_취약점조치내역_MessageGate.xlsx`(35행 전사) + `03_취약점조치결과_MessageGate.md` + 시트 사진(헤더 12개, 시트 4종).
- **분모 = 46** = 보안팀 35행(그중 1행은 known-FP) + 개발자 추가 발견 12(tomcat 11 + logback 1). 34/35 재현은 "기존 trivy 결과 재현율"이지 recall 이 아니다.
- known-FP: `CVE-2025-59250` mssql-jdbc — 스캐너가 설치 버전을 `13.2.1` 로 표기(실제 `13.2.1.jre11`, 수정 목록에 포함). 원인은 jar 버전 파싱으로 추정.
- 사람 도달성 판정 18건(jackson 6·log4j 1·tomcat 11·logback 1 = 전부 negative). 사유 분류: `config-gated`(HTTP/2·Realm·polymorphic typing·SiftingAppender) / `impl-absent`(log4j-core 없음) / `api-unused`(async parser). 나머지는 "개별 분석 미수행".

### 3.3 GT-A — 외부 소스코드 점검 (2026-06-19~23)

| 분류 | CWE | 기대 |
|---|---|---|
| 범주 내(사전 고정) | 259 하드코딩 / 760 zero-salt / 89(#305 MyBatis `${}`) | 커스텀 룰로 탐지. **회귀**(룰을 여기서 만들었으므로 일반화 증거 아님) |
| 측정 후 분류 | 489 활성 디버그(management 포트) / 497 자격증명 마스킹 | 기존 팩 탐지 여부를 측정하고 범주 내/외로 사후 확정. 분모 조정 금지 — 결과와 무관하게 표에 남긴다. (message-gate 의 `cwe-312-fix`·`cwe-314-fix` 브랜치는 이슈 번호 #312·#314 = CWE-476·489 이며 CWE-312/314 가 아님) |
| 범주 외(사전 고정) | 754 broad catch / 476 null / 397·398 / 676 | 코드 스멜·IDE 인스펙션 영역(갭 지도 결론). 측정하지 않고 "알려진 공백"으로 기재 |

### 3.4 매니페스트 형식 (`docs/verification/ground-truth/`)

`gt-b-sca.json` — 항목 단위 = advisory × 패키지 × 설치버전. 보안팀 행이 복수 패키지를 한 셀에 담은 경우(jackson 2.x/3.x)는 항목을 분리하되 `row` 로 원 행 번호를 보존한다.

```json
{
  "snapshot": "a483b3b1",
  "scan_date": "2026-08-31",
  "entries": [
    {"row": 3, "advisory": "CVE-2026-54512", "aliases": [], "package": "com.fasterxml.jackson.core:jackson-databind",
     "installed": "2.21.2", "fixed": ["2.18.8","2.21.4"], "severity_team": "HIGH", "cvss_max": 8.1, "cvss_source": "redhat",
     "origin": "team", "expected": "present",
     "human_verdict": "unreachable", "reason_class": "config-gated", "reason": "@JsonTypeInfo/activateDefaultTyping 0건"},
    {"row": 2, "advisory": "CVE-2025-59250", "package": "com.microsoft.sqlserver:mssql-jdbc", "installed": "13.2.1.jre11",
     "origin": "team", "expected": "absent", "note": "known-FP: 스캐너 버전 파싱"},
    {"row": null, "advisory": "CVE-2026-68763", "package": "org.apache.tomcat.embed:tomcat-embed-core", "installed": "11.0.22",
     "fixed": ["11.0.25"], "published": "2026-08-25", "origin": "dev-found", "expected": "present",
     "human_verdict": "unreachable", "reason_class": "config-gated", "reason": "HTTP/2 비활성"}
  ]
}
```

`gt-a-source.json` — 항목 단위 = (취약 스냅샷, 수정 커밋, 파일, 기대 룰 ID 또는 CWE, 기대 category, 기대 tier, 분류).

```json
{"entries": [
  {"cwe": "CWE-760", "vulnerable": "d4a1ded0", "fixed": "55e58bc6",
   "file": "src/main/java/.../LoadtestSeederConfig.java", "expected_rule": "secscan.zero-salt",
   "category": "sast", "expected_tier": "review", "tier_reason": "loadtest 경로 강등", "class": "in-category"},
  {"cwe": "CWE-489", "vulnerable": "29bfb5ba", "fixed": "5895c9f4", "file": "src/main/resources/application*.yml",
   "expected_rule": null, "category": null, "class": "measure-then-classify"}
]}
```

`golden/security-team-schema.json` — 시트 4종(`Summary`, `Findings`, `Deduped_CVEs`, `Targets`)과 `Deduped_CVEs` 헤더 12개: `No.`, `Vulnerability ID`, `Severity`, `Max CVSS Score`, `CVSS Source`, `Affected Packages`, `Installed Versions`, `Fixed Versions`, `Targets`, `Finding Count`, `Title`, `URL`. 사진 기준 재구성임을 파일 안에 명시한다.

## 4. 측정 하네스 (`tools/verify/`, 패키지 밖 개발 도구)

### 4.1 스냅샷 준비와 격리
- `git clone --local <message-gate> <scratch>/<snapshot>/repo && git checkout <sha>`. **스냅샷마다 새 디렉토리** — BOM 캐시 키가 대상 경로 해시라 같은 경로 재사용 시 stale BOM 을 쓴다(`secscan/sbom.py`). 백로그: content-addressed 키.
- 빌드는 임의 코드 실행이다("read-only" 표현 금지 → "격리 실행"). 별도 `GRADLE_USER_HOME`, 크리덴셜 환경변수 제거, secret 검증 OFF(`--network-off`), 의존성 다운로드용 네트워크만 허용.
- 스냅샷별 기록: 커밋, 도구 버전(trivy/cdxgen/semgrep/gitleaks/spotbugs/java/gradle), trivy DB `UpdatedAt`, Java DB 버전, 실행 명령, 소요 시간, 피크 메모리(`/usr/bin/time -l`).

### 4.2 단계 추적기 (제품 변경, 기본 무동작)
`run_scan(..., trace: TraceSink | None = None)`. 각 단계 뒤 `(stage, count, dedup_keys)` 를 기록: `raw:<tool>` → `normalize:<tool>` → `merge` → `exclude` → `compliance` → `reachability` → `secret_verify` → `baseline` → `suppress` → `final` (실제 `scan.py` 순서. 컴플라이언스는 도달성보다 앞서 항상 실행되고, SAST tier 는 파이프라인 단계가 아니라 출력 시 순수 함수로 계산된다). 하네스는 이를 **attrition 표**로 렌더해 "스캐너가 못 잡음" vs "정규화/제외가 버림"을 구분한다. `trace=None` 이면 동작·성능 변화 없음(테스트로 고정). V4 이후에는 `suppress` 뒤에 `disposition` 단계(§7.4)가 추가된다. V1 증거 동결은 현행 바이너리 기준이므로 이 단계 없이 기록하고, V4 회귀 시 두 추적을 나란히 둔다.

### 4.3 대조기 (`secscan/measure.py` 확장)
- `match_ground_truth(findings, manifest) -> MatchReport`. 매칭 순서: ① advisory id 정확 일치 + 패키지 정확 일치 + 설치버전 문자열 일치 → `exact`; ② id 는 같고 버전 표기만 다름 → `version-mismatch`(별도 집계, mssql 류); ③ alias(OSV 어댑터 출력의 aliases 에서만 유도, 수동 매핑 금지) 경유 → `alias`; ④ 미매칭 → `missed`. 기대 `absent` 항목이 매칭되면 `false-positive`.
- 결과는 **CVE 단위와 항목 단위**를 병기한다.
- 초과 탐지(정답지에 없는 우리 finding)는 전건 분류: `team-missed`(공개일 ≤ 2026-08-31, 보안팀 인벤토리에 있는 패키지) / `db-drift`(공개일 > 08-31) / `inventory-diff`(우리 BOM 에만 있는 패키지) / `our-fp`(버전 범위 오판정 등). 공개일은 advisory 메타에서 취득, 없으면 `unknown-date` 로 남긴다(강제 분류 금지).
- trivy DB 는 임의 날짜로 고정할 수 없다(`--skip-db-update` 는 현 캐시 재사용일 뿐). 따라서 이 캠페인은 **"현재 DB 기준 유효성"** 을 측정하고 보안팀 35행과의 차이를 위 분류로 설명한다.

### 4.4 증거 동결 순서
1. **현행 바이너리**(모델 변경 전)로 모든 스냅샷을 실행해 raw JSON·SBOM·attrition·`findings.sarif`·`report.md` 를 `docs/verification/evidence/<date>/<snapshot>/` 에 저장(비밀값 미포함 확인).
2. §7 모델·출력 변경 후 **같은 증거**로 회귀(정규화 골든처럼 raw JSON 재입력) — baseline 이동 방지.
3. 실스캔 재실행은 xlsx 완성 후 1회(최종 산출물 생성용).

### 4.5 정본 검증 (reconcile) — 측정 사실성
측정은 측정한 결과를 사실로 전달한다. AI(컨트롤러·서브에이전트)는 **수치를 쓰지 않고, 분류를 바꾸지 않고, 게이트 판정을 내리지 않는다**.

- **정본** = 스크립트가 증거(`findings.json`·`trace.json`·`raw/*`·매니페스트)에서 파생한 `facts.json`(id → 값). 결과 문서는 정본을 인용만 하며, 인용 수치 옆에 `<!-- fact:<id> -->` 마커를 단다.
- **생성 문서**(`gt-b-match.md`·`known-fp.md`·`profile-contract.md`·`input-surface.md`·`gt-a-differential.md`)는 생성기 함수의 결정적 출력이다. 손으로 고치지 않는다.
- **판단 격리**: 초과분 triage 의 override(`our-fp` 등)는 `provenance: "human:<이름>"` 이 있어야 유효. `ai:*`·누락은 위반. 실행자는 판단이 필요한 항목을 `needs_human` 목록으로만 보고한다.
- **검증기** `tools/verify/reconcile.py`: (a) 생성 문서를 같은 증거로 재생성해 바이트 비교 (b) 문서의 fact 마커 값 ↔ `facts.json` 대조 (c) 게이트 문서·측정 문서 요약 절의 표에서 측정값/값 열의 마커 없는 수치 = 출처 불명(행 라벨·기준 열은 제외) (d) override provenance 검사 (e) raw↔typed 카디널리티(raw trivy 고유 VulnerabilityID vs typed SCA 고유 advisory — 정규화 손실 검출). 산출 `reconcile-report.md` + exit code.
- **인용 스코프**: 수치를 인용할 때 "대상(message-gate a483b3b1) · 정답지(GT-B = 보안팀 trivy 1회 + 개발자 발견 12) 대비" 스코프를 병기한다. 절대 recall 로 읽히는 문장("secscan recall 80%")을 쓰지 않는다. SCA recall 은 origin 별 수치와 함께만 인용한다(축 2).
- **게이트**: 재생성 불일치 0 · 마커 불일치 0 · 출처 불명 수치 0 · 비인가 override 0 · raw↔typed 차이는 전건 사실로 기록. 미통과 시 **문서를 고친다**(정본은 고치지 않는다). 플랜 1 끝(V3)과 플랜 2 끝(V7)에서 실행.

## 5. 측정 축과 게이트

게이트 미통과는 캠페인 실패가 아니라 **백로그 P1 등록 사유**다. 캠페인은 측정을 끝내야 완료다. "원인 규명"만으로 통과되는 게이트는 두지 않는다.

| # | 축 | 정답지 | 측정 | 게이트 |
|---|---|---|---|---|
| 1 | 프로파일 계약 | 원 spec §8 | 프로파일별 기대 어댑터 vs 실제 실행·status. 드리프트(spec `accurate-sca=Trivy+OSV` vs 구현 `bom-sca` 단독 → SCA 합의 비활성) | 드리프트 전건 문서화 + spec 갱신 백로그 |
| 2 | SCA 현재 유효성 | GT-B 46 | GT-B recall(CVE·항목 병기) + **origin 별 병기 필수**(`team` 35 = 보안팀 trivy 결과 재현율 성격 — secscan 도 trivy 를 쓰므로 도구 상관 / `dev-found` 12 = 상대적으로 독립인 증거), attrition 으로 미탐 단계 특정 | CVE 단위 GT-B recall ≥ 44/46(합산; origin 별 수치 없이 합산만 보고 금지), HIGH/Important 미탐 ≤ 1, 미탐 전건 단계 특정 |
| 3 | SCA known-FP | mssql | 3단계: BOM/SBOM 에 컴포넌트 존재 → purl 버전 `13.2.1.jre11` 보존 → trivy 판정 비해당 | 3단계 모두 ✓ (미보고만으로 통과 불가) |
| 4 | SCA 초과분 | — | 4분류 전건 | 미분류 0, `our-fp` 는 백로그 |
| 5 | 입력면 교차 | 같은 스냅샷 | (a) `./gradlew bootJar` → `trivy rootfs build/libs`(중첩 jar — **`trivy fs` 는 jar 를 스캔하지 않는다**: Trivy 언어 지원표상 jar/war/ear 는 image·rootfs 전용, 2026-09-05 실측 num=0) (b) cdxgen BOM → `trivy sbom`. 인벤토리(purl 집합) 차·탐지 차·해석 버전 vs 보안팀 `Installed Versions` | 인벤토리 차 전건 원인 특정, 해석 버전 불일치 0 |
| 6 | 도달성 | 사람 negative 18 + 픽스처 | (a) 18건 **판정 근거 비교표**(우리: 패키지 prefix 존재 / 사람: 활성화 조건) — 일치율은 산출하지 않음 (b) 픽스처 `fixtures/reach-app`: 취약 API 사용(기대 reachable) / 같은 라이브러리 안전 API 만(현 엔진 reachable = 알려진 과대판정, 기록) / **프레임워크 활성화 라이브러리 앱 미참조**(기대: unreachable 금지 → unknown 또는 reachable) (c) unknown 기권 비율 | **false-unreachable = 0** (프레임워크 활성화 케이스 포함). 현 엔진은 (b)-3 에서 unreachable 을 낼 것으로 예상 → 백로그 P1 |
| 7 | GT-A differential | GT-A | 취약 스냅샷에서 기대 룰 출현 ∧ 수정 커밋에서 소멸. 탐지 recall 과 actionable recall(tier·exit code) 분리 | 범주 내 출현·소멸 100%. `measure-then-classify` 는 결과 기록만 |
| 8 | 보고서 충실성 | typed findings | `findings.json` 왕복 동일성; md/SARIF/xlsx 는 projection 계약(포함 필드·손실 필드 명시) 대비 검사; 부분 실패·스캐너 status 가 xlsx Meta 시트에 존재; **exit code·md·SARIF·xlsx 의 조치 판정(disposition) 일치** | 손실 0(계약 외 필드), id 집합 동일, 결정성(2회 실행 semantic 동일), **판정 불일치 0**(억제된 finding 이 exit code 를 올리지 않음 — 현행 결함 §7.4) |
| 9 | 측정 사실성 | 증거·정본 | §4.5 검증기: 생성 문서 재생성 비교, fact 마커 대조, 출처 불명 수치, override provenance, raw↔typed 카디널리티 | 재생성 불일치 0 · 마커 불일치 0 · 출처 불명 0 · 비인가 override 0 |

부수 측정(게이트 없음): 스냅샷별 소요 시간·피크 메모리·캐시 cold/warm, 억제 전이(만료→invalidated / 버전 상향→재노출 / 도달성 변화→invalidated), 컴플라이언스 매핑 누락 CWE 목록.

### 5.1 축 ↔ 파이프라인 단계 대응

| 축 | 걸리는 단계(현행 `scan.py`) | V4 이후 |
|---|---|---|
| 1 프로파일 계약 | 어댑터 구성 · 병렬 실행(status) | 동일 |
| 2~4 SCA | 병렬 실행(bom-sca) · 정규화·병합 | 동일 |
| 5 입력면 | 병렬 실행 입력(jar vs BOM) | 동일 |
| 6 도달성 | 도달성 보강 | 동일 |
| 7 GT-A differential | 정규화·병합 · 출력(tier·exit code) | 판정 단계(H) |
| 8 보고서 충실성 | 출력 | 판정 단계(H) + 출력 projection |

## 6. 변이 픽스처 (외부 repo 비의존, `fixtures/`)

| 픽스처 | 케이스 | 검증 대상 |
|---|---|---|
| `reach-app` | 취약 API 사용 / 안전 API 만 / 프레임워크 활성화(spring-boot-starter-web 경유 tomcat, 앱 코드 미참조) / 전이 의존성만 | 도달성 false-unreachable, BOM 전이 해석 |
| `secret-app` 확장 | working-tree 시크릿 / **history-only**(커밋 후 삭제) / allowlist 예제 / 저엔트로피 도메인 비밀번호 | gitleaks dir 의 history 미탐을 명시적으로 기록, 커스텀 룰 보완 |
| `suppress` 시나리오(기존 픽스처 재사용) | 만료 / 버전 상향 / 도달성 변화 | 각 전이의 기대값을 **현행 동작**(버전 상향 = 조용히 미매칭·재노출) 그대로 고정. "invalidated 보고" 는 백로그 |
| `deep` | `gradlew` 전용 프로젝트(시스템 gradle 없음 가정) / 빌드 실패 | 시스템 gradle 호출 문제(`adapters/spotbugs.py`)와 partial 격리 |

## 7. 모델·출력 확장

### 7.1 모델 (`secscan/models.py`)
- `Occurrence(tool, target, package, version)` — `Finding.occurrences: tuple[Occurrence, ...]`. merge 는 union 한다(현재는 첫 finding 의 `source` 만 유지 → `Targets`·`Finding Count` 복원 불가).
- `Cvss(source, version, score, vector)` — `Advisory.cvss: tuple[Cvss, ...]`. trivy `CVSS{nvd,redhat,ghsa}` 전부 보존. `Max CVSS Score`/`CVSS Source` 는 출력 시 파생. **severity 는 계속 벤더 등급**(CVSS 로 재계산 금지).
- `Advisory.published: str | None` — 초과분 분류용.
- `ScanResult` 에 `scanner_status: tuple[ScannerStatus(name, status, tool_version, duration_s, message)]`. CLI 는 구성된 어댑터 이름이 아니라 이것을 보고서에 넘긴다.
- 출력 전 안정 정렬: (category, severity rank desc, reachability rank desc, dedup_key).

### 7.2 `findings.json` (lossless canonical)
- typed 모델의 완전 직렬화(dataclass → dict, tuple → list). `from_json` 왕복 동일성 테스트. 하네스와 억제 워크플로의 입력.
- SARIF 는 여전히 출력 전용(원칙 3). `findings.json` 은 SARIF 가 아니라 내부 모델의 직렬화다.

### 7.3 projection 계약
`docs/output-contracts.md` 에 포맷별 포함/손실 필드 표. markdown 은 finding 줄에 `id`(12 hex) 를 추가한다(억제 스코프 지정에 필요). SARIF 손실 필드(aliases, references 일부, source, verified, suppression basis)를 명시한다.

### 7.4 판정 단계(H) — 파이프라인 재구성 (V4 범위)

**동기.** "조치 대상인가"가 현재 세 곳에서 따로 계산된다: exit code(`cli._has_actionable`), markdown 버킷(priority/review/low), SARIF `sastTier`. 이미 어긋나 있다 — markdown 은 억제된 finding 을 `active` 에서 제외하지만 `_has_actionable` 은 `suppression` 을 보지 않아 **사람이 확정한 억제된 secret 이 있어도 exit 1** 이다(테스트 없음). compliance 는 파이프라인 중간에서 저장되고 tier 는 출력 시 매번 계산·미저장이라 `findings.json` 에 tier 가 빠진다.

**변경.** 억제 다음에 결정적 단계 H 를 두고 Finding 에 저장한다.

- `Finding.disposition: str` — `actionable` / `review` / `demoted`(도달 불가 SCA) / `suppressed`. 규칙은 현행 `_has_actionable` + markdown 버킷을 그대로 옮기되 **억제를 먼저 본다**: `suppression is not None → suppressed`; SAST 는 `sast_tier`; SCA 는 `reachability != unreachable → actionable` 아니면 `demoted`; secret 은 `actionable`.
- `Finding.tier: str | None` — `sast_tier()` 결과를 저장(함수는 유지, H 에서만 호출).
- compliance 계산을 H 로 이동(결과 동일, 위치만 통일). `enrich_compliance` 의 in-place 변경도 다른 단계처럼 새 리스트 반환으로 맞춘다.
- exit code = `any(f.disposition == "actionable")`. markdown·SARIF·xlsx 는 `disposition`/`tier` 필드만 읽는다(재계산 금지). `_has_actionable` 은 disposition 을 읽는 얇은 함수로 축소.
- 재구성 후 단계: 입력 정책 → 수집 → 정규화 → 제외 → 병합 → 보강(도달성 ‖ 시크릿 검증) → 억제 → **판정(H)** → 출력. 제외를 병합 앞으로 옮기는 것과 어댑터에 제외 패턴을 전달하는 것은 §13 백로그(성능, 결과 불변).

**테스트.** (1) 억제된 secret 만 있을 때 exit 0. (2) 네 출력의 actionable 집합 동일(축 8). (3) 현행 골든 결과(V1 증거) 재입력 시 disposition 이 markdown 버킷과 1:1 일치 — 억제 케이스만 차이(결함 수정으로 인정). (4) `findings.json` 에 disposition·tier 포함.

## 8. xlsx 출력 (`secscan/output/xlsx.py`)

- 의존성: `pip install secscan[xlsx]` → openpyxl. 미설치 시 시트별 CSV 번들(`findings-xlsx/<sheet>.csv`) + 경고 1줄. 코어 의존성은 0 유지.
- 시트: `Summary`(category×severity, tier, 도달성, 프로파일, 대상, 일시) / `Findings`(발생 단위 1행) / `Deduped_CVEs`(보안팀 12열 1:1 + secscan 열: 도달성, 도달성 근거, 합의 도구, 합의 점수, 조치 등급, KISA, PCI, 억제 상태, Finding ID) / `Targets` / `SAST`(id, 룰, severity, confidence, tier, 파일, 줄, CWE, KISA, PCI, 억제) / `Secret`(id, 룰, 파일, 줄, verified, severity, 억제 — **비밀값 없음**) / `Meta`(스캐너 status·버전, 프로파일, 커밋, 부분 실패, 도달성 사유, secret 정책).
- 집계 규칙: `Deduped_CVEs` 1행 = advisory 1개. `Affected Packages`/`Installed Versions`/`Fixed Versions` 는 occurrences 를 `, ` 로 결합(보안팀 형식), `Finding Count` = occurrences 수, `Targets` = distinct target.
- 방어: 셀 값 `=`,`+`,`-`,`@`(선행 공백·제어문자 뒤 포함) 시작 → `'` 접두 + 문자열 타입 강제(openpyxl 은 `=` 시작 문자열을 수식으로 쓴다). 32,767자 초과 절단 + `…[truncated]`. 불법 XML 문자 제거. 1,048,576행 상한 초과 시 시트 분할. CSV 폴백도 같은 sanitizer.
- 결정성: 정렬 고정, `workbook.properties.created/modified` 를 스캔 일시로 고정.
- 골든: `golden/security-team-schema.json` 대비 헤더·시트명 검사 + openpyxl 재오픈 왕복(id 집합) + 가능하면 LibreOffice headless 재저장 스모크(선택).

## 9. 실행 순서

| 단계 | 내용 | 산출물 |
|---|---|---|
| V0 | 매니페스트 3종 + 스키마 골든 + 매칭 규칙 테스트 | `docs/verification/ground-truth/*`, tests |
| V1 | 격리 스냅샷 러너 + 단계 추적기(`trace`) + 증거 동결(현행 바이너리) | `tools/verify/`, `docs/verification/evidence/` |
| V2 | 축 1~5 측정(프로파일 계약·SCA 46·mssql 3단계·초과분·입력면) | 측정 표 |
| V3 | 축 6·7(도달성 재정의 + `reach-app` / GT-A differential) + **정본 검증(reconcile, 축 9)** | 픽스처·측정 표·`reconcile-report.md` |
| V4 | 모델 확장 + **판정 단계 H**(disposition·tier 저장, compliance 이동, exit code 결함 수정) + `findings.json` + projection 계약 + 정렬 (증거 재입력 회귀) | 코드·tests·`docs/output-contracts.md` |
| V5 | xlsx 어댑터 + CSV 폴백 + 방어 + 골든 | 코드·tests |
| V6 | 변이 픽스처 나머지(secret 3종·억제 전이·deep gradlew) + 축 8 | 픽스처·tests |
| V7 | 최종 실스캔 1회 → 측정 문서 + 백로그(P1: 안전성·재현성·FN 순) + 정본 검증 재실행 | `docs/measurements/…`, `reconcile-report.md`, PROGRESS/CLAUDE 갱신 |

각 단계 TDD, 소커밋, 커밋 메시지 끝 `다음:`. V1 의 증거 동결이 끝나기 전에 V4 를 시작하지 않는다.

## 10. 원칙 정합성

| 원칙 | 적용 |
|---|---|
| 1 정확도 우선 | false-unreachable = 0 게이트, 탐지/actionable recall 분리, 초과분 강제 분류 금지 |
| 2 결정적/LLM 경계 | Claude 층 비범위. 대조기·추적기·판정(H)·xlsx 전부 결정적. LLM 개입 후보는 §13 규칙 아래 별도 사이클 |
| 3 typed 모델 canonical | `findings.json` 은 내부 모델 직렬화, SARIF 는 출력 전용 유지 |
| 4 자동 억제 금지 | 억제 전이 측정만, 제안·자동 억제 없음 |
| 5 부분 실패 정상 | 스캐너 status 를 Meta 시트·md 에 명시, 구성값 대신 실제 status |
| 6 의존성 최소 | 코어 0 유지, openpyxl 은 extra + CSV 폴백 |
| 측정 사실성(사용자 원칙 2026-09-05) | 수치는 정본(`facts.json`)에서만, AI 는 수치·분류·게이트를 쓰지 않음, §4.5 검증기가 최종 게이트 |

## 11. 리스크

- 스냅샷 빌드에 의존성 다운로드 네트워크 필요. 실패 시 입력면 (a) 만 스킵하고 (b) 로 진행(partial).
- trivy DB 시점 차로 보안팀 35행과 완전 일치 불가 — §4.3 분류로 설명, 게이트는 46 기준.
- message-gate 는 이 저장소 밖 — 하네스는 경로 인자를 받고, 지속 자산은 매니페스트·증거·픽스처·측정 문서다.
- 도달성 축 6 은 현 엔진이 게이트를 통과하지 못할 가능성이 높다. 이는 캠페인의 결과이지 실패가 아니다.

## 12. Codex 검토 반영표

| Codex P1 | 반영 절 |
|---|---|
| 분모 34→46, precision 명칭 | §3.2, §5 축 2·4 |
| trained-on target | §3.3 (GT-A=회귀 명시, GT-B 는 독립) |
| DB 고정 불가 → historical/current 분리 | §4.3, §2 비범위 |
| jar vs BOM 별도 실험, 같은 커밋≠같은 의존성 | §5 축 5 (해석 버전 대조) |
| mssql 3단계 | §5 축 3 |
| 도달성 의미 불일치·false-unreachable | §5 축 6, §6 |
| 측정 단위·alias 매칭 | §3.4, §4.3 |
| 단계별 attrition | §4.2 |
| occurrences·CVSS map·Targets/Finding Count | §7.1 |
| 12열 스키마 골든 | §3.4 |
| lossless 왕복 vs projection | §7.2·7.3 |
| stdlib xlsx 부담 | §8 (openpyxl extra, 사용자 결정) |
| formula injection·셀 한도 | §8 |
| GT-A 매니페스트·detection/actionable 분리·differential | §3.3, §5 축 7 |
| 억제 변이 기대값 | §6 |
| partial failure 보고·프로파일 드리프트·BOM 캐시·격리 실행·게이트 수치·증거 동결 순서 | §4.1, §4.4, §5 축 1, §7.1 |

## 13. 백로그 (이 캠페인 비범위 — 초기 항목)

캠페인 종료 시 측정 결과로 우선순위를 다시 매긴다. 여기 항목은 설계 과정에서 확정된 것만 적는다.

### 13.1 LLM 개입 후보

원칙 2 를 지키는 형태는 하나다: **LLM 이 검사를 작성하고, 결정적 파이프라인이 실행한다.** 공통 규칙 — (a) 핫패스 밖: 파이프라인 종료 후 `findings.json` 을 입력으로, 배치·캐시(키 = advisory 또는 dedup_key × 코드 해시). (b) 결정적 산출물(json·SARIF·xlsx·exit code)에 LLM 텍스트를 섞지 않는다 — 별도 파일에 출처 표기. (c) 방향 제약: 위험을 **올리는** 쪽(reachable, 검토 필요)만 단독 작용, 내리는 쪽(unreachable, 억제)은 사람 확정.

| 우선 | 후보 | 형태 | 근거 |
|---|---|---|---|
| 1 | **도달성 전제조건 검사** | advisory 본문 → 전제조건(polymorphic typing 활성화, HTTP/2, SiftingAppender, log4j-core 존재 등) → grep/semgrep/설정 키 **쿼리** 생성 → 파이프라인이 실행. 증거 = (쿼리, 결과, file:line). 발견 → reachable, 미발견 → unknown + 증거. `Reachability.source="claude"` 자리 | message-gate 사람 판정 18건이 전부 이 유형. 축 6 이 "config-gated = unknown" 으로 끝나면 다음 사이클 1순위 |
| 2 | **review tier 삼각측량** | 룰 × 싱크 패턴 단위 클러스터로 1회 평가 + 사이트 샘플링. 산출 = FP 가능 사유·인용·정렬 순서. tier·건수·노출 불변 | deep review 355건(CRLF 163)이 실제 병목 |
| 3 | **조치 회신 문서 초안** | `findings.json` + 증거로 message-gate `03_취약점조치결과` 형식 초안. 별도 `summary.md` | 개발팀이 손으로 쓴 문서를 대체 |
| 4 | 부분 실패 진단 | deep 빌드 실패·스캐너 stderr → 원인·조치 제안(gradlew, JDK 불일치). 조언만 | deep 스킵 1순위 원인 |
| — | 금지 | 정규화·병합·제외·판정(H)·시크릿 검증에는 넣지 않는다(FN·비결정성) | |

### 13.2 파이프라인 재구성 잔여 (성능·위생, 결과 불변)
- 제외를 병합 앞으로 이동 + 어댑터에 제외 패턴 전달(semgrep `--exclude`, trivy `--skip-dirs`, gitleaks 설정). 현재는 build/·node_modules 까지 스캔 후 버림.
- BOM 캐시 키를 경로 해시에서 content-addressed 로(§4.1).
- 억제 stale 사유에 "버전 변경" 명시 보고(현재는 조용히 미매칭).
- 원 spec §8 프로파일 표를 구현(bom-sca)에 맞게 갱신, osv 어댑터 처리 결정(프로파일 편입 또는 제거).
- `secscan/adapters/spotbugs.py` 의 시스템 gradle 호출 → `gradlew` 우선(갭 지도 부수 발견).

### 13.3 알려진 결함
- exit code 가 억제를 무시(§7.4) — **V4 에서 해소**. 캠페인 전 실스캔·CI 게이트 해석 시 유의.

## 정오표 (2026-09-05 최종 리뷰)

원문(§1~§13)은 수정하지 않는다 — 이 절은 최종 리뷰(Important 8건)에서 확정된 spec 자체의
드리프트만 추가 기록한다.

(a) §3.2·§5 축 6(a)는 "사람 도달성 판정 18건(jackson 6·log4j 1·tomcat 11·logback 1 = 전부
negative)"이라고 적었으나, 내역의 합(6+1+11+1)은 19로 그 문장 자체가 자기모순이다. 실측
매니페스트는 `human.verdict_rows`/`human.verdict_advisories`(`facts.json`, spec §4.5 정본) 기준
34행 / 고유 advisory 24건이다 — "18건"·"19건" 어느 쪽과도 다르다. spec 드리프트로 기록만 하고
해소는 플랜 2 로 미룬다.

(b) §4.5 검사 목록에 두 항목을 추가한다: **(f) 인용 표 대조** — 결과 문서에서 측정 문서로 옮겨
적은 표가 "전체 인용"이라고 선언되면, 원본과 마커 제거 후 행 단위로 바이트 대조한다(이번
수정 라운드에서 `tools/verify/reconcile.py` 의 `check_quoted_tables`/`reconcile.quote_mismatch`
로 구현 완료). **(g) 판정 열은 생성기 출력이어야 한다** — 게이트 문서의 ✓/✗ 열은 현재 실행자가
손으로 쓰고 어떤 검사도 대조하지 않는다(리뷰 I5). 플랜 2 에서 `tools/verify/gate.py` 가 spec §5
기준 상수를 코드로 갖고 `facts*.json` 과 비교해 게이트 문서 전체를 생성하게 하면 해소된다.
