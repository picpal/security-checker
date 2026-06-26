# JVM 보안 점검 하이브리드 Agent — 설계 문서 (v2)

- **작성일**: 2026-06-26 / **개정**: 2026-06-27 (codex 리뷰 + 웹 fact-check 반영)
- **상태**: 설계 합의 완료 (구현 plan 작성 직전)
- **타겟**: JVM(Java/Kotlin) 프로젝트
- **실행 형태**: 하이브리드 (결정적 오케스트레이터 + Claude 해석/보고서 레이어)
- **실행 환경**: 로컬 개발 머신, 개인 사용 우선
- **핵심 가치**: **정확도 우선.** "FP가 많으면 아무도 안 쓴다"가 이 프로젝트의 1번 실패 원인이자 1번 설계 제약이다.

---

## 1. 목적

오픈소스 보안 스캐너들을 **요청한 수준·범위에 맞게 병렬 실행**하고, 결과를 **하나의 정규화된 내부 모델로 종합**한 뒤, **도달성 분석으로 노이즈를 걷어내고 Claude가 증거를 해석·보고서화**하는 보안 점검 도구.

개별 스캐너는 출력 포맷이 제각각이고 FP가 많다. 이 도구는 (1) 실행을 결정적·재현가능하게 캡슐화하고, (2) 출력을 typed finding 모델로 통일하며, (3) **도달성(reachability)으로 "실제 악용 가능한 것"만 남기고**, (4) Claude가 그 증거를 사람이 읽을 형태로 해석한다.

**정확도 우선 결정(2026-06-27)**: 최소 동작 MVP보다 "쓸 만한 정확도"를 먼저 증명한다. dep-scan 도달성 분석을 코어 정확도 엔진으로 둔다. 자원 부담은 4중 안전장치(10.1)로 길들인다.

---

## 2. 범위

### MVP (이번 사이클) — "정확한 정적 3종"
- **정적 3종**: SAST + SCA(의존성) + Secret
- **도달성 분석 포함** (SCA): dep-scan/atom 기반, 크기 인지 자동 실행
- 로컬 실행, 단일 JVM 프로젝트 대상
- 내부 typed finding 모델 → 통합 SARIF(기계용) + Markdown 보고서(사람용)

### 백로그 (이후 사이클, 각자 별도 spec)
- IaC/컨테이너(`+iac`), DAST(`+dast`), CI 통합(PR 게이트), 주기 점검(launchd + diff), 패치 모니터링(Dependency-Track)
- 깊은 SAST: Opengrep(cross-function taint, 성숙도 관찰 중), CodeQL(라이선스 허용 시 데이터플로우 최강)
- LSP 기반 코드 질의(Serena류)로 도달성 정밀화

### 명시적 비범위
- 상주 서버/대시보드(SonarQube, Dependency-Track), 상용/계정 종속(Snyk, ggshield), 자동 수정(auto-fix)

---

## 3. 설계 원칙 (codex 리뷰에서 승격)

1. **정확도 > 커버리지 > 속도.** 노이즈를 줄이는 모든 레버를 우선한다.
2. **결정적/LLM 경계를 분명히.** 스캐너 실행·정규화·도달성은 결정적 코드. Claude는 **증거의 해석자**이지 판정 oracle이 아니다.
3. **내부는 typed 모델, SARIF는 출력 포맷.** SARIF는 location 중심이라 SCA(package/advisory 중심)·secret을 내부 canonical로 쓰면 깨진다. 내부 typed model을 두고 SARIF는 emit만 한다.
4. **억제는 위험하다.** 자동 억제 금지. 모든 억제는 증거·출처·기한·범위를 갖고, 의존성/콜패스 변경 시 무효화된다.
5. **부분 실패는 정상.** 한 스캐너가 죽거나 도달성이 타임아웃해도 나머지 결과는 유효. partial-result를 1급으로 보고한다.
6. **설치 마찰이 최대 장벽.** `doctor`를 첫 마일스톤으로.

---

## 4. 아키텍처

```
┌──────────────────────────────────────────────────────────────────┐
│ [Claude 레이어]  증거 해석자 (oracle 아님)                          │
│  · 자연어 요청 해석 → 스택/빌드도구 감지 → 프로파일 선택              │
│  · typed findings + 도달성 증거 + 코드 컨텍스트 → 해석/우선순위        │
│  · 보고서 작성(CWE 설명, 수정/업그레이드 경로) · 억제 후보 "제안"       │
└──────────────▲───────────────────────────────────┬─────────────────┘
        typed findings(+evidence)                   │ 프로파일·대상으로 CLI 호출
┌──────────────┴───────────────────────────────────▼─────────────────┐
│ [오케스트레이터 CLI]  결정적·재현가능                                 │
│  · 프로파일대로 어댑터 병렬 실행 · 자원 거버넌스(11) · 부분실패 격리    │
├────────────────────────────────────────────────────────────────────┤
│ [정규화 → typed finding 모델 (6)]  ← 이 프로젝트의 심장               │
│  원시 출력 → typed findings → 합의 스코어링 → 도달성 주입 → 억제 적용   │
│         ├─ [도달성 엔진] dep-scan/atom (크기 인지 자동, 10.1)         │
│         └─ [억제 엔진] VEX/baseline (안전장치, 12)                    │
├────────────────────────────────────────────────────────────────────┤
│ [출력 어댑터]  typed model → SARIF 2.1.0 / Markdown                  │
├────────────────────────────────────────────────────────────────────┤
│ [스캐너 어댑터]  Semgrep · Trivy · osv-scanner · Gitleaks · TruffleHog│
│  (deep) SpotBugs+FindSecBugs                                        │
└────────────────────────────────────────────────────────────────────┘
```

### 데이터 흐름
1. 자연어 요청 → Claude가 스택/빌드도구 감지, 프로파일 결정
2. CLI를 `scan --profile <p> --target <path>`로 호출
3. 어댑터 병렬 실행(자원 거버넌스 적용) → 원시 출력
4. 정규화: 원시 → **typed findings** → 합의 dedup → **도달성 주입**(dep-scan) → 억제 적용
5. 출력 어댑터가 SARIF + (Claude용) typed findings 산출
6. Claude가 findings + 도달성 증거 + 코드를 해석 → Markdown 보고서, 억제 후보 제안(자동 기록 안 함)

---

## 5. 컴포넌트별 책임·인터페이스·의존성

### 5.1 스캐너 어댑터 (`adapters/`)
- **책임**: 스캐너 1개 실행, 원시 출력 반환. 인자·환경 차이 흡수. 정규화는 하지 않음.
- **인터페이스**: `run(target, options) -> RawResult{tool, version, format, payload, exit_code, stderr, status}`
- **status**: `ok | failed | timeout | skipped` (부분실패 보고용)
- **불변식**: 새 스캐너 = 어댑터 1개 추가, 코어 무변경.

### 5.2 오케스트레이터 (`orchestrator.py`)
- **책임**: 프로파일이 지정한 어댑터 병렬 실행, 자원 거버넌스(11), 부분실패 격리.
- **인터페이스**: `scan(profile, target) -> list[RawResult]`

### 5.3 정규화 → typed model (`normalize/`)
- **책임**: 원시 출력 → typed findings(6), 합의 스코어링, CWE/OWASP 매핑, severity 정규화.
- **인터페이스**: `to_findings(list[RawResult]) -> list[Finding]`
- **불변식**: 입력이 같으면 출력이 같다(결정적). → **단위 테스트 1순위**.

### 5.4 도달성 엔진 (`reachability/`)
- **책임**: dep-scan/atom으로 SCA findings에 도달성 증거 주입. 크기 인지 자동(10.1).
- **인터페이스**: `enrich(findings, target, budget) -> findings(+reachability)`
- **의존성**: dep-scan, atom(Java 21/Node), 메모리. → `doctor`가 사전 점검.

### 5.5 억제 엔진 (`suppress/`)
- **책임**: VEX/baseline 적용·기록. 안전장치(12). **Claude의 자동 억제 금지** — 제안만 받고 사람이 확정.
- **인터페이스**: `apply(findings, vex, baseline) -> findings`, `record(suppression, evidence, provenance, expiry)`

### 5.6 출력 어댑터 (`output/`)
- **책임**: typed findings → SARIF 2.1.0 / Markdown. SARIF는 출력 전용.

### 5.7 Claude 레이어
- **책임**: 프로파일 선택, 증거 해석, 보고서, 억제 후보 제안.
- **코드 질의**: 기본 `grep`/`ast-grep`(결정적 매칭). LSP(Serena) 어댑터로 교체 가능하게 추상화.
- **불변식**: 도달성 **판정**은 도달성 엔진(결정적)이 하고, Claude는 그 증거를 **해석/보강**만. reflection·Spring proxy·Lombok·annotation 라우팅 등 정적 사각지대는 보고서에 명시.

---

## 6. 데이터 모델 — typed finding (핵심)

SARIF가 아닌 내부 typed model을 canonical로 둔다. 핵심 필드:

```
Finding {
  id            // 안정적·재현가능 (tool + rule + 위치/패키지 해시)
  category      // sast | sca | secret
  tool, tool_version, rule_id
  severity      // 정규화된 등급
  cwe[], owasp[]
  // 위치형(SAST/secret)
  location { file, start_line, end_line, snippet_ref }
  // 컴포넌트형(SCA)
  component { ecosystem, package, version }
  advisory { id(CVE/GHSA), fixed_versions[] }
  // 정확도 메타
  reachability { status: reachable|unreachable|unknown, evidence: callpath?, source: dep-scan|claude }
  consensus  { tools[], score }     // 같은 finding을 몇 개 도구가 지적했나
  suppression { state, reason, provenance, evidence, expiry, scope }?
}
```

이 모델이 dedup·VEX 매칭·fix-version 추론·도달성 메타를 자연스럽게 담는다. SARIF emit 시 SCA 전용 필드는 `properties` bag에 싣는다.

---

## 7. 사용 시나리오 → 코어 1개 + 얇은 트리거 3개

| 시나리오 | 구현 | 단계 |
|---|---|---|
| 프로젝트 풀스캔 (on-demand) | 코어 그대로 | MVP |
| 신규 라이브러리 패치 체크 | 코어의 SCA+도달성만 변경 의존성에 (`quick`/`accurate-sca`) | MVP |
| 주기 점검 | 풀스캔을 launchd/cron + 직전 결과와 diff | 백로그 |

---

## 8. 프로파일

| 프로파일 | 구성 | 용도 | 단계 |
|---|---|---|---|
| `quick` | Trivy(SCA) + Gitleaks(secret), 도달성 생략 | 초고속 확인 | MVP |
| `accurate-sca` | Trivy+osv + **dep-scan 도달성** | 정확한 의존성 점검(패치 체크) | MVP |
| `standard` | Semgrep + Trivy+osv+도달성 + Gitleaks (+opt-in TruffleHog) | 기본 풀스캔 | MVP |
| `deep` | standard + SpotBugs+FindSecBugs | 정밀(빌드 필요, experimental) | MVP 후반 |
| `+iac`/`+dast` | 애드온 | 백로그 |

**Secret 검증 정책(프로파일 플래그)**: TruffleHog 유효성 검증은 발견된 자격증명을 제3자 서비스로 전송한다. 기본 **off**. `--verify-secrets` opt-in, `--network-off`로 강제 차단, 민감 환경용 `never-validate` 보장.

---

## 9. 툴 매트릭스 (선정 근거·라이선스)

> 라이선스 열은 **개인 사용 단계에선 모두 무관**. 사내/상용 확장 시 ★ 재검토.

| 영역 | 채택 | 역할 | 라이선스 |
|---|---|---|---|
| **SAST** | Semgrep CE | 기본 소스 스캔. taint는 **intraprocedural(함수 내)만** — cross-function/file은 Pro (10.2) | LGPL-2.1 |
| | SpotBugs + FindSecBugs (`deep`) | 바이트코드 정밀. 빌드 필요. **FindSecBugs 정체(v1.14.0, 2024)** / SpotBugs 활발(v4.10.x, 2026) | LGPL / 플러그인 |
| **SCA** | Trivy | 탐지 허브. Maven/Gradle(lockfile), **VEX 소비(experimental)** | Apache-2.0 |
| | osv-scanner | OSV.dev, SARIF, osv-scalibr 엔진. advisory 커버리지 보강(FN↓) | Apache-2.0 |
| | **OWASP dep-scan + atom** | **JVM 도달성(콜패스) — 정확도 코어 엔진(10.1)** | MIT 계열 |
| **Secret** | Gitleaks | 광범위 탐지, baseline/allowlist | MIT |
| | TruffleHog (opt-in) | 키 **유효성 검증**으로 FP↓ (network 정책 8) | ★AGPL-3.0 |

**제외**: PMD(보안 약함), Horusec(정체 v2.8.0/2022), Snyk·ggshield(상용 종속), OWASP Dependency-Check(느림·FP, CPE 매칭), tfsec(Trivy로 흡수됨).

---

## 10. 정확도 설계

### 10.0 4대 레버
| 레버 | MVP 적용 | 비고 |
|---|---|---|
| ① 도달성 | **dep-scan/atom**(10.1) + Claude 증거 해석 | **JVM SCA 노이즈 최대 감소원** |
| ② 분석 깊이 | `deep`: SpotBugs(바이트코드). 백로그: Opengrep/CodeQL | 패턴<데이터플로우<바이트코드 |
| ③ 다중엔진 합의 | Trivy ∪ osv (커버리지↑/FN↓), 동일 위치 중복→confidence 가중 | 정규화 레이어가 수행 |
| ④ 메타 해석+억제 | Claude가 코드 컨텍스트로 해석 → 억제 **후보 제안** → 사람 확정 → 재발 억제 | 자동 억제 금지(12) |

### 10.1 도달성 엔진 — dep-scan을 길들이는 4중 안전장치
dep-scan/atom은 Java 도달성을 실제 제공하지만, 대형 코드베이스에서 built artifact·다중 BOM·**대용량 메모리·수십 분**을 요구할 수 있다(웹 검증 확인). "제거"가 아니라 "관리":

1. **크기 인지 자동(확정 정책)** — LOC/모듈 수 감지. **임계 이하 → 자동 풀 도달성**. 임계 초과 → 사용자 확인 후 진행(또는 예산 제한). 임계값은 M1에서 실측 튜닝.
2. **캐싱** — atom 슬라이스를 코드 해시 기반 캐시. 코드 미변경 시 재사용(재점검 가속).
3. **예산 + 폴백** — `max-memory`·timeout 초과 시 도달성만 스킵, **Trivy/osv 탐지 결과는 유지하고 `reachability=unknown` 표기**.
4. **doctor 사전 점검** — dep-scan 런타임(Java 21/Node)·가용 메모리를 M0에서 확인.

### 10.2 무료 taint의 한계
Semgrep CE taint는 **intraprocedural(단일 함수 내)** 만 추적한다. cross-function/file은 Pro 전용. "taint로 공짜 정확도"를 과신하지 않는다. 깊은 데이터플로우는 백로그의 Opengrep(복원 진행 중, 아직 Pro/CodeQL 동급은 미검증) 또는 CodeQL(★OSI 오픈소스 한정 무료)로.

### 10.3 정확도 측정
OWASP Benchmark는 v1.2(2016) 동결·합성이라 부적합. **의도적 취약 픽스처 프로젝트**(알려진 CVE 의존성, 하드코딩 시크릿, 취약 패턴, 그리고 *도달 가능/불가능 케이스를 의도적으로 배치*)로 precision/recall을 회귀 측정. **M1에서 도달성이 실제로 FP를 줄이는지·비용이 값어치 하는지 실측**한다.

---

## 11. 자원 거버넌스

- **per-adapter**: timeout, max-memory 가이드, 전용 cache-dir, 취소(cancellation).
- **전역**: 동시성 상한(스캐너가 CPU/메모리/네트워크 경합 — Semgrep·TruffleHog·Trivy DB 갱신·atom).
- **부분 결과**: 실패/타임아웃 어댑터는 `status`로 표기, 나머지 결과는 유효하게 보고. "전부 성공"으로 위장하지 않음.
- **재시도**: 네트워크성 실패(DB 갱신)만 제한적 재시도.

---

## 12. 억제 안전장치

자동 억제는 진짜 취약점을 영구 은폐할 수 있다. 따라서:

- **Claude는 억제를 "제안"만** 한다. 기록은 사람이 확정.
- **억제 엔트리 필수 필드**: provenance(누가/언제/왜), evidence(도달 불가 콜패스 등 근거), expiry(기한), scope(정확한 패키지+버전 또는 위치).
- **stale 무효화**: 의존성 버전·콜패스·룰셋이 바뀌면 관련 억제를 자동 무효화 → 재검토 큐로.
- **저장 포맷**: OpenVEX / SARIF baseline — 표준·git 추적·감사가능.

---

## 13. 흔히 깨지는 지점 & 대응

| 실패 모드 | 왜 죽나 | 대응 |
|---|---|---|
| FP 폭탄·알림 피로 | 툴 그대로면 수천 건 | 도달성(10.1) + Claude 해석 + baseline |
| 정규화/모델 부적합 | SARIF를 내부 canonical로 쓰면 SCA 깨짐 | typed model(6) 내부, SARIF는 출력만 |
| **Maven/Gradle 해석 실패** | 멀티모듈·Kotlin DSL·BOM·private registry·동적버전·lockfile 부재·shaded JAR·JDK 불일치 | 빌드도구별 해석 전략, 실패 시 partial + 명시 경고 |
| dep-scan 자원 폭발 | 대형 코드베이스 64GB·15분+ | 4중 안전장치(10.1), 폴백 시 `reachability=unknown` |
| 버전/룰셋 드리프트 | 업데이트로 결과 급변 | 스캐너 버전·룰셋 핀(Docker 권장), finding에 tool_version 기록 |
| 빌드 의존 SAST 함정 | 빌드 깨지면 점검 불가 | 소스 기반(Semgrep) 기본, 바이트코드는 `deep` |
| 도달성 과신 | reflection·DI·deserialization·annotation 라우팅 사각 | 사각지대 보고서 명시, Claude는 해석자(5.7) |
| Secret 검증 부작용 | 자격증명을 제3자 전송 | 기본 off, opt-in/network-off/never-validate(8) |
| 억제 오남용 | 진짜 이슈 은폐 | 안전장치(12) |

---

## 14. 기술 선택

- **구현 언어**: **Python 권장**(스캐너 CLI 글루·SARIF 라이브러리·병렬·빠른 반복). dep-scan/atom도 Python/Node 생태계라 정합. *(CI 단계 단일바이너리 필요 시 Go 재검토 — plan에서 확정)*
- **스캐너 실행**: 로컬 바이너리 우선, 버전 고정 필요 시 Docker 옵션.
- **포맷**: 내부 typed model → SARIF 2.1.0(기계) + Markdown(사람). 억제는 OpenVEX/baseline.

---

## 15. 테스트·검증 전략

- **정규화/모델 골든 테스트**: 각 툴 샘플 원시 출력 → 기대 typed findings(결정성).
- **취약 픽스처 프로젝트**: 알려진 CVE 의존성 + 시크릿 + 취약 패턴 + **도달 가능/불가 케이스**. E2E.
- **도달성 정확도 회귀(M1 핵심)**: 픽스처로 dep-scan이 도달 불가를 정확히 걸러내는지 precision/recall + 비용(시간/메모리) 실측.
- **부분 실패 테스트**: 한 어댑터 강제 실패 시 나머지 결과·status 보고 검증.
- **어댑터 스모크**: `doctor`로 설치·런타임 점검.

---

## 16. 마일스톤

| 단계 | 산출물 | 검증 |
|---|---|---|
| **M0 doctor** | 스캐너 + 런타임(Java 21/Node/메모리) 점검, 설치 가이드 | 환경 진단 정확 |
| **M1 정확한 SCA** | Trivy+osv → typed model → 합의 dedup → **dep-scan 도달성(4중 안전장치)** → Claude 증거 해석 → SARIF+MD. **+ 도달성 정확도/비용 실측** | 픽스처 도달 불가 억제·재현성·비용 측정 |
| **M2 Secret** | Gitleaks + opt-in TruffleHog(network 정책) | 시크릿 탐지·검증·정책 동작 |
| **M3 SAST** | Semgrep 어댑터(taint 한계 인지) | 취약 패턴 탐지 |
| **M4 억제** | 억제 안전장치 + baseline + VEX 루프 + stale 무효화 | 억제 후 재발 억제·무효화 동작 |
| **M5 deep** | SpotBugs+FindSecBugs(빌드 연동, experimental) | 바이트코드 탐지 |

**M1을 "정확한 SCA"로 잡는 이유**: "정확도가 높아야 쓴다"가 전제이므로, 첫 산출물이 곧 정확도 증명이어야 한다. 도달성이 값어치 하는지 여기서 실측해 이후 투자를 결정한다.

---

## 17. 라이선스 노트

현재 **개인 사용 단계**라 채택 도구 라이선스 제약은 무관. **사내/상용 확장 시** 재검토:
- **TruffleHog (AGPL-3.0)**: 통합 방식에 따라 민감 → 검증 단계를 별도 프로세스로 격리.
- **CodeQL**: **OSI 승인 오픈소스** 코드베이스만 무료, 사유 코드는 유료(GitHub Advanced Security).
