# SAST 룰 확대 + 신뢰도 계층화 (B) — 설계 문서

> 코드 취약점 탐지(SAST) 커버리지를 넓히되, 늘어나는 FP를 **신뢰도 계층화**로
> 통제한다. 신규 스캐너가 아니라 **기존 Semgrep 경로 강화**다.

## 1. 목적 / 배경

message-gate 실증에서 SAST 탐지가 **0건**이었다. 원인은 Semgrep CE의 좁은 기본
룰셋(`p/java` + `p/security-audit`)이다. 사내 coderay가 코드 취약점을 더 잡는
격차를 줄이려면 두 갈래가 필요하다:

- **B (이 문서)**: 룰 *양* 확대 — 단일 지점에서 판단되는 패턴형(하드코딩·약한
  암호·위험 API·설정 오류 등). 저비용·즉시.
- **C (별도 spec)**: 분석 *깊이* — 함수간/파일간 taint(injection 흐름). coderay
  격차의 본질이나 CodeQL 빌드의존·고비용이라 분리한다.

조사 결론(2026-06): KISA·PCI-DSS 모두 공식 기계가독 룰셋을 제공하지 않으므로,
B는 별도 룰을 저작하지 않고 **검증된 오픈 레지스트리 팩**을 켜고, 그 결과의 CWE를
이미 구축한 컴플라이언스 매핑(`compliance.py`)으로 KISA/PCI에 자동 연결한다.

## 2. 범위

### 이 사이클 (B)
- Semgrep 레지스트리 팩 확대: 현행 + `p/owasp-top-ten` + `p/cwe-top-25`.
- semgrep `metadata.confidence` 추출 → typed Finding.
- 신뢰도 계층화: `severity` + `confidence` → `actionable` / `review` 파생.
- 보고서에 **검토 후보(낮은 신뢰)** 섹션 신설.
- severity 표기를 coderay 정합 한글 4+1단계로(출력 레이어 한정).
- CE 한계(Pro 무발화)·네트워크·Kotlin 커버리지 한계 명시.

### 비범위 (C 또는 별도)
- CodeQL/Opengrep 함수간 taint.
- **SAST 도구간 consensus**(같은 위치를 다른 도구가 지목 → 신뢰 부스트). 현재
  `dedup_key`가 `rule_id`를 포함해 도구·룰별로 분리되므로, 위치기반 합의는
  dedup 재설계가 필요하다 → **C 스펙에서** taint 연동과 함께 다룬다. B에서는
  semgrep 단일 도구라 `consensus.score`는 1로 고정이며 계층화 신호로 쓰지 않는다.
- 도달성의 SAST 적용(도달성은 SCA 전용 개념 유지).

## 3. 설계 원칙 (해당 절)

1. **정확도 우선** — 룰을 넓히되 FP는 *버리지 않고* 계층으로 분리(원칙1).
2. **결정적/LLM 경계** — 팩 실행·confidence 추출·등급 파생 모두 결정적 코드.
   LLM은 탐지하지 않는다(원칙2).
3. **typed model canonical** — confidence/등급은 Finding에 싣고, 한글 severity·
   계층 섹션은 출력 레이어에서만(원칙3).
4. **부분 실패는 정상** — 레지스트리 fetch 실패·Pro 룰 무발화를 숨기지 않는다
   (원칙5).

## 4. 아키텍처 / 변경 맵

신규 어댑터 없음. 기존 Semgrep 경로의 5개 파일만 수정한다.

| 파일 | 변경 |
|---|---|
| `adapters/semgrep.py` | `build_argv`에 `--config p/owasp-top-ten`, `--config p/cwe-top-25` 추가 |
| `normalize/semgrep.py` | `extra.metadata.confidence` 추출 → `Finding.confidence` |
| `models.py` | `Finding.confidence: str`("high"/"medium"/"low"/"unknown"), `sast_tier()` 헬퍼 |
| `output/markdown.py` | severity 한글 매핑 + SAST **검토 후보** 섹션 분리 |
| `output/sarif.py` · `cli.py` | `properties.confidence`/`sastTier` + CLI 요약 카운트 + CE 한계 안내 |
| `doctor.py` | semgrep purpose에 "레지스트리(최초 네트워크)" 한 줄 보강 |

`profiles.py`·`compliance.py`·`scan.py`는 **무변경**(semgrep이 이미 standard/deep,
컴플라이언스·enrich 파이프라인은 자동 연동).

## 5. 룰 팩 확대

`build_argv` 결과:
```
semgrep --config p/java --config p/security-audit \
        --config p/owasp-top-ten --config p/cwe-top-25 \
        --json --quiet --disable-version-check <target>
```
- secret 계열 팩(`p/secrets`)은 **제외** — gitleaks와 중복.
- 레지스트리 팩은 최초 실행 시 네트워크 fetch 필요. 캐시 후 오프라인 동작.

## 6. 신뢰도 계층화 (핵심)

**신호**: `severity`(정규화 영문) + `confidence`(semgrep 메타).

**파생 규칙** — `sast_tier(finding) -> "actionable" | "review"`:

| 조건 | 등급 |
|---|---|
| confidence == "low" | **review** |
| severity ∈ {critical, high, medium} AND confidence ≠ "low" | **actionable** |
| 그 외 (severity low/unknown) | **review** |

- confidence "unknown"(룰이 confidence 메타 미제공)은 `low`가 아니므로 severity가
  medium 이상이면 actionable(놓치지 않음, recall 우선). severity가 낮으면 review.
- SCA·secret 에는 적용하지 않는다(기존 우선순위 로직 유지). `sast_tier`는
  `category == "sast"` 에서만 의미.

## 7. severity 표기 — coderay 정합

내부 canonical(영문 5단계)은 **무변경**. 출력 레이어에서만 한글 매핑한다.

| canonical | 보고서/CLI(한글) | SARIF level |
|---|---|---|
| critical | 심각 | error |
| high | 위험 | error |
| medium | 보통 | warning |
| low | 일반 | note |
| unknown | 미상 | note |

coderay는 4단계지만 secscan은 도구가 severity 미제공인 경우가 있어 `unknown→미상`을
추가로 둔다(정직성). 정렬·정규화·dedup·SARIF는 영문값으로 수행한다.

## 8. 출력 구조

**Markdown 섹션** (위→아래 우선순위):
1. **우선 조치** — 도달가능/미상 SCA + secret + SAST `actionable`
2. **검토 후보 (낮은 신뢰)** — SAST `review` *(신규)*
3. **낮은 우선순위 — 도달 불가 SCA** *(기존)*
4. **억제됨 (사람 확정)** *(기존)*

- 각 finding의 severity는 한글로 표기. 컴플라이언스(KISA/PCI) 라벨은 기존 라인 유지.
- **CLI 요약**: `SAST 우선 N · 검토후보 M` 한 줄 추가.
- **SARIF**: `properties.confidence`, `properties.sastTier` 추가. level은 영문 유지
  (GitHub code scanning 등 기계 표준).

## 9. CE 한계·네트워크·Kotlin (원칙5)

- **Pro 무발화**: CE에서 Pro 전용·일부 프레임워크 룰은 에러 없이 0건. 기존
  `_SAST_NOTE`(intraprocedural 안내)에 "CE 한계로 일부 룰 미발화 — 깊은 분석은
  C(CodeQL) 예정" 한 줄 확장. "전부 성공" 위장 금지.
- **네트워크 실패**: 레지스트리 fetch 실패 시 semgrep 어댑터가 부분실패로 격리
  (기존 status 메커니즘). 나머지 결과는 유효. doctor에 "semgrep 레지스트리(최초
  네트워크)" 한 줄 보강.
- **Kotlin**: semgrep Kotlin 룰 커버리지가 Java보다 약함(experimental). 보고서에
  한계 명시 — 잡히는 만큼 잡되 못 잡는 것을 숨기지 않는다.

## 10. 컴플라이언스 연동 (자동)

semgrep 정규화는 이미 `_cwe_codes`로 CWE를 추출한다. 확대된 팩의 finding이 CWE를
달고 들어오면 `enrich_compliance`(기존)가 KISA/PCI를 자동으로 채운다 → message-gate의
"컴플라이언스가 SCA(라이브러리)에서만 나오는" 문제가 코드레벨로 해소된다. 추가 코드
없음. (CWE 메타 없는 룰은 매핑 없이 `compliance=None`, 기존 동작.)

## 11. 테스트·검증 (TDD)

- `normalize/semgrep`: confidence 추출 — confidence 포함 골든(실제 semgrep 실행 캡처).
- `models.sast_tier`: 등급 규칙 단위(경계값: medium+low_conf, high+unknown_conf, low_sev).
- `output/markdown`: severity 한글 매핑 + 검토 후보 섹션 분리.
- `output/sarif`: properties.confidence/sastTier.
- `cli`: 요약 SAST 우선/검토후보 카운트.
- **게이트**: 의도적 취약 픽스처에서 (a) SQL injection 류가 `actionable`로, (b)
  저신뢰 패턴이 `review`로 분리됨. message-gate 재스캔에서 SAST 신규 탐지 + 코드레벨
  컴플라이언스 매핑 발생.

## 12. success 기준

1. message-gate 재스캔: SAST 코드 취약점 신규 탐지(0 → N) + 컴플라이언스 코드레벨 매핑.
2. 저신뢰 패턴이 "검토 후보"로 분리되어 "우선 조치"가 깨끗하게 유지.
3. 의도적 취약 픽스처의 알려진 패턴(SQL injection 등) 탐지 유지(회귀 없음).
4. 전체 테스트 green, 부분실패(레지스트리/Pro 무발화) 정직 보고.

## 13. 라이선스 노트

Semgrep 엔진 LGPL-2.1, 레지스트리 룰 Semgrep Rules License v1.0(스캔 사용 허용).
상용·계정 종속 아님(원칙·spec §2 비범위에 안 걸림).
