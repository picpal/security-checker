# SAST 룰 확대 + 신뢰도 계층화 (B) — 설계 문서

> 코드 취약점 탐지(SAST) 커버리지를 넓히되, 늘어나는 FP를 **신뢰도 계층화**로
> 통제한다. 신규 스캐너가 아니라 **기존 Semgrep 경로 강화**다.
>
> _v2 (2026-06-27): codex 독립 검토 반영 — confidence 정규화/기본값, CLI exit-code
> 게이팅, 팩 메타·dedup 가정, doctor 런타임 점검을 보강._

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
- semgrep `metadata.confidence` 추출(**정규화**) → typed Finding.
- 신뢰도 계층화: `severity` + `confidence` → `actionable` / `review` 파생.
- **CLI exit-code 게이팅을 tier에 맞게 수정**(review SAST는 CI 비차단).
- 보고서에 **검토 후보(낮은 신뢰)** 섹션 신설.
- severity 표기를 coderay 정합 한글 4+1단계로(출력 레이어, **요약 포함 전 위치**).
- CE 한계(Pro 무발화)·네트워크·Kotlin 커버리지 한계 명시 + doctor 런타임 점검.

### 비범위 (C 또는 별도)
- CodeQL/Opengrep 함수간 taint.
- **SAST 도구간 consensus**(같은 위치를 다른 도구가 지목 → 신뢰 부스트). 현재
  `dedup_key`가 `rule_id`를 포함해 도구·룰별로 분리되므로 위치기반 합의는 dedup
  재설계가 필요하다 → **C 스펙에서** taint 연동과 함께. B에서 `consensus.score`는
  1 고정이며 계층화 신호로 쓰지 않는다.
- **semantic same-location 중복 제거**: 확대 팩(security-audit/owasp-top-ten/
  cwe-top-25)이 같은 취약점을 *다른 rule_id*로 중복 보고할 수 있다. `dedup_key`가
  rule_id를 포함하므로 exact 중복만 합쳐지고 같은 위치·다른 룰은 남는다. B는 이를
  해결하지 않는다(위치기반 dedup 재설계는 C). 따라서 **"우선 버킷이 완전히 깨끗"
  하다고 주장하지 않는다** — 중복 actionable이 남을 수 있음을 보고서가 인정한다.
- 도달성의 SAST 적용(도달성은 SCA 전용 개념 유지).

## 3. 설계 원칙 (해당 절)

1. **정확도 우선** — 룰을 넓히되 FP는 *버리지 않고* 계층으로 분리. confidence 신호가
   없으면 우선 버킷에 넣지 않는다(원칙1).
2. **결정적/LLM 경계** — 팩 실행·confidence 추출/정규화·등급 파생 모두 결정적 코드.
   LLM은 탐지하지 않는다(원칙2).
3. **typed model canonical** — confidence/등급은 Finding에. 한글 severity·계층 섹션은
   출력 레이어에서만. SARIF level은 영문(원칙3).
4. **부분 실패는 정상** — 레지스트리 fetch 실패·Pro 룰 무발화·semgrep 런타임 손상을
   숨기지 않는다(원칙5).

## 4. 아키텍처 / 변경 맵

신규 어댑터 없음. 기존 Semgrep 경로의 **8개 파일**을 수정한다.

| 파일 | 변경 |
|---|---|
| `adapters/semgrep.py` | `build_argv`에 `--config p/owasp-top-ten`, `--config p/cwe-top-25` |
| `normalize/semgrep.py` | `confidence` 추출(정규화) + `_cwe_codes` list/string/missing 방어 |
| `models.py` | `Finding.confidence` + `normalize_confidence()` + `sast_tier()` |
| `normalize/merge.py` | 중복 병합 시 confidence 보수적(더 낮은 값) 집계 |
| `output/markdown.py` | severity 한글(요약 포함 전 위치) + SAST **검토 후보** 섹션 |
| `output/sarif.py` | `properties.confidence`/`sastTier`(level은 영문 유지) |
| `cli.py` | 요약 카운트 + **exit-code 게이팅(review 제외)** + CE 한계 안내 |
| `doctor.py` | semgrep 런타임 점검 강화(버전 추출 실패 감지) + 레지스트리 네트워크 |

`profiles.py`·`compliance.py`·`scan.py`는 **무변경**(semgrep이 이미 standard/deep,
컴플라이언스·enrich 파이프라인은 자동 연동).

## 5. 룰 팩 확대 + 팩 audit

`build_argv` 결과:
```
semgrep --config p/java --config p/security-audit \
        --config p/owasp-top-ten --config p/cwe-top-25 \
        --json --quiet --disable-version-check <target>
```
- secret 계열 팩(`p/secrets`)은 **제외** — gitleaks와 중복.
- 레지스트리 팩은 최초 실행 시 네트워크 fetch 필요. 캐시 후 오프라인 동작.
- **팩 audit (P1)**: `metadata.confidence`는 룰 작성 메타지 엔진 보장 필드가 아니다.
  B1에서 의도적 취약 픽스처에 확대 팩을 실제 실행해 **confidence 분포(high/medium/
  low/missing 카운트)를 측정**하고 골든으로 커밋한다. missing 비율이 높으면 §6 기본값
  (=review)이 recall에 주는 영향을 측정 리포트에 남긴다.

## 6. 신뢰도 계층화 (핵심)

**confidence 정규화 (P1)**: semgrep 메타는 **대문자**(`HIGH`/`MEDIUM`/`LOW`)다(골든
`semgrep-sast-app.json` 확인). severity와 동일하게, 비교·출력 전 `normalize_confidence`
로 lowercase 정규화한다. 메타가 없으면 `"unknown"`.

**신호**: `severity`(정규화 영문) + `confidence`(정규화 영문).

**파생 규칙** — `sast_tier(finding) -> "actionable" | "review"`:

| 조건 | 등급 |
|---|---|
| confidence ∈ {high, medium} **AND** severity ∈ {critical, high, medium} | **actionable** |
| 그 외 (confidence low/unknown, 또는 severity low/unknown) | **review** |

- **missing/unknown confidence → review**(severity 무관). confidence 신호가 없는 룰을
  검증된 룰과 같은 우선 버킷에 넣지 않는다(원칙1). 정보는 "검토 후보" 섹션에 남으므로
  버려지지 않는다.
- SCA·secret 에는 적용하지 않는다(기존 우선순위 로직 유지). `sast_tier`는
  `category == "sast"` 에서만 의미.

**confidence 병합 (P2)**: `merge_consensus`가 중복(exact dedup_key)을 합칠 때 confidence는
**보수적 규칙**으로 더 낮은 값을 택한다(`unknown < low < medium < high`). tiering이
파서/입력 순서에 의존하지 않게 하기 위함.

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
추가로 둔다(정직성). **요약·heading 등 모든 human-facing 위치**에 적용한다(현재 요약은
영문 출력 중 — 누락 없이 매핑). 정렬·정규화·dedup·SARIF는 영문값으로 수행한다.

## 8. 출력 구조

**Markdown 섹션** (위→아래 우선순위):
1. **우선 조치** — 도달가능/미상 SCA + secret + SAST `actionable`
2. **검토 후보 (낮은 신뢰)** — SAST `review` *(신규)*
3. **낮은 우선순위 — 도달 불가 SCA** *(기존)*
4. **억제됨 (사람 확정)** *(기존)*

- 각 finding의 severity는 한글로 표기. 컴플라이언스(KISA/PCI) 라벨은 기존 라인 유지.
- **CLI 요약**: `SAST 우선 N · 검토후보 M` 한 줄 추가(severity 한글).
- **SARIF**: `properties.confidence`, `properties.sastTier` 추가. level은 영문 유지
  (GitHub code scanning 등 기계 표준).

**CLI exit-code 게이팅 (P1)**: 현재 `_has_actionable`은 unreachable SCA가 아닌 모든
finding에 nonzero를 반환한다 → review-tier SAST도 CI를 실패시켜 계층화가 무의미해진다.
**게이트 대상 = SAST `actionable` + secret + reachable/unknown SCA**. SAST `review`는
exit code에 영향을 주지 않는다(보고서엔 표기). 이 규칙을 단위 테스트로 고정한다.

## 9. CE 한계·네트워크·Kotlin·런타임 (원칙5)

- **Pro 무발화**: CE에서 Pro 전용·일부 프레임워크 룰은 에러 없이 0건. 기존
  `_SAST_NOTE`(intraprocedural 안내)에 "CE 한계로 일부 룰 미발화 — 깊은 분석은
  C(CodeQL) 예정" 한 줄 확장. "전부 성공" 위장 금지.
- **네트워크 실패**: 레지스트리 fetch 실패 시 semgrep 어댑터가 부분실패로 격리(기존
  status). 나머지 결과는 유효. doctor에 "semgrep 레지스트리(최초 네트워크)" 보강.
- **semgrep 런타임 점검 (P2)**: `semgrep --version` 자체가 실패할 수 있다(예: CA
  trust-anchor 에러 — 검토 환경에서 실측됨). `min_version`이 없으면 present를
  satisfying으로 표시하는 현 doctor 로직의 허점 → semgrep은 **버전 추출 실패 시
  미충족(경고)**으로 런타임 손상을 드러낸다. "전부 정상" 위장 금지.
- **Kotlin**: semgrep Kotlin 커버리지가 Java보다 약함(experimental). 보고서에 한계
  명시 — 잡히는 만큼 잡되 못 잡는 것을 숨기지 않는다.

## 10. 컴플라이언스 연동 (자동, shape 방어)

semgrep 정규화는 이미 `_cwe_codes`로 CWE를 추출한다. 확대 팩의 finding이 CWE를 달고
들어오면 `enrich_compliance`(기존)가 KISA/PCI를 자동으로 채운다 → message-gate의
"컴플라이언스가 SCA에서만 나오는" 문제가 코드레벨로 해소된다. 추가 코드 없음.

**shape 방어 (P2)**: `_cwe_codes`는 `metadata.cwe`가 list라고 가정한다. 룰이 단일
**문자열**을 내면 문자 단위로 iterate해 매핑이 silently drop된다 → list/string/missing
모두 방어하도록 정규화한다.

## 11. 테스트·검증 (TDD)

- `normalize/semgrep`: confidence 추출 + **정규화(대문자→소문자)** — 골든(실제 실행 캡처).
- `normalize/semgrep`: `_cwe_codes` shape 방어(list/string/missing).
- `models.normalize_confidence`: HIGH/medium/없음 → high/medium/unknown.
- `models.sast_tier`: 등급 규칙 단위(경계값: high_conf+low_sev→review, unknown_conf+
  critical→review, medium_conf+high_sev→actionable).
- `normalize/merge`: 중복 병합 시 confidence 보수적(낮은 값) 선택.
- `output/markdown`: severity 한글(**요약 + heading 둘 다**) + 검토 후보 섹션 분리.
- `output/sarif`: properties.confidence/sastTier.
- `cli`: 요약 카운트 + **exit-code 게이팅**(review-only SAST → exit 0, actionable → nonzero).
- **게이트**: 의도적 취약 픽스처에서 (a) SQL injection 류 `actionable`, (b) 저신뢰/
  unknown 패턴 `review`, (c) review-only는 CI 통과. message-gate 재스캔에서 SAST 신규
  탐지 + 코드레벨 컴플라이언스 매핑 + 팩 confidence 분포 리포트.
- **골든 우선 (P2)**: 단위 게이트는 커밋된 골든으로. 라이브 semgrep/레지스트리 실행은
  별도 통합 체크(네트워크·캐시·버전 변동에 flaky하므로 단위 게이트로 쓰지 않음).

## 12. success 기준

1. message-gate 재스캔: SAST 코드 취약점 신규 탐지(0 → N) + 컴플라이언스 코드레벨 매핑.
2. 저신뢰/unknown 패턴이 "검토 후보"로 분리, "우선 조치"는 (semantic 중복 제외) 깨끗 유지.
3. **review-only SAST는 CI를 통과**(exit 0), actionable은 nonzero — 게이팅 정상.
4. 의도적 취약 픽스처의 알려진 패턴(SQL injection 등) 탐지 유지(회귀 없음).
5. 전체 테스트 green. 부분실패(레지스트리/Pro 무발화/semgrep 런타임)·confidence 분포
   정직 보고.

## 13. 라이선스 노트

Semgrep 엔진 LGPL-2.1, 레지스트리 룰 Semgrep Rules License v1.0(스캔 사용 허용).
상용·계정 종속 아님(원칙·spec §2 비범위에 안 걸림).
