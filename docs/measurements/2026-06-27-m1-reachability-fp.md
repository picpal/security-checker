# M1 실측 — 도달성(reachability)의 FP 감소 효과 / 비용

- **일자**: 2026-06-27
- **대상 픽스처**: `fixtures/vuln-maven-app` (Maven)
  - `commons-text 1.9` — CVE-2022-42889 (Text4Shell): 앱이 `StringSubstitutor` **직접 호출 = 도달 가능**
  - `snakeyaml 1.30` — CVE-2022-1471 외 6건: pom 선언만, **미호출 = 도달 불가**
  - (전이) `commons-lang3 3.11` — CVE-2025-48924: 앱 직접 호출 없음
- **스택**: Trivy 0.71.2 + osv-scanner 2.4.0 (탐지) · OWASP dep-scan 6.2.0 + atom (도달성, SemanticReachability)
- **재현(오프라인·결정적)**: `pytest tests/test_gate_m1.py` (골든 기반)
- **재현(실제 E2E)**: `secscan scan --target fixtures/vuln-maven-app --profile accurate-sca --out out`

## 정확도 — FP 감소

| 지표 | 값 |
|---|---|
| 탐지 총건수 (Trivy ∪ osv, 합의 dedup) | **9** |
| 도달 가능 (조치 대상) | **1** (commons-text / CVE-2022-42889) |
| 도달 불가 (우선순위 강등) | **8** (snakeyaml ×7, commons-lang3 ×1) |
| 미상 | 0 |
| 조치 대상: 도달성 **off → on** | **9 → 1** |
| **노이즈 감소율** | **89%** |
| Ground-truth 정확도 (expected.json 대비) | **100%** (reachable 1/1, unreachable 1/1, 오판 0) |

→ 개발자가 봐야 할 알림이 9건에서 **1건**으로 줄었다. 그 1건은 실제로 악용 가능한 경로
(`App.interpolate → StringSubstitutor.replace`)를 가진 CRITICAL 이다. "FP가 많으면 안 쓴다"는
1번 제약을 도달성이 직접 해소한다.

## 합의(consensus)

- commons-text·snakeyaml 8건: Trivy ∩ osv (합의 2) — 신뢰도↑
- commons-lang3 (전이): Trivy 단독 (합의 1) — osv `--no-resolve` 가 전이 미해석

## 비용

| 항목 | 값 | 비고 |
|---|---|---|
| dep-scan SemanticReachability (fresh) | **~45초** | atom 슬라이스 생성 포함, 소형 픽스처 |
| 재실행 (atom 슬라이스 캐시 hit) | ~즉시 | 코드 해시별 `cache-dir` 재사용(안전장치 2) |
| 메모리 | 문제 없음 | 24GB 환경, 소형 프로젝트 |
| Trivy/osv (DB 캐시 후) | 수 초 | 첫 실행은 Trivy DB 다운로드 별도 |

> ⚠️ 비용은 **코드베이스 크기에 비례**한다. dep-scan 은 대형 프로젝트에서 대용량 메모리·수십 분이
> 들 수 있어 4중 안전장치(크기 인지 자동 / 캐싱 / 예산+폴백 / doctor 사전점검, spec §10.1)로
> 관리한다. 임계 초과 시 `reachability=unknown` 으로 폴백하고 탐지 결과는 유지한다.

## 한계 (보고서에 항상 명시)

도달성 판정은 **앱 레벨 호출 그래프** 기준이다. reflection·DI(Spring proxy)·역직렬화·동적
디스패치·애노테이션 라우팅, 그리고 **전이 의존 내부 호출**은 정적 분석 사각지대다. 따라서
'도달 불가'는 *우선순위 강등*의 근거일 뿐 **안전 보증이 아니다**. 억제는 사람이 증거를 확인해
확정한다(자동 억제 없음 — M4).

## 결론

도달성은 이 도구의 정확도 핵심이 맞다(89% 노이즈 감소, 오판 0). 비용은 크기 비례라 안전장치로
관리 가능하다. → **M1 게이트 통과. 도달성 투자 지속할 가치 있음.**
