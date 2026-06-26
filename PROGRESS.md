# 진행 상황

현재 마일스톤: **전체 완료 — 마무리 검증**

## 인프라 (M0보다 먼저)
- [x] CLAUDE.md 생성
- [x] PROGRESS.md 생성
- [x] Python 패키지 스캐폴딩 (pyproject, secscan/, tests/, venv)

## M0 — doctor ✅
- [x] 스캐너 설치 점검 (trivy / osv-scanner / depscan / atom)
- [x] 런타임 점검 (Java 21 / Node / 가용 메모리)
- [x] 누락 시 설치 가이드 출력
- [x] CLI `secscan doctor` 렌더링 + exit code (정상 0 / 문제 1)
- [x] **게이트 통과**: 미설치 4종 정확 탐지 + Java21/Node/메모리 인식 (22 tests green)

## M1 — 정확한 SCA (★정확도 증명)
- [x] Trivy 어댑터
- [x] osv-scanner 어댑터 (v2 `scan source`, exit1=취약점발견)
- [x] typed finding 모델 (spec §6) — secscan/models.py
- [x] 정규화 raw→typed (골든 테스트: trivy/osv 실제 출력)
- [x] 합의 dedup (Trivy ∪ osv + consensus score) — merge_consensus
- [x] 취약 픽스처 (commons-text=도달가능 / snakeyaml=도달불가) + golden 캡처
- [x] 오케스트레이터 (병렬 · status · 자원 거버넌스 · 부분실패 격리)
- [x] dep-scan 도달성 엔진 (4중 안전장치) + usage-슬라이스 provider
- [x] SARIF 2.1.0 출력 (도달성 주석, 자동억제 X)
- [x] Markdown 보고서 출력 (도달가능 우선 + 사각지대 명시)
- [x] scan CLI 커맨드 (`secscan scan --profile --target --out`)
- [x] 도달성 on/off FP 감소 + 비용 실측 리포트 (docs/measurements/2026-06-27-m1-*)
- [x] **게이트 통과**: unreachable 표기 ✓ + FP 89%↓(9→1) ✓ + ground-truth 100% ✓ + unknown 폴백 ✓ + 90 tests green

### M1 실측 결과 (게이트 증명)
- 실제 E2E: `secscan scan --target fixtures/vuln-maven-app --profile accurate-sca`
- 조치대상 9→1 (노이즈 89% 감소), 도달성 ground-truth 100% (commons-text 도달가능 / snakeyaml 도달불가)
- dep-scan ~45s(fresh), 슬라이스 캐시 재사용 시 즉시

## M2 — Secret ✅
- [x] Gitleaks 어댑터 (위치형 finding, raw 시크릿 미저장)
- [x] opt-in TruffleHog (`--verify-secrets` / `--network-off` / never-validate)
- [x] **게이트 통과**: 3건 탐지 · 검증 opt-in · network-off 차단 (E2E 3정책 확인, 116 tests)

## M3 — SAST ✅
- [x] Semgrep CE 어댑터 (p/java + p/security-audit)
- [x] taint intraprocedural 한계 보고서 명시 (markdown _SAST_NOTE, spec §10.2)
- [x] **게이트 통과**: SQL injection(CWE-89) 탐지 + typed 통합 (E2E, 125 tests). CE 한계로 인자경유 command injection 미탐지(문서화)

## M4 — 억제 ✅
- [x] 억제 엔트리 (provenance / evidence / expiry / scope 필수 검증)
- [x] baseline (기존 이슈 일괄 억제, 신규만 알림)
- [x] 영속화 JSON(OpenVEX 영감) + propose(제안만, 자동 억제 없음)
- [x] stale 무효화 (만료 / 의존성 버전(dedup_key) / 도달성 unreachable→reachable)
- [x] SARIF suppressions emit(사람 확정만) + markdown 억제 섹션 + cli 플래그
- [x] **게이트 통과**: 재발 억제 + 버전/도달성 변경 무효화 + 제안만 (146 tests)

## M5 — deep (experimental) ✅
- [x] SpotBugs + FindSecBugs 어댑터 (빌드 연동: mvn/gradle compile → 바이트코드)
- [x] 빌드 실패 partial 격리 (예외도 skipped 로 안전 처리)
- [x] **게이트 통과**: 바이트코드가 COMMAND_INJECTION(CWE-78, Semgrep CE 놓친 것)+SQL(CWE-89) 탐지 + 빌드실패 안전격리 (154 tests)

## 프로파일
- [ ] quick / accurate-sca / standard / deep

## 전체 완료 기준 ✅
- [x] M0~M5 각 검증 게이트 통과 (160 tests green)
- [x] 프로파일(quick/accurate-sca/standard/deep) 동작
- [x] 취약 픽스처 E2E + 도달성 정확도/비용 실측 리포트(docs/measurements/2026-06-27-m1-*)
- [x] 정규화 골든 테스트 + 부분실패 테스트 green
- [x] 자연어 "이 프로젝트 점검해줘" → 스택 감지(maven/java) → 프로파일(standard) → typed findings → 보고서 시연
- [x] CLAUDE.md / PROGRESS.md 최종 갱신

## 상태: M0~M5 전부 완료 (160 tests). 다음 사이클 후보 = 백로그(IaC/DAST/CI/주기점검/Opengrep/CodeQL).
