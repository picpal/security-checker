# 진행 상황

현재 마일스톤: **M1**

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
- [ ] 오케스트레이터 (병렬 · status · 자원 거버넌스)
- [ ] dep-scan 도달성 엔진 (4중 안전장치: 크기인지 자동 / 캐싱 / 예산+폴백 / doctor 점검)
- [ ] SARIF 2.1.0 출력
- [ ] Markdown 보고서 출력
- [ ] scan CLI 커맨드 (profile/target → findings → 보고서)
- [ ] 도달성 on/off FP 감소 + 비용 실측 리포트
- [ ] **게이트**: unreachable 표기 + FP 감소 수치 + unknown 폴백 + 골든·부분실패 테스트 green

## M2 — Secret
- [ ] Gitleaks 어댑터
- [ ] opt-in TruffleHog (`--verify-secrets` / `--network-off` / never-validate)
- [ ] **게이트**: 탐지 · 검증 · network 정책 동작

## M3 — SAST
- [ ] Semgrep CE 어댑터
- [ ] taint intraprocedural 한계 보고서 명시
- [ ] **게이트**: 취약 패턴 탐지, typed 모델 통합

## M4 — 억제
- [ ] 억제 엔트리 (provenance / evidence / expiry / scope)
- [ ] baseline
- [ ] OpenVEX 루프
- [ ] stale 무효화 (의존성 / 콜패스 / 룰셋 변경)
- [ ] **게이트**: 억제 후 재발 억제 + 버전 변경 시 무효화

## M5 — deep (experimental)
- [ ] SpotBugs + FindSecBugs 어댑터 (빌드 연동)
- [ ] 빌드 실패 partial 격리
- [ ] **게이트**: 바이트코드 탐지, 빌드 실패 안전 처리

## 프로파일
- [ ] quick / accurate-sca / standard / deep

## 전체 완료 기준
- [ ] 자연어 "이 프로젝트 점검해줘" → 스택 감지 → 프로파일 선택 → typed findings → 보고서 시연
