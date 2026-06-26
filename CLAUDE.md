# security-checker — 프로젝트 메모리 (compact 생존용)

> JVM(Java/Kotlin) 보안 점검 하이브리드 CLI. 결정적 오케스트레이터가 OSS 스캐너를
> 병렬 실행·정규화하고, 도달성(reachability) 분석으로 노이즈를 걷어낸 뒤
> Claude가 증거를 해석해 보고서를 낸다.

## 복원 절차 (compact / 세션 복귀 시 순서대로 읽기)
1. 이 파일 (`CLAUDE.md`)
2. goal: `docs/superpowers/specs/2026-06-27-impl-goal.md`
3. **spec (최우선 기준)**: `docs/superpowers/specs/2026-06-26-jvm-security-scanner-design.md`
4. `PROGRESS.md`
5. `git log --oneline`

## 현재 마일스톤: M2 (Secret)
<!-- 진행하며 이 줄을 갱신한다 -->
- **M0 doctor 완료** (2026-06-27): doctor.py + cli.py. 게이트 통과.
- **M1 정확한 SCA 완료** (2026-06-27, 90 tests green): adapters(trivy/osv) · models(Finding) · normalize(골든) · merge(consensus) · orchestrator(병렬·부분실패) · reachability(engine 4중 안전장치 + depscan usage-슬라이스 provider) · output(sarif/markdown) · scan.run_scan · profiles · measure · cli scan. **게이트: FP 89%↓(9→1), ground-truth 100%.** 실측: docs/measurements/2026-06-27-m1-*.
- **M2 다음 할 일**: Gitleaks 어댑터(secret) + opt-in TruffleHog 검증(`--verify-secrets`/`--network-off`/never-validate, spec §8). secret은 위치형(location) finding — models.Location 사용. 정규화/SARIF/MD에 secret 카테고리 통합.
- **아키텍처 메모**: 새 스캐너 = adapters/<tool>.py + normalize/<tool>.py + normalize._PARSERS 한 줄 + profiles. 도달성은 SCA 전용.

## 핵심 원칙 6 (위반 금지)
1. **정확도 우선** — FP를 줄이는 레버를 모든 것에 우선.
2. **결정적/LLM 경계** — 스캐너 실행·정규화·도달성은 결정적 코드. Claude는 증거 해석자일 뿐, 판정 oracle이 아니다.
3. **내부는 typed finding 모델, SARIF는 출력 전용** (SARIF를 내부 canonical로 쓰지 말 것 — spec §6).
4. **자동 억제 금지** — 억제는 사람이 확정 (spec §12).
5. **부분 실패는 정상** — 스캐너가 죽거나 도달성이 타임아웃해도 나머지 결과는 유효하게 보고(partial-result). "전부 성공" 위장 금지.
6. **구현 언어 Python**, 어댑터 인터페이스 추상화 (새 스캐너 = 어댑터 1개 추가, 코어 무변경).

## 작업 방식
- **TDD** (`superpowers:test-driven-development`). 작은 단위로 자주 커밋. 커밋 메시지 마지막 줄에 `다음: <할 일>`.
- 각 마일스톤 시작 전 **spec §16 + 해당 절 재독**. 게이트 미통과면 다음으로 안 넘어감.
- context 60% 근접 시 `PROGRESS.md` 최신화 → 커밋 → compact.
- 의존성 최소화(설치 마찰이 최대 장벽). 가능하면 stdlib. dev 의존성만 `pytest`.

## 하지 말 것
- 백로그 손대기: IaC/DAST/CI/주기점검/패치 모니터링/Opengrep/CodeQL/LSP.
- Claude 자동 억제 / 상용·계정 종속 툴(Snyk, ggshield) / SARIF를 내부 모델로 사용.

## 환경 (2026-06-27 확인)
- Python 3.14.5 · Java 21.0.10 ✓ · Node v24.5.0 ✓ · go 없음
- 스캐너: trivy / osv-scanner / depscan / atom / semgrep / gitleaks / trufflehog **전부 미설치** (M0 doctor 테스트 대상)

## 명령어
- 테스트: `.venv/bin/pytest` (또는 `python3 -m pytest`)
- doctor: `.venv/bin/secscan doctor` (또는 `python3 -m secscan doctor`)
