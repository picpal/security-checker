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

## 상태: M0~M5 전부 완료 ✅ (160 tests green, 2026-06-27)
<!-- goal 의 모든 마일스톤·전체 완료 기준 충족. 다음은 백로그(별도 사이클). -->
- **M0** doctor / **M1** 정확한 SCA(FP 89%↓, GT 100%) / **M2** Secret(gitleaks+trufflehog 정책) / **M3** SAST(semgrep, CE taint 한계) / **M4** 억제(provenance/evidence/expiry/scope, baseline, stale 무효화, 자동억제 금지) / **M5** deep(spotbugs+findsecbugs 바이트코드 — CE 놓친 CWE-78 탐지, 빌드실패 격리).
- 프로파일 quick/accurate-sca/standard/deep 동작. `secscan detect|scan|doctor`. 자연어 점검 시연 완료.
- **아키텍처**: 새 스캐너 = adapters/<tool>.py + normalize/<tool>.py + normalize._PARSERS 한 줄 + profiles + doctor REQUIREMENTS. 카테고리 전용(도달성=SCA, 검증=secret). 실제 스캔(네트워크/빌드)은 Bash dangerouslyDisableSandbox=true. Finding.dedup_key가 억제 매칭 키.
- **모델**: Finding{category,severity,tool,rule_id,cwe,owasp,component,advisory,location,reachability,consensus,verified,suppression}.
- **백로그(미착수)**: IaC/DAST/CI/주기점검/Dependency-Track/Opengrep/CodeQL(cross-function taint)/LSP.

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
