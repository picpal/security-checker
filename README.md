# secscan — JVM 보안 점검 하이브리드 CLI

JVM(Java/Kotlin) 프로젝트용 보안 점검 도구. 결정적 오케스트레이터가 오픈소스 스캐너를
병렬 실행·정규화하고, **도달성(reachability) 분석으로 노이즈를 걷어낸 뒤**, Claude가
증거를 해석해 보고서를 낸다.

- **설계 문서(spec)**: [`docs/superpowers/specs/2026-06-26-jvm-security-scanner-design.md`](docs/superpowers/specs/2026-06-26-jvm-security-scanner-design.md)
- **구현 goal**: [`docs/superpowers/specs/2026-06-27-impl-goal.md`](docs/superpowers/specs/2026-06-27-impl-goal.md)
- **진행 상황**: [`PROGRESS.md`](PROGRESS.md)

## 핵심 가치
**정확도 우선.** "FP가 많으면 아무도 안 쓴다"가 이 프로젝트의 1번 설계 제약이다.

## 빠른 시작 (개발)
```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest          # 테스트
.venv/bin/secscan doctor  # 환경 점검
```

## 상태
구현 진행 중 (M0 doctor부터). 자세한 진행은 `PROGRESS.md` 참조.
