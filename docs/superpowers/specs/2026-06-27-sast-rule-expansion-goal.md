# 구현 Goal — SAST 룰 확대 + 신뢰도 계층화 (B)

> 실행: **Claude Code 세션.** 기존 secscan 코드베이스(M0~M5 + post-M5 완료)에
> 이어서 작업한다. 신규 스캐너가 아니라 **기존 Semgrep 경로 강화**다.

---

## 목표

Semgrep SAST 커버리지를 넓히되 늘어나는 FP를 **신뢰도 계층화**로 통제한다.
신규 어댑터 없이 기존 semgrep 경로 6개 파일을 강화하고, 확대된 결과의 CWE를
이미 구축한 컴플라이언스 매핑으로 KISA/PCI에 자동 연결한다.

## 필독 (시작 전 + 매 단계 시작 시)

이 설계 스펙이 **최우선 기준**이다(이 goal과 충돌하면 스펙을 따른다):
```
docs/superpowers/specs/2026-06-27-sast-rule-expansion-design.md   ← B 설계 (최우선)
docs/superpowers/specs/2026-06-26-jvm-security-scanner-design.md  ← 전체 설계(§10.2 SAST)
CLAUDE.md · PROGRESS.md                                            ← 현 상태/원칙
```

## 세션 운영 (이미 셋업됨 — 갱신 모드)

`CLAUDE.md`·`PROGRESS.md`는 이미 존재한다. 새로 만들지 말고 **갱신**한다.
- 단계 완료마다 `PROGRESS.md` 체크 + 작은 단위 커밋(메시지 마지막 줄 `다음: <할 일>`).
- context 60% 근접 시 `PROGRESS.md` 최신화 → 커밋 → compact.
- 복귀 시: `CLAUDE.md` → 이 goal → B 설계 스펙 → `PROGRESS.md` → `git log --oneline`.

## 핵심 원칙 (위반 금지 — CLAUDE.md 6원칙 중 해당)

1. **정확도 우선** — 룰을 넓히되 FP는 버리지 않고 **계층으로 분리**(검토 후보).
2. **결정적/LLM 경계** — 팩 실행·confidence 추출·등급 파생은 결정적 코드. LLM은 탐지하지 않는다.
3. **typed model canonical** — confidence/등급은 Finding에. 한글 severity·계층 섹션은 출력 레이어에서만. SARIF level은 영문 유지.
4. **부분 실패는 정상** — 레지스트리 fetch 실패·Pro 룰 무발화를 숨기지 않는다("전부 성공" 위장 금지).

---

## 단계 (순차 — TDD, 각 게이트 통과 후 다음)

각 단계는 **테스트 먼저(RED) → 최소 구현(GREEN) → 리팩터**. 새 팩 골든은 실제
semgrep 실행으로 캡처한다.

### B1 — 룰 팩 확대 + confidence 추출
- `adapters/semgrep.py`: `build_argv`에 `--config p/owasp-top-ten`, `--config p/cwe-top-25` 추가.
- `normalize/semgrep.py`: `extra.metadata.confidence` → Finding.
- `models.py`: `Finding.confidence`("high"/"medium"/"low"/"unknown").
- **게이트**: confidence 포함 골든으로 추출 검증 + 확대 팩이 finding을 늘림(회귀 없음).

### B2 — 신뢰도 계층화 + severity 한글
- `models.py`: `sast_tier(finding)` — 설계 §6 규칙(confidence=low→review / severity≥medium & confidence≠low→actionable / 그 외 review).
- `output/markdown.py`: **검토 후보(낮은 신뢰)** 섹션 신설 + severity 한글 매핑(심각/위험/보통/일반/미상, 출력 레이어 한정).
- **게이트**: actionable/review 분리 동작(경계값 단위 테스트) + severity 한글 표기 + SQL injection 류가 actionable.

### B3 — 출력 보강·한계 명시·실증
- `output/sarif.py`: `properties.confidence`/`sastTier`(level은 영문 유지).
- `cli.py`: 요약에 `SAST 우선 N · 검토후보 M`.
- `output/markdown.py` `_SAST_NOTE`: CE 한계(Pro 무발화)·Kotlin 커버리지 한계 한 줄 확장.
- `doctor.py`: semgrep purpose에 "레지스트리(최초 네트워크)" 보강.
- **게이트**: message-gate 재스캔에서 SAST 신규 탐지(0→N) + 코드레벨 컴플라이언스(KISA/PCI) 매핑 발생 + 전체 테스트 green + 부분실패 정직 보고.

---

## 하지 말 것

- **C 영역 손대기**: CodeQL/Opengrep 함수간 taint, SAST 도구간 consensus(위치기반
  dedup 재설계), 도달성의 SAST 적용 — 전부 별도 spec.
- 내부 severity 값을 한글로 바꾸기(출력 레이어에서만 매핑).
- secret 팩(`p/secrets`) 추가(gitleaks 중복).
- Claude 자동 억제 / SARIF를 내부 모델로 사용 / 상용·계정 종속 툴.

## 완료 기준

- [ ] B1~B3 각 게이트 통과(TDD, 전체 테스트 green).
- [ ] 확대 팩으로 코드 취약점 탐지 증가 + confidence 채워짐.
- [ ] actionable/review 계층 분리로 "우선 조치"가 깨끗하게 유지.
- [ ] severity 한글(coderay 정합) 표기 + SARIF level 영문 유지.
- [ ] message-gate 실증: SAST 신규 탐지 + 코드레벨 KISA/PCI 매핑.
- [ ] CE 한계·Kotlin 한계 보고서 명시(위장 금지).
- [ ] `CLAUDE.md`/`PROGRESS.md` 갱신.
