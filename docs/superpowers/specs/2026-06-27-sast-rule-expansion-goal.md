# 구현 Goal — SAST 룰 확대 + 신뢰도 계층화 (B)

> 실행: **Claude Code 세션.** 기존 secscan 코드베이스(M0~M5 + post-M5 완료)에
> 이어서 작업한다. 신규 스캐너가 아니라 **기존 Semgrep 경로 강화**다.
>
> _v2 (2026-06-27): codex 독립 검토 반영._

---

## 목표

Semgrep SAST 커버리지를 넓히되 늘어나는 FP를 **신뢰도 계층화**로 통제한다. 신규
어댑터 없이 기존 semgrep 경로 **8개 파일**을 강화하고, 확대된 결과의 CWE를 이미
구축한 컴플라이언스 매핑으로 KISA/PCI에 자동 연결한다.

## 필독 (시작 전 + 매 단계 시작 시)

이 설계 스펙이 **최우선 기준**이다(이 goal과 충돌하면 스펙을 따른다):
```
docs/superpowers/specs/2026-06-27-sast-rule-expansion-design.md   ← B 설계 v2 (최우선)
docs/superpowers/specs/2026-06-26-jvm-security-scanner-design.md  ← 전체 설계(§10.2 SAST)
CLAUDE.md · PROGRESS.md                                            ← 현 상태/원칙
```

## 세션 운영 (이미 셋업됨 — 갱신 모드)

`CLAUDE.md`·`PROGRESS.md`는 이미 존재한다. 새로 만들지 말고 **갱신**한다.
- 단계 완료마다 `PROGRESS.md` 체크 + 작은 단위 커밋(메시지 마지막 줄 `다음: <할 일>`).
- context 60% 근접 시 `PROGRESS.md` 최신화 → 커밋 → compact.
- 복귀 시: `CLAUDE.md` → 이 goal → B 설계 스펙 → `PROGRESS.md` → `git log --oneline`.

## 핵심 원칙 (위반 금지)

1. **정확도 우선** — 룰을 넓히되 FP는 버리지 않고 **계층 분리**. confidence 신호 없으면 우선 버킷에 안 넣는다.
2. **결정적/LLM 경계** — 팩 실행·confidence 추출/정규화·등급 파생은 결정적 코드. LLM은 탐지하지 않는다.
3. **typed model canonical** — confidence/등급은 Finding에. 한글 severity·계층 섹션은 출력 레이어에서만. SARIF level은 영문.
4. **부분 실패는 정상** — 레지스트리 fetch 실패·Pro 무발화·semgrep 런타임 손상을 숨기지 않는다.

---

## 단계 (순차 — TDD, 각 게이트 통과 후 다음)

TDD: **테스트 먼저(RED) → 최소 구현(GREEN) → 리팩터**. 단위 게이트는 **커밋된 골든**으로.
라이브 semgrep/레지스트리는 별도 통합 체크(flaky하므로 단위 게이트로 쓰지 않음).

### B1 — 룰 팩 확대 + confidence 추출/정규화 + 팩 audit
- `adapters/semgrep.py`: `build_argv`에 `--config p/owasp-top-ten`, `--config p/cwe-top-25`.
- `models.py`: `Finding.confidence` + `normalize_confidence()`(대문자 HIGH/MEDIUM/LOW → 소문자, 없으면 "unknown").
- `normalize/semgrep.py`: `metadata.confidence` 추출 후 **정규화** → Finding. `_cwe_codes` list/string/missing 방어.
- **팩 audit**: 의도적 취약 픽스처에 확대 팩을 실제 실행해 confidence 분포(high/medium/low/missing) 측정·골든 커밋.
- **게이트**: 정규화 골든(대문자→소문자) + cwe shape 방어 단위 + 확대 팩이 finding 증가 + confidence 분포 리포트.

### B2 — 신뢰도 계층화 + severity 한글 + 병합
- `models.py`: `sast_tier(f)` — confidence ∈ {high,medium} AND severity ∈ {critical,high,medium} → actionable; **그 외(미상/저신뢰 포함) → review**.
- `normalize/merge.py`: 중복 병합 시 confidence **보수적**(더 낮은 값, unknown<low<medium<high).
- `output/markdown.py`: **검토 후보(낮은 신뢰)** 섹션 신설 + severity 한글 매핑(심각/위험/보통/일반/미상)을 **요약·heading 등 전 위치**에.
- **게이트**: sast_tier 경계값 단위(high_conf+low_sev→review, unknown+critical→review, medium+high→actionable) + merge 보수적 + severity 한글 요약+heading 둘 다.

### B3 — exit-code 게이팅·출력 보강·한계·실증
- `cli.py`: **exit-code 게이팅** — 게이트 대상 = SAST `actionable` + secret + reachable/unknown SCA. **review SAST는 exit 0**. + 요약에 `SAST 우선 N · 검토후보 M`.
- `output/sarif.py`: `properties.confidence`/`sastTier`(level 영문 유지).
- `output/markdown.py` `_SAST_NOTE`: CE 한계(Pro 무발화)·Kotlin 커버리지 한계 확장.
- `doctor.py`: semgrep **버전 추출 실패 시 미충족(경고)**로 런타임 손상 노출 + 레지스트리 네트워크 보강.
- **게이트**: exit-code(review-only → 0, actionable → nonzero) 단위 + message-gate 재스캔 SAST 신규 탐지 + 코드레벨 컴플라이언스 매핑 + 전체 green + 부분실패/분포 정직 보고.

---

## 하지 말 것

- **C 영역**: CodeQL/Opengrep 함수간 taint, SAST 도구간 consensus, **semantic
  same-location 중복 제거(위치기반 dedup 재설계)**, 도달성의 SAST 적용 — 전부 별도 spec.
- **missing/unknown confidence를 actionable로 승격**(원칙1 위반 — 무조건 review).
- 내부 severity 값을 한글로 바꾸기(출력 레이어에서만 매핑).
- secret 팩(`p/secrets`) 추가(gitleaks 중복).
- Claude 자동 억제 / SARIF를 내부 모델로 사용 / 상용·계정 종속 툴.

## 완료 기준

- [ ] B1~B3 각 게이트 통과(TDD, 전체 테스트 green, 단위는 커밋 골든).
- [ ] confidence 추출+정규화(대문자 방어) + 분포 audit 리포트.
- [ ] sast_tier: missing/unknown → review(원칙1). actionable/review 계층 분리.
- [ ] **CLI exit-code 게이팅**: review-only SAST는 CI 통과(exit 0), actionable은 nonzero.
- [ ] merge 시 confidence 보수적 병합(순서 비의존).
- [ ] severity 한글(coderay 정합) — 요약 포함 전 위치. SARIF level 영문.
- [ ] cwe shape 방어(list/string/missing) → 컴플라이언스 코드레벨 매핑.
- [ ] doctor가 semgrep 런타임 손상(버전 실패) 노출.
- [ ] message-gate 실증 + CE/Kotlin 한계 보고서 명시.
- [ ] `CLAUDE.md`/`PROGRESS.md` 갱신.
