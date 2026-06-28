# Opengrep 함수간 taint PoC (C 사전 검증, 2026-06-28)

C(함수간 taint) 엔진으로 **Opengrep**(CodeQL은 사유 코드 라이선스로 제외)을 골라,
secscan 어댑터를 만들기 전에 실효성을 PoC로 검증했다. 결론: **부분 가치, 단 cross-file
불가 + message-gate는 검증 부적합 타겟.**

## 검증 사실

| 항목 | 결과 |
|---|---|
| 설치 | Opengrep v1.23.0, `install.sh`(~/.local/bin), LGPL, **빌드 불필요(소스 기반)** |
| 기본(intra-file taint) | **동작** — sast-app 2건(formatted-sql + jdbc-sqli), `dataflow_trace`(source→sink) 포함 |
| `--pro`(interfile) | ❌ `"requires the pro engine, but do not have the pro engine"` — **Semgrep Pro 바이너리 필요, OSS 불가** |
| Semgrep 룰 호환 | taint 문법 동일. 단 `--config p/java` 안 됨 → `opengrep-rules` 로컬 지정 |
| message-gate | **0건**(467 파일 스캔, errors 0). Semgrep CE도 0. |

## 결론

1. **Opengrep = intra-file cross-function taint.** Semgrep CE(단일 함수)의 **상위호환**
   (sast-app: Semgrep 1건 < Opengrep 2건). 한 파일 안에서 함수 경유하는 흐름을 잡는다.
2. **cross-file(파일 경계) taint는 OSS로 불가.** Opengrep `--help`에 interfile 옵션이
   있으나 실행 시 Semgrep Pro 엔진을 요구 — fork 잔재. cross-file 은 유료(Semgrep Pro /
   GHAS CodeQL)만.
3. **message-gate 0건은 C 판단 근거로 부적합.** 두 해석이 겹친다: (a) injection 흐름이
   레이어드(Controller/Service/Repository) cross-file → OSS 불가, (b) **이미 coderay로
   점검·수정되어 취약점이 적음**(사용자 확인). 어느 쪽이든 message-gate로는 C(또는 어떤
   SAST)의 가치를 측정할 수 없다.

## 함의

- **secscan 정확도/SAST 검증은 "미수정 취약 코드"로 해야 한다.** coderay로 다듬어진
  message-gate는 0건에 가까워 부적합. 의도적 취약 픽스처나 알려진 취약 OSS를 기준으로.
- **C(Opengrep)의 객관 가치는 message-gate와 무관하게 존재**(intra-file cross-function
  > Semgrep CE). 다만 "coderay 격차 해소"가 목표라면, 그 격차가 cross-file taint인 한
  OSS로는 못 메운다 — 유료 엔진/GHAS가 유일.
- **C 본 구현 우선순위는 coderay 격차의 정체를 확인한 뒤 판단**하는 것이 합리적
  (cross-file이면 OSS 무의미 / intra-file·룰 문제면 Opengrep·룰 추가로 해결 가능).

## 설치물 (정리 대상)
PoC용 `~/.opengrep`, `~/.local/bin/opengrep`, scratchpad `opengrep-rules`는 repo에 커밋하지
않음. C 본 구현 결정 시 doctor REQUIREMENTS + 어댑터로 정식 편입.
