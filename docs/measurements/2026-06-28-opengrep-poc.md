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

## 후속 전수 검증 — 격차 = 룰, C 불필요 확정

사용자 제안으로 message-gate 보안 수정 PR의 **취약 커밋 시점**을 `clone --local`로 꺼내
secscan 으로 스캔(ground-truth = coderay 수정 내역과 대조).

| CWE (PR) | 취약 패턴 | semgrep(B) | 원인 | 해결 |
|---|---|---|---|---|
| #305 SQLi | MyBatis `FROM ..._${month}` | 0 | 룰 부재 | 커스텀 룰 (실증 3건 탐지) |
| #259 하드코딩 | `PASSWORD = "loadtest-pw"` | 0 | 룰 부재/낮은 엔트로피 | 커스텀 룰 |
| #760 zero salt | `SALT_B64 = "AAAA..."` | 0 | 특화 취약(일반 룰 없음) | 커스텀 룰 |
| #476/754/404 | 빈/광범위 catch·리소스 | 0 | spotbugs(deep) 영역 | deep 활용 |

**결론**: 5개 CWE 중 cross-function taint가 필요한 것 **0개**. coderay 격차의 정체는
**룰 커버리지 + deep(spotbugs) 미활용**이지 taint 가 아니다 → **C(Opengrep/CodeQL)
불필요 확정.** 진짜 경로 = 커스텀 룰셋(MyBatis/하드코딩/zero-salt 등) + deep 프로파일.

**검증 워크플로우 확립**(재사용): `취약 커밋 clone --local → secscan → coderay diff 대조`.
ground-truth 공짜, 재현 가능 — message-gate "이미 수정됨" 부적합 문제를 우회한다.

**미확정**: #259(gitleaks)·#476(spotbugs deep)은 다른 secscan 도구 재검증이 남음(semgrep
단독 0/5 만 확인). 정확한 갭 지도엔 gitleaks/deep 재검증 필요.

**정리**: C 불필요 확정으로 PoC용 opengrep(`~/.opengrep`, `~/.local/bin/opengrep`)은 제거함.
향후 검증·구현은 semgrep + 커스텀 룰로 충분.
