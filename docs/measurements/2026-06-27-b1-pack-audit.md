# B1 팩 audit — 확대 팩 효과 + confidence 분포 (2026-06-27)

spec §5(팩 audit) 요구에 따라, 확대 팩(`p/owasp-top-ten` + `p/cwe-top-25`)이 실제로
finding을 늘리는지와 `metadata.confidence` 분포(→ missing→review 정책 영향)를 실측.

## 방법
의도적 취약 픽스처(`fixtures/sast-app`, Java)와 실프로젝트(`message-gate`, Java)에
현행 팩 vs 확대 팩을 실제 semgrep 1.168.0로 실행(read-only).

## 결과

| 대상 | 현행 팩 | 확대 팩 | scanned | confidence 분포 |
|---|---|---|---|---|
| sast-app (의도 취약 Java) | 1 | 1 | - | MEDIUM ×1 |
| message-gate (Spring Boot, Java 329+) | 0 | **0** | 451 | (없음) |

- message-gate는 451 파일을 실제 스캔(errors 1 = `gradlew` 쉘스크립트 syntax, 무관).
  **0건은 위장이 아니라 실측**(원칙5).
- 확대 팩은 두 샘플에서 추가 탐지 0 (sast-app 1→1, message-gate 0→0).

## 발견 (중요)

1. **message-gate는 패턴형 SAST가 잡을 게 없다.** Java 329개지만 잘 짜인 Spring
   Boot 코드(JPA/Repository 등) — semgrep CE 패턴 룰(formatted-sql-string 등)에
   걸리는 raw SQL/명령 실행 패턴이 없다. B(패턴 확대)의 한계가 아니라 코드가 깨끗.

2. **B/C 분리가 옳았음을 실증.** message-gate에 SAST 격차가 있다면(coderay가 잡는
   것이 있다면) 그것은 패턴형(B)이 아니라 **함수간 흐름(C=taint)** 영역이거나
   coderay 전용 룰이다. B로는 그 격차를 메울 수 없음이 데이터로 확인됨.

3. **confidence 분포는 가용 샘플로 빈약.** 관측된 신호는 security-audit 룰의
   MEDIUM 1건뿐. owasp-top-ten/cwe-top-25 룰의 missing 비율은 finding이 나와야
   측정 가능 → 취약 패턴이 풍부한 코드 확보 시 재측정. 그때까지 **missing→review**가
   안전 기본값(원칙1).

## 함의 (스펙/goal 반영)

- **B success #1("message-gate SAST 0→N") 재해석**: message-gate는 패턴 취약점이
  없는 코드라 0이 정상. B 검증은 (a) 단위 게이트(정규화/tier/exit/severity, 골든·
  합성)와 (b) 취약 패턴이 있는 코드에서의 탐지로 한다. message-gate 0건 자체가
  "패턴형으로는 못 잡는다 → C 필요"라는 **음성 증거**로 가치가 있다.
- B는 코드 취약점이 있는 프로젝트를 위한 커버리지·계층화 기능으로 유효. 다만
  coderay와의 message-gate 격차 해소는 **C(CodeQL taint)** 가 본질임이 재확인됨.
