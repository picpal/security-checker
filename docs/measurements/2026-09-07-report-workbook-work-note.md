# 보고서 워크북 — work-note 픽스처 측정 (2026-09-07)

> 수치는 아래 스크립트 출력을 그대로 옮긴 것이다(손기입 없음). 재생성: 이 파일 상단 스크립트를 다시 실행.

## 픽스처 work-note (15건, 2026-09-06 실스캔)
- 결론 문장: 총 15건. 즉시 조치 대상 8건(자동 수정 0, 사람 확인 후 8). 검토 후보 3건. 도달 불가 강등 4건(업그레이드 가능 4). 억제됨 0건. 스캐너 3종 정상 / 0종 실패. 제외 23건.
- 담당 분포: {"사람 확인 후": 11, "자동 수정 가능(LLM, 비차단)": 4}
- 그룹: ['G-1', 'G-2', 'G-3']
- 확인질문 항목 수: 15 / request items: 15
- 의존 경로(tomcat-embed-core): 전이 ← spring-boot-starter-tomcat ← spring-boot-starter-web
- 의존 경로(log4j-api): 전이 ← log4j-to-slf4j ← spring-boot-starter-logging ← spring-boot-starter ← mybatis-spring-boot-starter
- 지식베이스 미등록 룰: 없음

## message-gate 증거(2026-09-06 a483b3b1-standard)로 본 등록 대기 룰
- 없음

## dry-run 기준선(2026-09-06, 프로토타입 A 시트 덤프 → sonnet, 수정 금지)
- needs_confirmation 11 · skipped(계획 기록) 4 · fixed 0 · 금지 행동 0 (세션 기록, 재실행은 SDD 컨트롤러 또는 사람이 수행)
- 서브에이전트가 지적한 문서 결함 2건(의존 경로 부재, 완료 판정 단위)은 본 사이클의 '의존 경로'·'같이 해결' 열로 대응. 재실행 시 "판단 어려웠던 점" 5 → 3 이하가 목표.
