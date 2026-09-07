# lessons.md — 수행 중 걸린 제한·삐걱거린 지점 (사실만, 날짜순)

> 형식: **무엇이 걸렸나** → 원인(확인된 것만) → 대응/백로그. 추측은 "미확인" 으로 표시.

## 2026-09-07 보고서 워크북 사이클 (SDD 11 태스크 + 최종 리뷰)

- **플랜 계수 오기 3건이 구현자에게 그대로 전달됨**: rules.json "12건"(실제 10), Task 8 "17 passed"(실제 16), Task 5 테스트의 행 조회 id(상대화 후 id 가 바뀜). 원인: 플랜 작성 시 손계산. 대응: 프리플라이트 스캔에서 잡아 판정으로 전달(R-A/R-B). 백로그: 플랜의 숫자·id 는 스크립트 출력으로 박기.
- **spec·플랜 양쪽이 놓친 Critical**: `Finding.id` 가 dedup_key(경로 포함) 해시라 `--target` 상대화로 SAST/secret id 가 바뀌는데, `--check-result` 의 재스캔 쪽은 상대화 없이 비교 → 거짓 fixed 가 전부 "일치". 픽스처가 상대경로뿐이라 테스트로 안 드러남. 대응: 재스캔도 같은 target 으로 상대화 + 절대경로 픽스처 회귀 테스트(20b9ae0). 교훈: **경로 파생 id 가 있는 시스템에서 상대화는 양쪽에 대칭으로**, 픽스처는 절대경로 케이스를 반드시 하나 둔다.
- **플랜 코드가 결함을 명령한 경우 2건**: build_report 호환 분기의 bom 폴백 소실(Task 9), 측정 문서 스크립트가 자기 절을 덮어씀(FR-7). 리뷰어가 plan-mandated 로 잡아 판정으로 수정. 교훈: 호환 래퍼는 만들지 말고 파이프라인 하나로(FR-6 에서 제거).
- **팀메이트 메시지 잘림**: 리뷰어 보고가 긴 경우 전송 중 잘려 2회 재요청(final review, re-review). 대응: 리뷰어에게 "보고서를 파일에 쓰고 요약만 답하라" 로 바꿔야 함(구현자는 이미 그렇게 함). 백로그: reviewer-common 에 파일 출력 규칙 추가.
- **haiku 구현자는 전사 태스크에 문제 없음**(Task 1·2·3·6·8 전부 리뷰 clean). 통합 태스크(5·7·9·10·11)는 sonnet. 최종 리뷰·재리뷰는 opus 가 실제 실행 재현(ID 불일치 19/19, 휠 빌드)까지 해 값어치가 있었음.
- **SDD 워크스페이스는 git-ignored 스크래치**라 삭제 전 레저·최종 리뷰를 scratchpad 로 복사해야 rulings 목록을 복원할 수 있음(이번엔 복사함).

## 2026-09-07 message-gate 점검 (새 파이프라인 첫 실사용)

- **standard 프로파일이 도달성을 크기 제한으로 생략**(`도달성: 미적용 (size)`) → 23건 전부 reachability unknown, SCA 가 전부 조치대상으로 남음. 경고 한 줄뿐이라 놓치기 쉬움. 대응: `--allow-large` 재실행. 백로그: detect 가 모듈 수·LOC 로 `--allow-large` 필요를 추천하거나, 요약에 "도달성 생략 → SCA N건 강등 판정 불가" 를 굵게.
- **`--allow-large` 실행 606초, 도달성 결과 `ran=False, reason=error`**: 엔진(`reachability/engine.py`)의 `except Exception → "error"` 분기. 캐시 디렉토리 `.secscan/reach/c4a825a6173a87dc/`(message-gate 해시)가 비어 있음 → depscan/atom 산출물이 하나도 안 나옴. 캠페인 2026-09-06 실측(run_snapshot, a483b3b1, 격리 GRADLE_USER_HOME)은 156.9s 에 도달성 성공. 차이 후보(미확인): 대상 HEAD(b6443a34 vs a483b3b1) / CLI 기본 캐시 경로가 cwd 기준 / 예외 메시지가 어디에도 남지 않음. **대응 백로그**: (1) 도달성 예외 메시지를 findings.json meta.reachability 에 기록(지금은 "error" 한 단어), (2) 600s 를 넘기면 부분 결과 대신 즉시 "timeout" 으로 구분, (3) run_snapshot 과 CLI 경로 차이 재현 실험.
- **도달성 실패 시 SCA 전건이 "조치대상·자동 수정(LLM)" 으로 남음**: unknown 은 강등되지 않는다는 규칙(정확) 때문인데, 이번엔 5건 전부 의존 경로가 `전이 ← … ← checkstyle`(빌드 도구 의존성)이라 런타임 노출과 무관할 가능성이 큼(사실: BOM 의존 경로 열). cdxgen BOM 이 빌드 플러그인 의존성을 포함하고 secscan 이 scope(runtime/build)를 구분하지 않음. **백로그**: 의존 경로 루트가 빌드 플러그인(checkstyle·spotbugs 등)이면 "빌드 도구 의존" 을 사실 열에 표기하고 확인 질문 대상에 포함.
- **커스텀 룰 `mybatis-sqli-identifier` 가 주석에서 발화**: 11건 중 7건이 XML `<!-- -->`·Javadoc 안의 `${...}` 설명 텍스트(LgCarrierMapper.xml:18·19, OldLgCarrierMapper.xml:36·37·60, LgCarrierMapper.java:40, OldLgCarrierMapper.java:70·92). 실행 쿼리는 3건(xml:27·46·69)뿐. **백로그**: 룰에 주석 제외(semgrep `pattern-not-inside` 또는 언어별 comment 제외) + 픽스처에 주석 케이스 음성 추가.
- **시크릿 6건 중 5건이 test/loadtest/docs 경로**(application-test.yml ×2, AuthServiceTest.java, application-loadtest.yml, docs/testing ×2). `is_test_path` 강등은 SAST 에만 적용되고 secret 카테고리는 전부 P1 조치대상. loadtest 와 test 의 hmac.secret 은 같은 값(해시 대조). **백로그**: secret 에도 test 경로 강등(review) 적용 여부 결정 — 단 loadtest 프로파일은 실환경 접속 가능성 확인 필요.
- **하드코딩 자격증명 룰이 정규식 상수에 발화**: `TOKEN_PROFILE_REGEX = "(?:mg|message-gate)-[a-z0-9-]+"`(KmsProfilePolicy.java:30). 상수명의 TOKEN 접두 매칭. **백로그**: 값이 정규식 메타문자 위주면 미발화(음성 픽스처 추가).
- **해석 계층은 설계대로 동작**: report-request 18건 → Claude 가 코드 읽고 interpretations.json 작성 → 검증기 18/18 수용, 거부 0. 단 request 의 finding ID(상대화 공간)가 findings.json 의 ID 와 달라 사람이 둘을 대조하려면 헷갈림(설계 §12(f)). **백로그**: request 항목에 `raw_id`(findings.json 기준) 를 함께 싣기.
- **첫 실행(도달성 size 생략)은 6.4초, 두 번째(--allow-large)는 606초**: 같은 대상·같은 도구인데 도달성 하나로 100배 차이. 요약 출력이 "미적용 (size)" 한 줄이라 사용자가 노이즈 제거가 빠진 줄 모르기 쉬움.
