# 대조 — a483b3b1-standard vs gt-b-sca.json

## 단계별 attrition

raw: trivy=ok(313797B), gitleaks=ok(9393B), semgrep=ok(57924B)

| 단계 | 건수 | 증감 |
|---|---|---|
| normalize:gitleaks | 13 |  |
| normalize:semgrep | 15 | +2 |
| normalize:trivy | 48 | +33 |
| merge | 73 | +25 |
| exclude | 73 | +0 |
| compliance | 73 | +0 |
| reachability | 73 | +0 |
| final | 73 | +0 |

## 정답지 대조

- CVE 단위 recall(GT-B 합산): 37/46
- origin 별 CVE recall: dev-found 3/12 · team 34/34 (team = 보안팀 trivy 결과 재현율 성격, dev-found = 독립 증거 — spec §5 축 2)
- 항목 단위 recall: strict 47/56 · version-mismatch 포함 47/56
- 종류별: {'exact': 47, 'missed': 9}

### 미탐
| advisory | 패키지 | 설치 | 심각도(보안팀) | origin |
|---|---|---|---|---|
| CVE-2026-68763 | org.apache.tomcat.embed:tomcat-embed-core | 11.0.22 | Important | dev-found |
| CVE-2026-68569 | org.apache.tomcat.embed:tomcat-embed-core | 11.0.22 | Important | dev-found |
| CVE-2026-65927 | org.apache.tomcat.embed:tomcat-embed-core | 11.0.22 | Important | dev-found |
| CVE-2026-65637 | org.apache.tomcat.embed:tomcat-embed-core | 11.0.22 | Moderate | dev-found |
| CVE-2026-73180 | org.apache.tomcat.embed:tomcat-embed-core | 11.0.22 | Low | dev-found |
| CVE-2026-66422 | org.apache.tomcat.embed:tomcat-embed-core | 11.0.22 | Low | dev-found |
| CVE-2026-66299 | org.apache.tomcat.embed:tomcat-embed-core | 11.0.22 | Low | dev-found |
| CVE-2026-65183 | org.apache.tomcat.embed:tomcat-embed-core | 11.0.22 | Low | dev-found |
| CVE-2026-19880 | ch.qos.logback:logback-core | 1.5.32 | - | dev-found |

### 초과 탐지
| advisory | 패키지 | 설치 | 분류 |
|---|---|---|---|
| CVE-2026-40992 | org.springframework.boot:spring-boot-starter-mail | 4.0.6 | inventory-diff |

## 사람 도달성 판정 비교(일치율 산출 안 함 — 방법이 다름)

| advisory | 패키지 | 사람 판정 | 사람 근거 분류 | 우리 판정 | 우리 근거 | 판정 방법 차이 |
|---|---|---|---|---|---|---|
| GHSA-r7wm-3cxj-wff9 | com.fasterxml.jackson.core:jackson-core | unreachable | api-unused (async 논블로킹 파서(NonBlockingUtf8JsonParserBase) 미사용, 서블릿 블로킹 스택) | unreachable | - | 사람=CVE 전제조건 / 우리=패키지 prefix 존재(atom usage 슬라이스에 해당 타입 호출 유무) |
| GHSA-r7wm-3cxj-wff9 | tools.jackson.core:jackson-core | unreachable | api-unused (async 논블로킹 파서 미사용) | unreachable | - | 사람=CVE 전제조건 / 우리=패키지 prefix 존재(atom usage 슬라이스에 해당 타입 호출 유무) |
| CVE-2026-54512 | com.fasterxml.jackson.core:jackson-databind | unreachable | config-gated (@JsonTypeInfo/@JsonSubTypes/activateDefaultTyping/PolymorphicTypeValidator src 전체 0건) | unreachable | - | 사람=CVE 전제조건 / 우리=패키지 prefix 존재(atom usage 슬라이스에 해당 타입 호출 유무) |
| CVE-2026-54512 | tools.jackson.core:jackson-databind | unreachable | config-gated (polymorphic typing 미활성) | unreachable | - | 사람=CVE 전제조건 / 우리=패키지 prefix 존재(atom usage 슬라이스에 해당 타입 호출 유무) |
| CVE-2026-54513 | com.fasterxml.jackson.core:jackson-databind | unreachable | config-gated (polymorphic typing 미활성) | unreachable | - | 사람=CVE 전제조건 / 우리=패키지 prefix 존재(atom usage 슬라이스에 해당 타입 호출 유무) |
| CVE-2026-54513 | tools.jackson.core:jackson-databind | unreachable | config-gated (polymorphic typing 미활성) | unreachable | - | 사람=CVE 전제조건 / 우리=패키지 prefix 존재(atom usage 슬라이스에 해당 타입 호출 유무) |
| CVE-2026-54518 | com.fasterxml.jackson.core:jackson-databind | unreachable | api-unused (@JsonView·@JsonUnwrapped·@JsonAlias·@JsonIgnoreProperties·PropertyNamingStrategy 전부 0건 (도달 경로 미확인)) | unreachable | - | 사람=CVE 전제조건 / 우리=패키지 prefix 존재(atom usage 슬라이스에 해당 타입 호출 유무) |
| CVE-2026-54518 | tools.jackson.core:jackson-databind | unreachable | api-unused (view/alias 계열 어노테이션 0건) | unreachable | - | 사람=CVE 전제조건 / 우리=패키지 prefix 존재(atom usage 슬라이스에 해당 타입 호출 유무) |
| CVE-2026-59888 | com.fasterxml.jackson.core:jackson-databind | unreachable | api-unused (HTTP 직렬화 record 18개/15파일 전부 @JsonIgnore 0건) | unreachable | - | 사람=CVE 전제조건 / 우리=패키지 prefix 존재(atom usage 슬라이스에 해당 타입 호출 유무) |
| CVE-2026-59888 | tools.jackson.core:jackson-databind | unreachable | api-unused (record 에 @JsonIgnore 0건) | unreachable | - | 사람=CVE 전제조건 / 우리=패키지 prefix 존재(atom usage 슬라이스에 해당 타입 호출 유무) |
| CVE-2026-59889 | com.fasterxml.jackson.core:jackson-databind | unreachable | api-unused (@JsonView·@JsonUnwrapped 0건 (도달 경로 미확인)) | unreachable | - | 사람=CVE 전제조건 / 우리=패키지 prefix 존재(atom usage 슬라이스에 해당 타입 호출 유무) |
| CVE-2026-59889 | tools.jackson.core:jackson-databind | unreachable | api-unused (@JsonView·@JsonUnwrapped 0건) | unreachable | - | 사람=CVE 전제조건 / 우리=패키지 prefix 존재(atom usage 슬라이스에 해당 타입 호출 유무) |
| GHSA-mhm7-754m-9p8w | com.fasterxml.jackson.core:jackson-databind | unreachable | api-unused (@JsonView·@JsonTypeInfo(EXTERNAL_PROPERTY) 0건) | unreachable | - | 사람=CVE 전제조건 / 우리=패키지 prefix 존재(atom usage 슬라이스에 해당 타입 호출 유무) |
| CVE-2026-49844 | org.apache.logging.log4j:log4j-api | unreachable | impl-absent (log4j-core 부재(로깅 구현체 logback), 브리지 log4j-to-slf4j 는 JSON 포맷터를 타지 않음) | unreachable | - | 사람=CVE 전제조건 / 우리=패키지 prefix 존재(atom usage 슬라이스에 해당 타입 호출 유무) |
| CVE-2026-54514 | com.fasterxml.jackson.core:jackson-databind | unreachable | api-unused (InetSocketAddress 역직렬화 0건 (도달 경로 미확인)) | unreachable | - | 사람=CVE 전제조건 / 우리=패키지 prefix 존재(atom usage 슬라이스에 해당 타입 호출 유무) |
| CVE-2026-54514 | tools.jackson.core:jackson-databind | unreachable | api-unused (InetSocketAddress 역직렬화 0건) | unreachable | - | 사람=CVE 전제조건 / 우리=패키지 prefix 존재(atom usage 슬라이스에 해당 타입 호출 유무) |
| CVE-2026-54515 | com.fasterxml.jackson.core:jackson-databind | unreachable | api-unused (@JsonIgnoreProperties 0건 (도달 경로 미확인)) | unreachable | - | 사람=CVE 전제조건 / 우리=패키지 prefix 존재(atom usage 슬라이스에 해당 타입 호출 유무) |
| CVE-2026-54515 | tools.jackson.core:jackson-databind | unreachable | api-unused (@JsonIgnoreProperties 0건) | unreachable | - | 사람=CVE 전제조건 / 우리=패키지 prefix 존재(atom usage 슬라이스에 해당 타입 호출 유무) |
| CVE-2026-54516 | com.fasterxml.jackson.core:jackson-databind | unreachable | api-unused (PropertyNamingStrategy·renamed properties 0건 (도달 경로 미확인)) | unreachable | - | 사람=CVE 전제조건 / 우리=패키지 prefix 존재(atom usage 슬라이스에 해당 타입 호출 유무) |
| CVE-2026-54516 | tools.jackson.core:jackson-databind | unreachable | api-unused (PropertyNamingStrategy 0건) | unreachable | - | 사람=CVE 전제조건 / 우리=패키지 prefix 존재(atom usage 슬라이스에 해당 타입 호출 유무) |
| CVE-2026-54517 | com.fasterxml.jackson.core:jackson-databind | unreachable | api-unused (@JsonView 필터 0건 (도달 경로 미확인)) | unreachable | - | 사람=CVE 전제조건 / 우리=패키지 prefix 존재(atom usage 슬라이스에 해당 타입 호출 유무) |
| CVE-2026-54517 | tools.jackson.core:jackson-databind | unreachable | api-unused (@JsonView 0건) | unreachable | - | 사람=CVE 전제조건 / 우리=패키지 prefix 존재(atom usage 슬라이스에 해당 타입 호출 유무) |
| CVE-2026-68763 | org.apache.tomcat.embed:tomcat-embed-core | unreachable | config-gated (HTTP/2 비활성(설정 0건, Spring Boot 기본 false)) | 미탐 | - | 사람=CVE 전제조건 / 우리=패키지 prefix 존재(atom usage 슬라이스에 해당 타입 호출 유무) |
| CVE-2026-68569 | org.apache.tomcat.embed:tomcat-embed-core | unreachable | config-gated (Tomcat Realm 미사용(자체 HTTP Basic 필터)) | 미탐 | - | 사람=CVE 전제조건 / 우리=패키지 prefix 존재(atom usage 슬라이스에 해당 타입 호출 유무) |
| CVE-2026-65927 | org.apache.tomcat.embed:tomcat-embed-core | unreachable | config-gated (RewriteValve 미설정) | 미탐 | - | 사람=CVE 전제조건 / 우리=패키지 prefix 존재(atom usage 슬라이스에 해당 타입 호출 유무) |
| CVE-2026-65182 | org.apache.tomcat.embed:tomcat-embed-core | unreachable | config-gated (web.xml security-constraint 미사용) | unreachable | - | 사람=CVE 전제조건 / 우리=패키지 prefix 존재(atom usage 슬라이스에 해당 타입 호출 유무) |
| CVE-2026-65637 | org.apache.tomcat.embed:tomcat-embed-core | unreachable | config-gated (HTTP/2 비활성) | 미탐 | - | 사람=CVE 전제조건 / 우리=패키지 prefix 존재(atom usage 슬라이스에 해당 타입 호출 유무) |
| CVE-2026-73180 | org.apache.tomcat.embed:tomcat-embed-core | unreachable | config-gated (WebSocket 미사용) | 미탐 | - | 사람=CVE 전제조건 / 우리=패키지 prefix 존재(atom usage 슬라이스에 해당 타입 호출 유무) |
| CVE-2026-68525 | org.apache.tomcat.embed:tomcat-embed-core | unreachable | config-gated (formLogin 명시적 disable) | unreachable | - | 사람=CVE 전제조건 / 우리=패키지 prefix 존재(atom usage 슬라이스에 해당 타입 호출 유무) |
| CVE-2026-66422 | org.apache.tomcat.embed:tomcat-embed-core | unreachable | config-gated (security-role-ref·isUserInRole 0건) | 미탐 | - | 사람=CVE 전제조건 / 우리=패키지 prefix 존재(atom usage 슬라이스에 해당 타입 호출 유무) |
| CVE-2026-66299 | org.apache.tomcat.embed:tomcat-embed-core | unreachable | config-gated (WebSocket chat 예제 앱 미배포) | 미탐 | - | 사람=CVE 전제조건 / 우리=패키지 prefix 존재(atom usage 슬라이스에 해당 타입 호출 유무) |
| CVE-2026-65905 | org.apache.tomcat.embed:tomcat-embed-core | unreachable | config-gated (DIGEST 인증 미사용) | unreachable | - | 사람=CVE 전제조건 / 우리=패키지 prefix 존재(atom usage 슬라이스에 해당 타입 호출 유무) |
| CVE-2026-65183 | org.apache.tomcat.embed:tomcat-embed-core | unreachable | config-gated (Unix Domain Socket 커넥터 미구성(TCP 7700/9090)) | 미탐 | - | 사람=CVE 전제조건 / 우리=패키지 prefix 존재(atom usage 슬라이스에 해당 타입 호출 유무) |
| CVE-2026-19880 | ch.qos.logback:logback-core | unreachable | config-gated (SiftingAppender 미사용(appender 는 콘솔·롤링 파일 2종)) | 미탐 | - | 사람=CVE 전제조건 / 우리=패키지 prefix 존재(atom usage 슬라이스에 해당 타입 호출 유무) |