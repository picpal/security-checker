# 보안 점검 보고서 — secscan

- 대상: `a483b3b1`
- 스캐너: trivy, gitleaks, semgrep, spotbugs

## 요약
- 총 **483건** — 심각 3, 위험 28, 보통 70, 일반 382
- 도달성: 도달 가능 **0** · 도달 불가 **0** · 미상 **483**
- 컴플라이언스: KISA 약점 매핑 **34건** · PCI-DSS 6.2.4 관련 **34건**

> ⚠️ **정적 분석 사각지대**: 도달성 판정은 리플렉션·DI(Spring proxy)·역직렬화·동적 디스패치·애노테이션 라우팅을 놓칠 수 있습니다. '도달 불가'는 *우선순위 강등* 근거일 뿐 안전 보증이 아닙니다. 억제는 사람이 증거를 확인해 확정하세요(자동 억제 없음).

> ℹ️ **SAST(Semgrep CE) 주의**: taint 분석이 **intraprocedural**(함수 내)로 제한되어 함수·파일 경계를 넘는 데이터 흐름은 놓칠 수 있습니다(spec §10.2). CE 에서는 일부 Pro 전용·프레임워크 룰이 발화하지 않으며, Kotlin 커버리지는 Java 보다 약합니다(못 잡는 것을 숨기지 않습니다). 깊은 cross-function 분석은 향후 CodeQL(C)로 보강 예정.

## 우선 조치
### [심각] CVE-2026-65182 — org.apache.tomcat.embed:tomcat-embed-core@11.0.22
- 도달성: **도달성 미상**
- 수정: `11.0.25, 10.1.58, 9.0.121` 이상으로 업그레이드
- CWE-284 CWE-863 · 탐지: trivy (합의 1)

### [심각] CVE-2026-65905 — org.apache.tomcat.embed:tomcat-embed-core@11.0.22
- 도달성: **도달성 미상**
- 수정: `11.0.25, 10.1.58, 9.0.121` 이상으로 업그레이드
- CWE-294 · 탐지: trivy (합의 1)

### [심각] CVE-2026-68525 — org.apache.tomcat.embed:tomcat-embed-core@11.0.22
- 도달성: **도달성 미상**
- 수정: `11.0.25, 10.1.58, 9.0.121` 이상으로 업그레이드
- CWE-863 · 탐지: trivy (합의 1)

### [위험] GHSA-r7wm-3cxj-wff9 — com.fasterxml.jackson.core:jackson-core@2.21.2
- 도달성: **도달성 미상**
- 수정: `2.18.8, 2.21.4` 이상으로 업그레이드
- 탐지: trivy (합의 1)

### [위험] CVE-2026-54512 — com.fasterxml.jackson.core:jackson-databind@2.21.2
- 도달성: **도달성 미상**
- 수정: `2.18.8, 3.1.4, 2.21.4` 이상으로 업그레이드
- CWE-184 CWE-502 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 신뢰할 수 없는 데이터의 역직렬화 · PCI-DSS 6.2.4 — injection

### [위험] CVE-2026-54513 — com.fasterxml.jackson.core:jackson-databind@2.21.2
- 도달성: **도달성 미상**
- 수정: `2.18.8, 2.21.4, 3.1.4` 이상으로 업그레이드
- CWE-184 · 탐지: trivy (합의 1)

### [위험] CVE-2026-40983 — io.micrometer:micrometer-core@1.16.5
- 도달성: **도달성 미상**
- 수정: `1.16.6, 1.15.12` 이상으로 업그레이드
- CWE-400 CWE-770 · 탐지: trivy (합의 1)

### [위험] CVE-2026-40984 — io.micrometer:micrometer-core@1.16.5
- 도달성: **도달성 미상**
- 수정: `1.16.6, 1.15.12` 이상으로 업그레이드
- CWE-400 CWE-770 · 탐지: trivy (합의 1)

### [위험] CVE-2026-41695 — org.springframework.data:spring-data-commons@4.0.5
- 도달성: **도달성 미상**
- 수정: `4.0.6, 3.5.12` 이상으로 업그레이드
- CWE-400 · 탐지: trivy (합의 1)

### [위험] CVE-2026-41716 — org.springframework.data:spring-data-commons@4.0.5
- 도달성: **도달성 미상**
- 수정: `4.0.6, 3.5.12` 이상으로 업그레이드
- CWE-770 · 탐지: trivy (합의 1)

### [위험] CVE-2026-41850 — org.springframework:spring-expression@7.0.7
- 도달성: **도달성 미상**
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-407 · 탐지: trivy (합의 1)

### [위험] CVE-2026-41842 — org.springframework:spring-webmvc@7.0.7
- 도달성: **도달성 미상**
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-400 · 탐지: trivy (합의 1)

### [위험] CVE-2026-41845 — org.springframework:spring-webmvc@7.0.7
- 도달성: **도달성 미상**
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-79 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 크로스사이트 스크립트(XSS) · PCI-DSS 6.2.4 — injection

### [위험] GHSA-r7wm-3cxj-wff9 — tools.jackson.core:jackson-core@3.1.2
- 도달성: **도달성 미상**
- 수정: `3.1.4` 이상으로 업그레이드
- 탐지: trivy (합의 1)

### [위험] CVE-2026-54512 — tools.jackson.core:jackson-databind@3.1.2
- 도달성: **도달성 미상**
- 수정: `3.1.4` 이상으로 업그레이드
- CWE-184 CWE-502 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 신뢰할 수 없는 데이터의 역직렬화 · PCI-DSS 6.2.4 — injection

### [위험] CVE-2026-54513 — tools.jackson.core:jackson-databind@3.1.2
- 도달성: **도달성 미상**
- 수정: `3.1.4` 이상으로 업그레이드
- CWE-184 · 탐지: trivy (합의 1)

### [위험] generic-api-key — /private/tmp/secscan-verify/a483b3b1/repo/docs/superpowers/plans/2026-06-07-kms-cbc-payload-encryption.md:182
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — /private/tmp/secscan-verify/a483b3b1/repo/docs/superpowers/specs/2026-06-30-structured-access-logging-design.md:99
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — /private/tmp/secscan-verify/a483b3b1/repo/docs/superpowers/specs/2026-06-30-structured-access-logging-design.md:104
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — /private/tmp/secscan-verify/a483b3b1/repo/docs/superpowers/specs/2026-06-29-password-self-renewal-design.md:79
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — /private/tmp/secscan-verify/a483b3b1/repo/docs/superpowers/plans/2026-05-20-sha512-password-encoder.md:960
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — /private/tmp/secscan-verify/a483b3b1/repo/docs/superpowers/plans/2026-05-20-sha512-password-encoder.md:977
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — /private/tmp/secscan-verify/a483b3b1/repo/src/main/resources/application-example.yml:76
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — /private/tmp/secscan-verify/a483b3b1/repo/src/main/resources/application-loadtest.yml:118
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — /private/tmp/secscan-verify/a483b3b1/repo/docs/testing/api-test-cases.md:860
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — /private/tmp/secscan-verify/a483b3b1/repo/docs/testing/api-test-cases.md:909
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — /private/tmp/secscan-verify/a483b3b1/repo/src/test/resources/application-test.yml:84
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — /private/tmp/secscan-verify/a483b3b1/repo/src/test/resources/application-test.yml:132
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — /private/tmp/secscan-verify/a483b3b1/repo/src/test/java/com/messagegate/auth/AuthServiceTest.java:630
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] secscan.rules.hardcoded-credential — /private/tmp/secscan-verify/a483b3b1/repo/src/main/java/com/messagegate/common/constants/KmsProfilePolicy.java:30
- CWE-798 CWE-259 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA 하드코드된 중요정보 · PCI-DSS 6.2.4 — access control

### [보통] CVE-2026-54514 — com.fasterxml.jackson.core:jackson-databind@2.21.2
- 도달성: **도달성 미상**
- 수정: `2.18.8, 2.21.4, 3.1.4` 이상으로 업그레이드
- CWE-918 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 서버사이드 요청 위조(SSRF) · PCI-DSS 6.2.4 — business logic

### [보통] CVE-2026-54515 — com.fasterxml.jackson.core:jackson-databind@2.21.2
- 도달성: **도달성 미상**
- 수정: `3.1.4, 2.18.9, 2.21.5, 2.22.1` 이상으로 업그레이드
- CWE-915 · 탐지: trivy (합의 1)

### [보통] CVE-2026-54516 — com.fasterxml.jackson.core:jackson-databind@2.21.2
- 도달성: **도달성 미상**
- 수정: `2.21.4, 3.1.4` 이상으로 업그레이드
- CWE-915 · 탐지: trivy (합의 1)

### [보통] CVE-2026-54517 — com.fasterxml.jackson.core:jackson-databind@2.21.2
- 도달성: **도달성 미상**
- 수정: `2.21.4, 3.1.4` 이상으로 업그레이드
- CWE-863 · 탐지: trivy (합의 1)

### [보통] CVE-2026-54518 — com.fasterxml.jackson.core:jackson-databind@2.21.2
- 도달성: **도달성 미상**
- 수정: `2.21.4` 이상으로 업그레이드
- CWE-863 · 탐지: trivy (합의 1)

### [보통] CVE-2026-59888 — com.fasterxml.jackson.core:jackson-databind@2.21.2
- 도달성: **도달성 미상**
- 수정: `2.18.8, 2.21.4` 이상으로 업그레이드
- CWE-915 · 탐지: trivy (합의 1)

### [보통] CVE-2026-59889 — com.fasterxml.jackson.core:jackson-databind@2.21.2
- 도달성: **도달성 미상**
- 수정: `2.21.5, 2.18.9, 2.22.1` 이상으로 업그레이드
- CWE-863 · 탐지: trivy (합의 1)

### [보통] GHSA-mhm7-754m-9p8w — com.fasterxml.jackson.core:jackson-databind@2.21.2
- 도달성: **도달성 미상**
- 수정: `2.18.9, 2.21.5` 이상으로 업그레이드
- 탐지: trivy (합의 1)

### [보통] CVE-2026-49844 — org.apache.logging.log4j:log4j-api@2.25.4
- 도달성: **도달성 미상**
- 수정: `2.25.5, 2.26.1` 이상으로 업그레이드
- CWE-116 · 탐지: trivy (합의 1)

### [보통] CVE-2026-41001 — org.springframework.boot:spring-boot-autoconfigure@4.0.6
- 도달성: **도달성 미상**
- 수정: `4.0.7, 3.5.15` 이상으로 업그레이드
- CWE-377 · 탐지: trivy (합의 1)

### [보통] CVE-2026-40992 — org.springframework.boot:spring-boot-starter-mail@4.0.6
- 도달성: **도달성 미상**
- 수정: `4.0.7, 3.5.15` 이상으로 업그레이드
- CWE-295 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 부적절한 인증서 유효성 검증 · PCI-DSS 6.2.4 — cryptography

### [보통] CVE-2026-41711 — org.springframework.data:spring-data-commons@4.0.5
- 도달성: **도달성 미상**
- 수정: `4.0.6, 3.5.12` 이상으로 업그레이드
- CWE-400 · 탐지: trivy (합의 1)

### [보통] CVE-2026-41721 — org.springframework.data:spring-data-commons@4.0.5
- 도달성: **도달성 미상**
- 수정: `4.0.6, 3.5.12` 이상으로 업그레이드
- CWE-400 · 탐지: trivy (합의 1)

### [보통] CVE-2026-41706 — org.springframework.security:spring-security-web@7.0.5
- 도달성: **도달성 미상**
- 수정: `7.0.6, 6.5.11` 이상으로 업그레이드
- CWE-601 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 신뢰되지 않는 URL 주소로 자동접속 연결 · PCI-DSS 6.2.4 — business logic

### [보통] CVE-2026-41851 — org.springframework:spring-expression@7.0.7
- 도달성: **도달성 미상**
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-770 · 탐지: trivy (합의 1)

### [보통] CVE-2026-41854 — org.springframework:spring-web@7.0.7
- 도달성: **도달성 미상**
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-918 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 서버사이드 요청 위조(SSRF) · PCI-DSS 6.2.4 — business logic

### [보통] CVE-2026-41841 — org.springframework:spring-webmvc@7.0.7
- 도달성: **도달성 미상**
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-524 · 탐지: trivy (합의 1)

### [보통] CVE-2026-41843 — org.springframework:spring-webmvc@7.0.7
- 도달성: **도달성 미상**
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-22 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 경로 조작 및 자원 삽입 · PCI-DSS 6.2.4 — injection

### [보통] CVE-2026-41844 — org.springframework:spring-webmvc@7.0.7
- 도달성: **도달성 미상**
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-601 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 신뢰되지 않는 URL 주소로 자동접속 연결 · PCI-DSS 6.2.4 — business logic

### [보통] CVE-2026-41846 — org.springframework:spring-webmvc@7.0.7
- 도달성: **도달성 미상**
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-79 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 크로스사이트 스크립트(XSS) · PCI-DSS 6.2.4 — injection

### [보통] CVE-2026-41853 — org.springframework:spring-webmvc@7.0.7
- 도달성: **도달성 미상**
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-444 · 탐지: trivy (합의 1)

### [보통] CVE-2026-54514 — tools.jackson.core:jackson-databind@3.1.2
- 도달성: **도달성 미상**
- 수정: `2.21.4, 3.1.4` 이상으로 업그레이드
- CWE-918 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 서버사이드 요청 위조(SSRF) · PCI-DSS 6.2.4 — business logic

### [보통] CVE-2026-54515 — tools.jackson.core:jackson-databind@3.1.2
- 도달성: **도달성 미상**
- 수정: `3.1.4` 이상으로 업그레이드
- CWE-915 · 탐지: trivy (합의 1)

### [보통] CVE-2026-54516 — tools.jackson.core:jackson-databind@3.1.2
- 도달성: **도달성 미상**
- 수정: `3.1.4` 이상으로 업그레이드
- CWE-915 · 탐지: trivy (합의 1)

### [보통] CVE-2026-54517 — tools.jackson.core:jackson-databind@3.1.2
- 도달성: **도달성 미상**
- 수정: `3.1.4` 이상으로 업그레이드
- CWE-863 · 탐지: trivy (합의 1)

### [보통] CVE-2026-54518 — tools.jackson.core:jackson-databind@3.1.2
- 도달성: **도달성 미상**
- 수정: `3.1.4` 이상으로 업그레이드
- CWE-863 · 탐지: trivy (합의 1)

### [보통] CVE-2026-59888 — tools.jackson.core:jackson-databind@3.1.2
- 도달성: **도달성 미상**
- 수정: `3.1.4` 이상으로 업그레이드
- CWE-915 · 탐지: trivy (합의 1)

### [보통] CVE-2026-59889 — tools.jackson.core:jackson-databind@3.1.2
- 도달성: **도달성 미상**
- 수정: `3.1.5, 3.2.1` 이상으로 업그레이드
- CWE-863 · 탐지: trivy (합의 1)

### [일반] CVE-2026-10532 — ch.qos.logback:logback-core@1.5.32
- 도달성: **도달성 미상**
- 수정: `1.5.34` 이상으로 업그레이드
- CWE-502 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 신뢰할 수 없는 데이터의 역직렬화 · PCI-DSS 6.2.4 — injection

### [일반] CVE-2026-9828 — ch.qos.logback:logback-core@1.5.32
- 도달성: **도달성 미상**
- 수정: `1.5.33` 이상으로 업그레이드
- CWE-502 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 신뢰할 수 없는 데이터의 역직렬화 · PCI-DSS 6.2.4 — injection

### [일반] CVE-2026-41848 — org.springframework:spring-core@7.0.7
- 도달성: **도달성 미상**
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-1333 · 탐지: trivy (합의 1)

### [일반] CVE-2026-41852 — org.springframework:spring-expression@7.0.7
- 도달성: **도달성 미상**
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-863 · 탐지: trivy (합의 1)

## 검토 후보 (낮은 신뢰)
### [위험] HRS_REQUEST_PARAMETER_TO_HTTP_HEADER — com/messagegate/config/MdcFilter.java:35
- CWE-113 · 탐지: spotbugs (합의 1)
- 컴플라이언스: KISA HTTP 응답분할 · PCI-DSS 6.2.4 — injection

### [보통] secscan.rules.mybatis-sqli-identifier — /private/tmp/secscan-verify/a483b3b1/repo/src/main/java/com/messagegate/mapper/lg/LgCarrierMapper.java:40
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] secscan.rules.mybatis-sqli-identifier — /private/tmp/secscan-verify/a483b3b1/repo/src/main/java/com/messagegate/mapper/oldlg/OldLgCarrierMapper.java:70
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] secscan.rules.mybatis-sqli-identifier — /private/tmp/secscan-verify/a483b3b1/repo/src/main/java/com/messagegate/mapper/oldlg/OldLgCarrierMapper.java:92
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] secscan.rules.mybatis-sqli-identifier — /private/tmp/secscan-verify/a483b3b1/repo/src/main/resources/mybatis/mapper/lg/LgCarrierMapper.xml:18
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] secscan.rules.mybatis-sqli-identifier — /private/tmp/secscan-verify/a483b3b1/repo/src/main/resources/mybatis/mapper/lg/LgCarrierMapper.xml:19
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] secscan.rules.mybatis-sqli-identifier — /private/tmp/secscan-verify/a483b3b1/repo/src/main/resources/mybatis/mapper/lg/LgCarrierMapper.xml:27
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] secscan.rules.mybatis-sqli-identifier — /private/tmp/secscan-verify/a483b3b1/repo/src/main/resources/mybatis/mapper/oldlg/OldLgCarrierMapper.xml:36
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] secscan.rules.mybatis-sqli-identifier — /private/tmp/secscan-verify/a483b3b1/repo/src/main/resources/mybatis/mapper/oldlg/OldLgCarrierMapper.xml:37
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] secscan.rules.mybatis-sqli-identifier — /private/tmp/secscan-verify/a483b3b1/repo/src/main/resources/mybatis/mapper/oldlg/OldLgCarrierMapper.xml:46
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] secscan.rules.mybatis-sqli-identifier — /private/tmp/secscan-verify/a483b3b1/repo/src/main/resources/mybatis/mapper/oldlg/OldLgCarrierMapper.xml:60
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] secscan.rules.mybatis-sqli-identifier — /private/tmp/secscan-verify/a483b3b1/repo/src/main/resources/mybatis/mapper/oldlg/OldLgCarrierMapper.xml:69
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] PREDICTABLE_RANDOM — com/messagegate/carrier/RandomWeightedCarrierSelector.java:34
- CWE-330 · 탐지: spotbugs (합의 1)
- 컴플라이언스: KISA 적절하지 않은 난수값 사용 · PCI-DSS 6.2.4 — cryptography

### [보통] SPRING_CSRF_PROTECTION_DISABLED — com/messagegate/config/SecurityConfig.java:144
- CWE-352 · 탐지: spotbugs (합의 1)
- 컴플라이언스: KISA 크로스사이트 요청 위조(CSRF) · PCI-DSS 6.2.4 — business logic

### [보통] SPRING_CSRF_PROTECTION_DISABLED — com/messagegate/config/SecurityConfig.java:93
- CWE-352 · 탐지: spotbugs (합의 1)
- 컴플라이언스: KISA 크로스사이트 요청 위조(CSRF) · PCI-DSS 6.2.4 — business logic

### [보통] CRLF_INJECTION_LOGS — com/messagegate/controller/AdminController.java:425
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/controller/AdminController.java:366
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/controller/AdminController.java:339
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/controller/AdminController.java:392
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/service/CarrierOverrideService.java:199
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/service/CarrierOverrideService.java:166
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/service/CarrierOverrideService.java:253
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/service/CarrierWeightService.java:97
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/service/GracePeriodService.java:211
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/service/GracePeriodService.java:105
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/service/MessageService.java:311
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] SQL_INJECTION_SPRING_JDBC — com/messagegate/service/OutboxAdminService.java:175
- CWE-89 · 탐지: spotbugs (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] SQL_INJECTION_SPRING_JDBC — com/messagegate/service/OutboxAdminService.java:157
- CWE-89 · 탐지: spotbugs (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] PREDICTABLE_RANDOM — com/messagegate/service/OutboxWorker.java:776
- CWE-330 · 탐지: spotbugs (합의 1)
- 컴플라이언스: KISA 적절하지 않은 난수값 사용 · PCI-DSS 6.2.4 — cryptography

### [보통] SQL_INJECTION_JDBC — com/messagegate/service/OutboxWorker.java:492
- CWE-89 · 탐지: spotbugs (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] CRLF_INJECTION_LOGS — com/messagegate/service/PayloadProfileService.java:141
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:368
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:401
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:415
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:447
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:265
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:305
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:309
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:328
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:343
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:242
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/util/EmailNotificationHelper.java:35
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/util/EmailNotificationHelper.java:42
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthFailureAccountLocker.java:75
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthFailureAccountLocker.java:82
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP — com/messagegate/auth/AuthFailureAlertContext.java:15
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/auth/AuthFailureAlertContext.java:15
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthFailureGuard.java:241
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthFailureGuard.java:200
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthFailureGuard.java:335
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthFailureGuard.java:343
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthFailureGuard.java:362
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthFailureGuard.java:124
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthFailureMailer.java:80
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthFailureMailer.java:43
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthFailureMailer.java:55
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthService.java:99
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthService.java:112
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthService.java:180
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthService.java:382
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthService.java:387
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthService.java:338
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthService.java:214
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthService.java:238
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthService.java:247
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthService.java:253
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthService.java:293
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthService.java:304
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthService.java:313
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthService.java:322
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/BasicAuthFilter.java:134
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/BasicAuthFilter.java:141
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/BasicAuthFilter.java:147
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/BasicAuthFilter.java:165
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/BasicAuthFilter.java:188
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] IMPROPER_UNICODE — com/messagegate/auth/BasicAuthFilter.java:210
- CWE-176 · 탐지: spotbugs (합의 1)

### [일반] DM_CONVERT_CASE — com/messagegate/carrier/CarrierFactory.java:25
- 탐지: spotbugs (합의 1)

### [일반] IMPROPER_UNICODE — com/messagegate/carrier/CarrierFactory.java:25
- CWE-176 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/CarrierRouter.java:174
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/CarrierRouter.java:181
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/CarrierRouter.java:195
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/CarrierRouter.java:220
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/CarrierRouter.java:73
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/CarrierRouter.java:95
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/CarrierRouter.java:101
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/CarrierRouter.java:274
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/CarrierRouter.java:280
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/CarrierRouter.java:143
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] DM_CONVERT_CASE — com/messagegate/carrier/CarrierRouter.java:159
- 탐지: spotbugs (합의 1)

### [일반] IMPROPER_UNICODE — com/messagegate/carrier/CarrierRouter.java:159
- CWE-176 · 탐지: spotbugs (합의 1)

### [일반] IMPROPER_UNICODE — com/messagegate/carrier/CarrierRouter.java:160
- CWE-176 · 탐지: spotbugs (합의 1)

### [일반] THROWS_METHOD_THROWS_CLAUSE_THROWABLE — com/messagegate/carrier/CarrierRouter.java:243
- CWE-397 · 탐지: spotbugs (합의 1)

### [일반] THROWS_METHOD_THROWS_RUNTIMEEXCEPTION — com/messagegate/carrier/CarrierRouter.java:309
- CWE-397 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/KTAdapter.java:176
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/KTAdapter.java:127
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/KTAdapter.java:133
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/carrier/KTAdapter.java:42
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/carrier/KtSequenceAllocator.java:19
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/LGAdapter.java:163
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/LGAdapter.java:232
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/LGAdapter.java:77
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/LGAdapter.java:83
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/LGAdapter.java:90
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/LGAdapter.java:132
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/LGAdapter.java:143
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/LGAdapter.java:150
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/carrier/LGAdapter.java:48
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/OldLgAdapter.java:186
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/OldLgAdapter.java:202
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/OldLgAdapter.java:111
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/OldLgAdapter.java:119
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/OldLgAdapter.java:59
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/carrier/OldLgAdapter.java:45
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] DM_CONVERT_CASE — com/messagegate/carrier/RandomWeightedCarrierSelector.java:51
- 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/common/exception/GlobalExceptionHandler.java:72
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/common/exception/GlobalExceptionHandler.java:74
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] RCN_REDUNDANT_NULLCHECK_OF_NONNULL_VALUE — com/messagegate/common/exception/GlobalExceptionHandler.java:96
- 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP — com/messagegate/common/exception/MessageGateException.java:55
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/common/exception/MessageGateException.java:33
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/common/exception/MessageGateException.java:47
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] SE_BAD_FIELD — com/messagegate/common/exception/MessageGateException.java
- 탐지: spotbugs (합의 1)

### [일반] SE_BAD_FIELD — com/messagegate/common/exception/PayloadValidationException.java
- 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/config/CarrierBulkheadConfig.java:22
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/config/CarrierCircuitBreakerConfig.java:82
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/config/CarrierCircuitBreakerConfig.java:88
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/config/CarrierCircuitBreakerConfig.java:29
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/config/HttpLoggingFilter.java:34
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/config/KmsCircuitBreakerConfig.java:155
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/config/KmsCircuitBreakerConfig.java:161
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/config/LifecycleLoggingListener.java:48
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/config/LifecycleLoggingListener.java:41
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/config/LifecycleLoggingListener.java:34
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/controller/AdminController.java:270
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/controller/AdminController.java:299
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/controller/AdminController.java:97
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/controller/AdminController.java:96
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/AdminController.java:416
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/AdminController.java:184
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/AdminController.java:360
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/AdminController.java:333
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/AdminController.java:477
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/AdminController.java:261
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/AdminController.java:525
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/AdminController.java:291
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/AdminController.java:238
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/AdminController.java:203
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/AdminController.java:168
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/AdminController.java:217
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/AdminController.java:445
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/AdminController.java:460
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/AdminController.java:390
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/AdminController.java:147
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/AdminController.java:113
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/AdminController.java:133
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/AdminController.java:500
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/HealthController.java:24
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/LoadtestOutboxInsertController.java:46
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/LoadtestOutboxWorkerController.java:60
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/LoadtestOutboxWorkerController.java:46
- 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/controller/MessageController.java:68
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/MessageController.java:144
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/MessageController.java:162
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/MessageController.java:107
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/MessageController.java:125
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/MessageController.java:84
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/OutboxAdminController.java:58
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/OutboxAdminController.java:44
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/PasswordStatusController.java:47
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/PasswordStatusController.java:69
- 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/dto/ErrorResponse.java:21
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP — com/messagegate/dto/SendOutcome.java:3
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/dto/SendOutcome.java:3
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] SE_NO_SERIALVERSIONID — com/messagegate/entity/CarrierWeightId.java:9
- 탐지: spotbugs (합의 1)

### [일반] CT_CONSTRUCTOR_THROW — com/messagegate/entity/MessageErrorLog.java:99
- 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QCarrierWeight.java:25
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QCarrierWeight.java:27
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QCarrierWeight.java:29
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QCarrierWeight.java:31
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QCarrierWeight.java:33
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QCarrierWeight.java:35
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QConfigAudit.java:25
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QConfigAudit.java:27
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QConfigAudit.java:29
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QConfigAudit.java:31
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QConfigAudit.java:33
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QConfigAudit.java:35
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QDailyReportMailLog.java:25
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QDailyReportMailLog.java:27
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QDailyReportMailLog.java:29
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QDailyReportMailLog.java:31
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QDailyReportMailLog.java:33
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QDailyReportMailLog.java:35
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QDailyReportMailLog.java:37
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QDailyReportMailLog.java:39
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QJobLock.java:25
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QJobLock.java:31
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QJobLock.java:27
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QJobLock.java:29
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QJobLock.java:33
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageErrorLog.java:25
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageErrorLog.java:27
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageErrorLog.java:29
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageErrorLog.java:31
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageErrorLog.java:33
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageErrorLog.java:35
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageErrorLog.java:37
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageErrorLog.java:39
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageErrorLog.java:41
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageErrorLog.java:43
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageErrorLog.java:45
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageMeta.java:25
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageMeta.java:27
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageMeta.java:29
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageMeta.java:31
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageMeta.java:33
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageMeta.java:35
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageMeta.java:37
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageMeta.java:39
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageMeta.java:41
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageMeta.java:43
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageMeta.java:45
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageMeta.java:47
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageMeta.java:49
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageMeta.java:51
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageMeta.java:53
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QOutboxLoadtestRow.java:25
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QOutboxLoadtestRow.java:27
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QOutboxLoadtestRow.java:29
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QOutboxLoadtestRow.java:31
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QOutboxLoadtestRow.java:33
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QOutboxLoadtestRow.java:35
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QOutboxLoadtestRow.java:37
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QPasswordHistory.java:25
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QPasswordHistory.java:27
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QPasswordHistory.java:29
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QPasswordHistory.java:31
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QPasswordHistory.java:33
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QPasswordHistory.java:35
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QPasswordHistory.java:37
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QPasswordHistory.java:39
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QPasswordHistory.java:41
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QPasswordHistory.java:43
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QPasswordHistory.java:45
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QPasswordHistory.java:47
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QPasswordHistory.java:49
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QPasswordHistory.java:51
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QPasswordHistory.java:53
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuth.java:30
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuth.java:32
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuth.java:34
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuth.java:36
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuth.java:46
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuth.java:50
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuth.java:52
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuth.java:54
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuth.java:63
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuthHistory.java:25
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuthHistory.java:27
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuthHistory.java:29
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuthHistory.java:31
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuthHistory.java:33
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuthHistory.java:35
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuthHistory.java:37
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuthHistory.java:39
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuthHistory.java:41
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuthHistory.java:43
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuthHistory.java:45
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuthHistory.java:47
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuthHistory.java:49
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuthHistory.java:51
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuthHistory.java:53
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceCarrierOverride.java:25
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceCarrierOverride.java:27
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceCarrierOverride.java:29
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceCarrierOverride.java:31
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceCarrierOverride.java:33
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceCarrierOverride.java:35
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceCarrierOverride.java:37
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceSalt.java:25
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceSalt.java:27
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceSalt.java:29
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QSystemConfig.java:25
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QSystemConfig.java:27
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QSystemConfig.java:29
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QSystemConfig.java:31
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QSystemConfig.java:33
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] SE_NO_SERIALVERSIONID — com/messagegate/entity/ServiceCarrierOverrideId.java:8
- 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/logging/AccessEventLogger.java:124
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/logging/AccessEventLogger.java:134
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/logging/AccessEventLogger.java:53
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/logging/AccessEventLogger.java:74
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/logging/AccessEventLogger.java:91
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/logging/AccessEventLogger.java:108
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/logging/AccessEventLogger.java:175
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/logging/AccessEventLogger.java:189
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/logging/AccessEventLogger.java:150
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/logging/AccessEventLogger.java:161
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/repository/jpa/ServiceAuthQueryRepositoryImpl.java:170
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/repository/jpa/ServiceAuthQueryRepositoryImpl.java:212
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/scheduler/DailyReportJob.java:50
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/scheduler/InactiveAccountLockerJob.java:42
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/scheduler/JobFailureTracker.java:59
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/scheduler/JobFailureTracker.java:65
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/scheduler/JobFailureTracker.java:72
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/scheduler/JobFailureTracker.java:86
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/scheduler/JobLockService.java:22
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/scheduler/JobLockService.java:34
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/scheduler/JobLockService.java:46
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/scheduler/MessageMonitoringJob.java:134
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/scheduler/MessageMonitoringJob.java:155
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/scheduler/MessageMonitoringJob.java:160
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/scheduler/MessageMonitoringJob.java:179
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/scheduler/MessageMonitoringJob.java:185
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/scheduler/MessageMonitoringJob.java:210
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/scheduler/MessageMonitoringJob.java:83
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/scheduler/PasswordExpiryReminderJob.java:58
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP — com/messagegate/security/password/PasswordEncoderProperties.java:30
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP — com/messagegate/security/password/PasswordEncoderProperties.java:38
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/security/password/PasswordEncoderProperties.java:34
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/security/password/PasswordEncoderProperties.java:42
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP — com/messagegate/security/password/PropertyHmacKeyProvider.java:104
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/security/password/PropertyHmacKeyProvider.java:47
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] IMPROPER_UNICODE — com/messagegate/security/password/PropertyHmacKeyProvider.java:62
- CWE-176 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/security/password/SidAwareHashServiceImpl.java:65
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/security/password/SidAwareHashServiceImpl.java:74
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/security/payload/OutboxAtRestCipher.java:109
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/security/payload/OutboxAtRestCipher.java:80
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/security/payload/PayloadDecryptionService.java:341
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/security/payload/PayloadDecryptionService.java:310
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/security/payload/PayloadDecryptionService.java:368
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/security/payload/PayloadDecryptionService.java:223
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/security/payload/PayloadDecryptionService.java:249
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/CarrierDispatchService.java:171
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/CarrierOverrideService.java:113
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] DM_CONVERT_CASE — com/messagegate/service/CarrierRoutingStatusService.java:52
- 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/CarrierWeightService.java:150
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/GracePeriodService.java:148
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/IdempotencyGuardImpl.java:42
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/InactiveAccountTransactionalHelper.java:82
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/InactiveAccountTransactionalHelper.java:87
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/InactiveAccountTransactionalHelper.java:105
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/InactiveAccountTransactionalHelper.java:59
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/InactiveAccountTransactionalHelper.java:67
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/MessageResendService.java:393
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/MessageResendService.java:235
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/MessageResendService.java:278
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/MessageResendService.java:292
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/MessageResendService.java:311
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/MessageResendService.java:316
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/MessageResendService.java:334
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/MessageResendService.java:351
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/MessageResendService.java:362
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/MessageResendService.java:374
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/service/MessageResendService.java:157
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] THROWS_METHOD_THROWS_RUNTIMEEXCEPTION — com/messagegate/service/MessageResendService.java:383
- CWE-397 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/MessageService.java:176
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/MessageService.java:186
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/MessageService.java:189
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/MessageService.java:205
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/MessageService.java:211
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/MessageService.java:230
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/MessageService.java:232
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/MessageService.java:251
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/MessageService.java:281
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] DM_CONVERT_CASE — com/messagegate/service/MessageService.java:338
- 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/OutboxAcceptService.java:141
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/service/OutboxAcceptService.java:112
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/OutboxAdminService.java:145
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/service/OutboxDrainSimulator.java:89
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/OutboxStatusService.java:99
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/OutboxWorker.java:523
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/OutboxWorker.java:546
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/OutboxWorker.java:559
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/OutboxWorker.java:593
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/OutboxWorker.java:605
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/OutboxWorker.java:609
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/OutboxWorker.java:619
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/OutboxWorker.java:724
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/OutboxWorker.java:343
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/OutboxWorker.java:358
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/OutboxWorker.java:383
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/OutboxWorker.java:683
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/OutboxWorker.java:695
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/OutboxWorker.java:703
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/OutboxWorker.java:645
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/OutboxWorker.java:756
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CT_CONSTRUCTOR_THROW — com/messagegate/service/OutboxWorker.java:204
- 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/service/OutboxWorker.java:209
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/service/OutboxWorker.java:216
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] SQL_PREPARED_STATEMENT_GENERATED_FROM_NONCONSTANT_STRING — com/messagegate/service/OutboxWorker.java:492
- CWE-89 · 탐지: spotbugs (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/PasswordService.java:129
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/PasswordService.java:135
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/PayloadProfileService.java:135
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP — com/messagegate/service/ReportService.java:161
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/service/ReportService.java:161
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:391
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:409
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:429
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:288
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:297
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:103
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:110
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:139
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:158
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:200
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:206
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:512
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:382
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:279
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:191
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:478
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/service/ServiceAccountManagementService.java:86
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/SystemAlertService.java:196
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/SystemAlertService.java:200
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/SystemAlertService.java:213
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/SystemAlertService.java:217
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/SystemAlertService.java:245
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/SystemAlertService.java:254
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/service/SystemAlertService.java:78
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/util/EmailNotificationHelper.java:54
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/util/MonthSuffixValidator.java:41
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

## 낮은 우선순위 — 도달 불가 (SCA)
_해당 없음._
