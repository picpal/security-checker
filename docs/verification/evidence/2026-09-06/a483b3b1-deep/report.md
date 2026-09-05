# 보안 점검 보고서 — secscan

- 대상: `a483b3b1`
- 스캐너: trivy ok · gitleaks ok · semgrep ok · spotbugs ok

## 요약
- 총 **483건** — 심각 3, 위험 28, 보통 70, 일반 382
- 도달성: 도달 가능 **0** · 도달 불가 **0** · 미상 **483**
- 컴플라이언스: KISA 약점 매핑 **34건** · PCI-DSS 6.2.4 관련 **34건**

> ⚠️ **정적 분석 사각지대**: 도달성 판정은 리플렉션·DI(Spring proxy)·역직렬화·동적 디스패치·애노테이션 라우팅을 놓칠 수 있습니다. '도달 불가'는 *우선순위 강등* 근거일 뿐 안전 보증이 아닙니다. 억제는 사람이 증거를 확인해 확정하세요(자동 억제 없음).

> ℹ️ **SAST(Semgrep CE) 주의**: taint 분석이 **intraprocedural**(함수 내)로 제한되어 함수·파일 경계를 넘는 데이터 흐름은 놓칠 수 있습니다(spec §10.2). CE 에서는 일부 Pro 전용·프레임워크 룰이 발화하지 않으며, Kotlin 커버리지는 Java 보다 약합니다(못 잡는 것을 숨기지 않습니다). 깊은 cross-function 분석은 향후 CodeQL(C)로 보강 예정.

## 우선 조치
### [심각] CVE-2026-65182 — org.apache.tomcat.embed:tomcat-embed-core@11.0.22 · id `494bf1b2dc7d`
- 도달성: **도달성 미상**
- 수정: `11.0.25, 10.1.58, 9.0.121` 이상으로 업그레이드
- CWE-284 CWE-863 · 탐지: trivy (합의 1)

### [심각] CVE-2026-65905 — org.apache.tomcat.embed:tomcat-embed-core@11.0.22 · id `eca2f3434dc5`
- 도달성: **도달성 미상**
- 수정: `11.0.25, 10.1.58, 9.0.121` 이상으로 업그레이드
- CWE-294 · 탐지: trivy (합의 1)

### [심각] CVE-2026-68525 — org.apache.tomcat.embed:tomcat-embed-core@11.0.22 · id `f95f95fa4dd7`
- 도달성: **도달성 미상**
- 수정: `11.0.25, 10.1.58, 9.0.121` 이상으로 업그레이드
- CWE-863 · 탐지: trivy (합의 1)

### [위험] secscan.rules.hardcoded-credential — /private/tmp/secscan-verify/a483b3b1/repo/src/main/java/com/messagegate/common/constants/KmsProfilePolicy.java:30 · id `009b8686fb3e`
- CWE-798 CWE-259 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA 하드코드된 중요정보 · PCI-DSS 6.2.4 — access control

### [위험] GHSA-r7wm-3cxj-wff9 — com.fasterxml.jackson.core:jackson-core@2.21.2 · id `97b125c3ca5a`
- 도달성: **도달성 미상**
- 수정: `2.18.8, 2.21.4` 이상으로 업그레이드
- 탐지: trivy (합의 1)

### [위험] CVE-2026-54512 — com.fasterxml.jackson.core:jackson-databind@2.21.2 · id `5a948d71dd88`
- 도달성: **도달성 미상**
- 수정: `2.18.8, 3.1.4, 2.21.4` 이상으로 업그레이드
- CWE-184 CWE-502 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 신뢰할 수 없는 데이터의 역직렬화 · PCI-DSS 6.2.4 — injection

### [위험] CVE-2026-54513 — com.fasterxml.jackson.core:jackson-databind@2.21.2 · id `dee6ba128869`
- 도달성: **도달성 미상**
- 수정: `2.18.8, 2.21.4, 3.1.4` 이상으로 업그레이드
- CWE-184 · 탐지: trivy (합의 1)

### [위험] CVE-2026-40983 — io.micrometer:micrometer-core@1.16.5 · id `ec2ddc6ed4d6`
- 도달성: **도달성 미상**
- 수정: `1.16.6, 1.15.12` 이상으로 업그레이드
- CWE-400 CWE-770 · 탐지: trivy (합의 1)

### [위험] CVE-2026-40984 — io.micrometer:micrometer-core@1.16.5 · id `63c7e5b17ce4`
- 도달성: **도달성 미상**
- 수정: `1.16.6, 1.15.12` 이상으로 업그레이드
- CWE-400 CWE-770 · 탐지: trivy (합의 1)

### [위험] CVE-2026-41695 — org.springframework.data:spring-data-commons@4.0.5 · id `27770b969d5c`
- 도달성: **도달성 미상**
- 수정: `4.0.6, 3.5.12` 이상으로 업그레이드
- CWE-400 · 탐지: trivy (합의 1)

### [위험] CVE-2026-41716 — org.springframework.data:spring-data-commons@4.0.5 · id `63ae23f65444`
- 도달성: **도달성 미상**
- 수정: `4.0.6, 3.5.12` 이상으로 업그레이드
- CWE-770 · 탐지: trivy (합의 1)

### [위험] CVE-2026-41850 — org.springframework:spring-expression@7.0.7 · id `ec11668ec58e`
- 도달성: **도달성 미상**
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-407 · 탐지: trivy (합의 1)

### [위험] CVE-2026-41842 — org.springframework:spring-webmvc@7.0.7 · id `2bd37a7f5e43`
- 도달성: **도달성 미상**
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-400 · 탐지: trivy (합의 1)

### [위험] CVE-2026-41845 — org.springframework:spring-webmvc@7.0.7 · id `f83f4a9723f8`
- 도달성: **도달성 미상**
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-79 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 크로스사이트 스크립트(XSS) · PCI-DSS 6.2.4 — injection

### [위험] GHSA-r7wm-3cxj-wff9 — tools.jackson.core:jackson-core@3.1.2 · id `32d151df56d7`
- 도달성: **도달성 미상**
- 수정: `3.1.4` 이상으로 업그레이드
- 탐지: trivy (합의 1)

### [위험] CVE-2026-54512 — tools.jackson.core:jackson-databind@3.1.2 · id `5381c1a80d26`
- 도달성: **도달성 미상**
- 수정: `3.1.4` 이상으로 업그레이드
- CWE-184 CWE-502 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 신뢰할 수 없는 데이터의 역직렬화 · PCI-DSS 6.2.4 — injection

### [위험] CVE-2026-54513 — tools.jackson.core:jackson-databind@3.1.2 · id `f973cf6af03a`
- 도달성: **도달성 미상**
- 수정: `3.1.4` 이상으로 업그레이드
- CWE-184 · 탐지: trivy (합의 1)

### [위험] generic-api-key — /private/tmp/secscan-verify/a483b3b1/repo/docs/superpowers/plans/2026-05-20-sha512-password-encoder.md:960 · id `d1618f138fd4`
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — /private/tmp/secscan-verify/a483b3b1/repo/docs/superpowers/plans/2026-05-20-sha512-password-encoder.md:977 · id `cce10c69bd46`
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — /private/tmp/secscan-verify/a483b3b1/repo/docs/superpowers/plans/2026-06-07-kms-cbc-payload-encryption.md:182 · id `57ba01ff1e4f`
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — /private/tmp/secscan-verify/a483b3b1/repo/docs/superpowers/specs/2026-06-29-password-self-renewal-design.md:79 · id `0c6c3573bf1e`
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — /private/tmp/secscan-verify/a483b3b1/repo/docs/superpowers/specs/2026-06-30-structured-access-logging-design.md:104 · id `541b04e51289`
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — /private/tmp/secscan-verify/a483b3b1/repo/docs/superpowers/specs/2026-06-30-structured-access-logging-design.md:99 · id `d2a9d31675a1`
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — /private/tmp/secscan-verify/a483b3b1/repo/docs/testing/api-test-cases.md:860 · id `0dcb9af5216a`
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — /private/tmp/secscan-verify/a483b3b1/repo/docs/testing/api-test-cases.md:909 · id `d24298c86fa6`
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — /private/tmp/secscan-verify/a483b3b1/repo/src/main/resources/application-example.yml:76 · id `1800a2de75ee`
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — /private/tmp/secscan-verify/a483b3b1/repo/src/main/resources/application-loadtest.yml:118 · id `e5fa873a7c52`
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — /private/tmp/secscan-verify/a483b3b1/repo/src/test/java/com/messagegate/auth/AuthServiceTest.java:630 · id `16bd1729e636`
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — /private/tmp/secscan-verify/a483b3b1/repo/src/test/resources/application-test.yml:132 · id `e69855091488`
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — /private/tmp/secscan-verify/a483b3b1/repo/src/test/resources/application-test.yml:84 · id `0f3653e6acd6`
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [보통] CVE-2026-54514 — com.fasterxml.jackson.core:jackson-databind@2.21.2 · id `6a8468772377`
- 도달성: **도달성 미상**
- 수정: `2.18.8, 2.21.4, 3.1.4` 이상으로 업그레이드
- CWE-918 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 서버사이드 요청 위조(SSRF) · PCI-DSS 6.2.4 — business logic

### [보통] CVE-2026-54515 — com.fasterxml.jackson.core:jackson-databind@2.21.2 · id `70f5ca7b9c8d`
- 도달성: **도달성 미상**
- 수정: `3.1.4, 2.18.9, 2.21.5, 2.22.1` 이상으로 업그레이드
- CWE-915 · 탐지: trivy (합의 1)

### [보통] CVE-2026-54516 — com.fasterxml.jackson.core:jackson-databind@2.21.2 · id `26157a86e040`
- 도달성: **도달성 미상**
- 수정: `2.21.4, 3.1.4` 이상으로 업그레이드
- CWE-915 · 탐지: trivy (합의 1)

### [보통] CVE-2026-54517 — com.fasterxml.jackson.core:jackson-databind@2.21.2 · id `da7a8a4395ac`
- 도달성: **도달성 미상**
- 수정: `2.21.4, 3.1.4` 이상으로 업그레이드
- CWE-863 · 탐지: trivy (합의 1)

### [보통] CVE-2026-54518 — com.fasterxml.jackson.core:jackson-databind@2.21.2 · id `8ea8abe066bd`
- 도달성: **도달성 미상**
- 수정: `2.21.4` 이상으로 업그레이드
- CWE-863 · 탐지: trivy (합의 1)

### [보통] CVE-2026-59888 — com.fasterxml.jackson.core:jackson-databind@2.21.2 · id `73193fb7f937`
- 도달성: **도달성 미상**
- 수정: `2.18.8, 2.21.4` 이상으로 업그레이드
- CWE-915 · 탐지: trivy (합의 1)

### [보통] CVE-2026-59889 — com.fasterxml.jackson.core:jackson-databind@2.21.2 · id `9cb4c6240105`
- 도달성: **도달성 미상**
- 수정: `2.21.5, 2.18.9, 2.22.1` 이상으로 업그레이드
- CWE-863 · 탐지: trivy (합의 1)

### [보통] GHSA-mhm7-754m-9p8w — com.fasterxml.jackson.core:jackson-databind@2.21.2 · id `849aa917d353`
- 도달성: **도달성 미상**
- 수정: `2.18.9, 2.21.5` 이상으로 업그레이드
- 탐지: trivy (합의 1)

### [보통] CVE-2026-49844 — org.apache.logging.log4j:log4j-api@2.25.4 · id `e0bd29ddbb20`
- 도달성: **도달성 미상**
- 수정: `2.25.5, 2.26.1` 이상으로 업그레이드
- CWE-116 · 탐지: trivy (합의 1)

### [보통] CVE-2026-41001 — org.springframework.boot:spring-boot-autoconfigure@4.0.6 · id `d90388f4a666`
- 도달성: **도달성 미상**
- 수정: `4.0.7, 3.5.15` 이상으로 업그레이드
- CWE-377 · 탐지: trivy (합의 1)

### [보통] CVE-2026-40992 — org.springframework.boot:spring-boot-starter-mail@4.0.6 · id `50e2592380a5`
- 도달성: **도달성 미상**
- 수정: `4.0.7, 3.5.15` 이상으로 업그레이드
- CWE-295 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 부적절한 인증서 유효성 검증 · PCI-DSS 6.2.4 — cryptography

### [보통] CVE-2026-41711 — org.springframework.data:spring-data-commons@4.0.5 · id `32a87b644940`
- 도달성: **도달성 미상**
- 수정: `4.0.6, 3.5.12` 이상으로 업그레이드
- CWE-400 · 탐지: trivy (합의 1)

### [보통] CVE-2026-41721 — org.springframework.data:spring-data-commons@4.0.5 · id `da73be808e24`
- 도달성: **도달성 미상**
- 수정: `4.0.6, 3.5.12` 이상으로 업그레이드
- CWE-400 · 탐지: trivy (합의 1)

### [보통] CVE-2026-41706 — org.springframework.security:spring-security-web@7.0.5 · id `f8eeb1ae7dec`
- 도달성: **도달성 미상**
- 수정: `7.0.6, 6.5.11` 이상으로 업그레이드
- CWE-601 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 신뢰되지 않는 URL 주소로 자동접속 연결 · PCI-DSS 6.2.4 — business logic

### [보통] CVE-2026-41851 — org.springframework:spring-expression@7.0.7 · id `597228550044`
- 도달성: **도달성 미상**
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-770 · 탐지: trivy (합의 1)

### [보통] CVE-2026-41841 — org.springframework:spring-webmvc@7.0.7 · id `a32cec304e8e`
- 도달성: **도달성 미상**
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-524 · 탐지: trivy (합의 1)

### [보통] CVE-2026-41843 — org.springframework:spring-webmvc@7.0.7 · id `1152f302a96c`
- 도달성: **도달성 미상**
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-22 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 경로 조작 및 자원 삽입 · PCI-DSS 6.2.4 — injection

### [보통] CVE-2026-41844 — org.springframework:spring-webmvc@7.0.7 · id `721c61d5119b`
- 도달성: **도달성 미상**
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-601 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 신뢰되지 않는 URL 주소로 자동접속 연결 · PCI-DSS 6.2.4 — business logic

### [보통] CVE-2026-41846 — org.springframework:spring-webmvc@7.0.7 · id `1c725b3e6882`
- 도달성: **도달성 미상**
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-79 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 크로스사이트 스크립트(XSS) · PCI-DSS 6.2.4 — injection

### [보통] CVE-2026-41853 — org.springframework:spring-webmvc@7.0.7 · id `21037de4c299`
- 도달성: **도달성 미상**
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-444 · 탐지: trivy (합의 1)

### [보통] CVE-2026-41854 — org.springframework:spring-web@7.0.7 · id `c9d6e8495d18`
- 도달성: **도달성 미상**
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-918 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 서버사이드 요청 위조(SSRF) · PCI-DSS 6.2.4 — business logic

### [보통] CVE-2026-54514 — tools.jackson.core:jackson-databind@3.1.2 · id `b51207774023`
- 도달성: **도달성 미상**
- 수정: `2.21.4, 3.1.4` 이상으로 업그레이드
- CWE-918 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 서버사이드 요청 위조(SSRF) · PCI-DSS 6.2.4 — business logic

### [보통] CVE-2026-54515 — tools.jackson.core:jackson-databind@3.1.2 · id `e340a403d09c`
- 도달성: **도달성 미상**
- 수정: `3.1.4` 이상으로 업그레이드
- CWE-915 · 탐지: trivy (합의 1)

### [보통] CVE-2026-54516 — tools.jackson.core:jackson-databind@3.1.2 · id `36dc696461c0`
- 도달성: **도달성 미상**
- 수정: `3.1.4` 이상으로 업그레이드
- CWE-915 · 탐지: trivy (합의 1)

### [보통] CVE-2026-54517 — tools.jackson.core:jackson-databind@3.1.2 · id `a5fb2a0b5507`
- 도달성: **도달성 미상**
- 수정: `3.1.4` 이상으로 업그레이드
- CWE-863 · 탐지: trivy (합의 1)

### [보통] CVE-2026-54518 — tools.jackson.core:jackson-databind@3.1.2 · id `338c83011c94`
- 도달성: **도달성 미상**
- 수정: `3.1.4` 이상으로 업그레이드
- CWE-863 · 탐지: trivy (합의 1)

### [보통] CVE-2026-59888 — tools.jackson.core:jackson-databind@3.1.2 · id `4f7f6582dfc0`
- 도달성: **도달성 미상**
- 수정: `3.1.4` 이상으로 업그레이드
- CWE-915 · 탐지: trivy (합의 1)

### [보통] CVE-2026-59889 — tools.jackson.core:jackson-databind@3.1.2 · id `9baaafc6e4d2`
- 도달성: **도달성 미상**
- 수정: `3.1.5, 3.2.1` 이상으로 업그레이드
- CWE-863 · 탐지: trivy (합의 1)

### [일반] CVE-2026-10532 — ch.qos.logback:logback-core@1.5.32 · id `6fd0eca65eae`
- 도달성: **도달성 미상**
- 수정: `1.5.34` 이상으로 업그레이드
- CWE-502 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 신뢰할 수 없는 데이터의 역직렬화 · PCI-DSS 6.2.4 — injection

### [일반] CVE-2026-9828 — ch.qos.logback:logback-core@1.5.32 · id `1a4f28dc8fac`
- 도달성: **도달성 미상**
- 수정: `1.5.33` 이상으로 업그레이드
- CWE-502 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 신뢰할 수 없는 데이터의 역직렬화 · PCI-DSS 6.2.4 — injection

### [일반] CVE-2026-41848 — org.springframework:spring-core@7.0.7 · id `12ef34192ff5`
- 도달성: **도달성 미상**
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-1333 · 탐지: trivy (합의 1)

### [일반] CVE-2026-41852 — org.springframework:spring-expression@7.0.7 · id `c986cf4e4411`
- 도달성: **도달성 미상**
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-863 · 탐지: trivy (합의 1)

## 검토 후보 (낮은 신뢰)
### [위험] HRS_REQUEST_PARAMETER_TO_HTTP_HEADER — com/messagegate/config/MdcFilter.java:35 · id `e8e0fa4da981`
- CWE-113 · 탐지: spotbugs (합의 1)
- 컴플라이언스: KISA HTTP 응답분할 · PCI-DSS 6.2.4 — injection

### [보통] secscan.rules.mybatis-sqli-identifier — /private/tmp/secscan-verify/a483b3b1/repo/src/main/java/com/messagegate/mapper/lg/LgCarrierMapper.java:40 · id `102bb5bc80f8`
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] secscan.rules.mybatis-sqli-identifier — /private/tmp/secscan-verify/a483b3b1/repo/src/main/java/com/messagegate/mapper/oldlg/OldLgCarrierMapper.java:70 · id `fffa9c073e88`
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] secscan.rules.mybatis-sqli-identifier — /private/tmp/secscan-verify/a483b3b1/repo/src/main/java/com/messagegate/mapper/oldlg/OldLgCarrierMapper.java:92 · id `f7be457e4123`
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] secscan.rules.mybatis-sqli-identifier — /private/tmp/secscan-verify/a483b3b1/repo/src/main/resources/mybatis/mapper/lg/LgCarrierMapper.xml:18 · id `53119bce97e0`
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] secscan.rules.mybatis-sqli-identifier — /private/tmp/secscan-verify/a483b3b1/repo/src/main/resources/mybatis/mapper/lg/LgCarrierMapper.xml:19 · id `853712944752`
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] secscan.rules.mybatis-sqli-identifier — /private/tmp/secscan-verify/a483b3b1/repo/src/main/resources/mybatis/mapper/lg/LgCarrierMapper.xml:27 · id `cb31970c42a1`
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] secscan.rules.mybatis-sqli-identifier — /private/tmp/secscan-verify/a483b3b1/repo/src/main/resources/mybatis/mapper/oldlg/OldLgCarrierMapper.xml:36 · id `4053d0befb21`
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] secscan.rules.mybatis-sqli-identifier — /private/tmp/secscan-verify/a483b3b1/repo/src/main/resources/mybatis/mapper/oldlg/OldLgCarrierMapper.xml:37 · id `399a2b3f2480`
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] secscan.rules.mybatis-sqli-identifier — /private/tmp/secscan-verify/a483b3b1/repo/src/main/resources/mybatis/mapper/oldlg/OldLgCarrierMapper.xml:46 · id `f54a584ee8fe`
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] secscan.rules.mybatis-sqli-identifier — /private/tmp/secscan-verify/a483b3b1/repo/src/main/resources/mybatis/mapper/oldlg/OldLgCarrierMapper.xml:60 · id `82a3bb4a2e72`
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] secscan.rules.mybatis-sqli-identifier — /private/tmp/secscan-verify/a483b3b1/repo/src/main/resources/mybatis/mapper/oldlg/OldLgCarrierMapper.xml:69 · id `273b5bf12c75`
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] PREDICTABLE_RANDOM — com/messagegate/carrier/RandomWeightedCarrierSelector.java:34 · id `9694ae769d5a`
- CWE-330 · 탐지: spotbugs (합의 1)
- 컴플라이언스: KISA 적절하지 않은 난수값 사용 · PCI-DSS 6.2.4 — cryptography

### [보통] SPRING_CSRF_PROTECTION_DISABLED — com/messagegate/config/SecurityConfig.java:144 · id `168f63238a8f`
- CWE-352 · 탐지: spotbugs (합의 1)
- 컴플라이언스: KISA 크로스사이트 요청 위조(CSRF) · PCI-DSS 6.2.4 — business logic

### [보통] SPRING_CSRF_PROTECTION_DISABLED — com/messagegate/config/SecurityConfig.java:93 · id `fa999553bab5`
- CWE-352 · 탐지: spotbugs (합의 1)
- 컴플라이언스: KISA 크로스사이트 요청 위조(CSRF) · PCI-DSS 6.2.4 — business logic

### [보통] CRLF_INJECTION_LOGS — com/messagegate/controller/AdminController.java:339 · id `2f6cb21faea8`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/controller/AdminController.java:366 · id `3d6887d1e9ae`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/controller/AdminController.java:392 · id `926ffce7b714`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/controller/AdminController.java:425 · id `8d7db698fffc`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/service/CarrierOverrideService.java:166 · id `3d1236a8a5f8`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/service/CarrierOverrideService.java:199 · id `d5b6578ded9d`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/service/CarrierOverrideService.java:253 · id `331281cbf167`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/service/CarrierWeightService.java:97 · id `3acd50268199`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/service/GracePeriodService.java:105 · id `88f98ed23d92`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/service/GracePeriodService.java:211 · id `233826704b4a`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/service/MessageService.java:311 · id `0d6796f8c1c0`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] SQL_INJECTION_SPRING_JDBC — com/messagegate/service/OutboxAdminService.java:157 · id `6c7ee545c4f7`
- CWE-89 · 탐지: spotbugs (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] SQL_INJECTION_SPRING_JDBC — com/messagegate/service/OutboxAdminService.java:175 · id `f317d7c48df8`
- CWE-89 · 탐지: spotbugs (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] SQL_INJECTION_JDBC — com/messagegate/service/OutboxWorker.java:492 · id `760ab2933988`
- CWE-89 · 탐지: spotbugs (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] PREDICTABLE_RANDOM — com/messagegate/service/OutboxWorker.java:776 · id `2e58b7cf5b8b`
- CWE-330 · 탐지: spotbugs (합의 1)
- 컴플라이언스: KISA 적절하지 않은 난수값 사용 · PCI-DSS 6.2.4 — cryptography

### [보통] CRLF_INJECTION_LOGS — com/messagegate/service/PayloadProfileService.java:141 · id `e689b08515d9`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:242 · id `b15534dc90c8`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:265 · id `547764752abe`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:305 · id `de1014c3aec6`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:309 · id `626c30e81c44`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:328 · id `0b758a01b116`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:343 · id `ea50e2be0135`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:368 · id `5b098c10b69e`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:401 · id `9e9b0fda63a5`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:415 · id `f9c859504985`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:447 · id `0ed86ae0885f`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/util/EmailNotificationHelper.java:35 · id `2e183df642ae`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [보통] CRLF_INJECTION_LOGS — com/messagegate/util/EmailNotificationHelper.java:42 · id `ad9a0a92571e`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthFailureAccountLocker.java:75 · id `3515f8a893cc`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthFailureAccountLocker.java:82 · id `aab74ee32c8d`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP — com/messagegate/auth/AuthFailureAlertContext.java:15 · id `e5088dc52390`
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/auth/AuthFailureAlertContext.java:15 · id `81dec9e1b2be`
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthFailureGuard.java:124 · id `3acb155ba71b`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthFailureGuard.java:200 · id `67f46444988c`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthFailureGuard.java:241 · id `0e8f249978bf`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthFailureGuard.java:335 · id `b5071198533b`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthFailureGuard.java:343 · id `6abf7a1bbb3e`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthFailureGuard.java:362 · id `f240424d028f`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthFailureMailer.java:43 · id `acac0631d821`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthFailureMailer.java:55 · id `1c018984c777`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthFailureMailer.java:80 · id `c64a12bcc9b4`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthService.java:112 · id `53938180cd24`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthService.java:180 · id `43686da3d9dc`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthService.java:214 · id `bb0cac199ae2`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthService.java:238 · id `07ed2f9cff0d`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthService.java:247 · id `54fe15b29657`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthService.java:253 · id `a2722458752f`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthService.java:293 · id `1e208bb84323`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthService.java:304 · id `963c7ce747d7`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthService.java:313 · id `3118b2f4536f`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthService.java:322 · id `28741c7db331`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthService.java:338 · id `4f11040f4f50`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthService.java:382 · id `9262b5a26183`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthService.java:387 · id `0af88dd7935b`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/AuthService.java:99 · id `277937f9d134`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/BasicAuthFilter.java:134 · id `b2bbbfbd3d20`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/BasicAuthFilter.java:141 · id `ac98ea7d2b2c`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/BasicAuthFilter.java:147 · id `d4b12b35a432`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/BasicAuthFilter.java:165 · id `24308a5d421f`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/auth/BasicAuthFilter.java:188 · id `f7b0313b046e`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] IMPROPER_UNICODE — com/messagegate/auth/BasicAuthFilter.java:210 · id `3149f10d5290`
- CWE-176 · 탐지: spotbugs (합의 1)

### [일반] DM_CONVERT_CASE — com/messagegate/carrier/CarrierFactory.java:25 · id `fedba15c8ebd`
- 탐지: spotbugs (합의 1)

### [일반] IMPROPER_UNICODE — com/messagegate/carrier/CarrierFactory.java:25 · id `a3e578c9264a`
- CWE-176 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/CarrierRouter.java:101 · id `8ef1fc1e2436`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/CarrierRouter.java:143 · id `f2d8a15bba83`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] DM_CONVERT_CASE — com/messagegate/carrier/CarrierRouter.java:159 · id `9ff534bfdf97`
- 탐지: spotbugs (합의 1)

### [일반] IMPROPER_UNICODE — com/messagegate/carrier/CarrierRouter.java:159 · id `2d72480bf506`
- CWE-176 · 탐지: spotbugs (합의 1)

### [일반] IMPROPER_UNICODE — com/messagegate/carrier/CarrierRouter.java:160 · id `c41f9a179eda`
- CWE-176 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/CarrierRouter.java:174 · id `2427cdaf1300`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/CarrierRouter.java:181 · id `8f2a8da686a6`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/CarrierRouter.java:195 · id `24e4fb64be46`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/CarrierRouter.java:220 · id `79e5c7f2962d`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] THROWS_METHOD_THROWS_CLAUSE_THROWABLE — com/messagegate/carrier/CarrierRouter.java:243 · id `6e821c7cff1c`
- CWE-397 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/CarrierRouter.java:274 · id `16ba8496e38b`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/CarrierRouter.java:280 · id `a33bd93c60bd`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] THROWS_METHOD_THROWS_RUNTIMEEXCEPTION — com/messagegate/carrier/CarrierRouter.java:309 · id `153336399813`
- CWE-397 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/CarrierRouter.java:73 · id `ed5868e04318`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/CarrierRouter.java:95 · id `ca13b598cec1`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/KTAdapter.java:127 · id `7ec5617e7a81`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/KTAdapter.java:133 · id `7dca68fe3c05`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/KTAdapter.java:176 · id `40b30fda9c10`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/carrier/KTAdapter.java:42 · id `439c39aef316`
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/carrier/KtSequenceAllocator.java:19 · id `03c4425802a1`
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/LGAdapter.java:132 · id `da51c2581d68`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/LGAdapter.java:143 · id `ce43524c4a11`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/LGAdapter.java:150 · id `e67877ebc9fc`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/LGAdapter.java:163 · id `00e1d9302339`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/LGAdapter.java:232 · id `912777482e18`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/carrier/LGAdapter.java:48 · id `a02f06e41dbe`
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/LGAdapter.java:77 · id `97c5e1fae774`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/LGAdapter.java:83 · id `111f05ff6389`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/LGAdapter.java:90 · id `dbcb70a3944d`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/OldLgAdapter.java:111 · id `0328517e2f93`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/OldLgAdapter.java:119 · id `53dd039c5227`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/OldLgAdapter.java:186 · id `e888b620a56c`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/OldLgAdapter.java:202 · id `aeb769241f79`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/carrier/OldLgAdapter.java:45 · id `cc7509d5505d`
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/carrier/OldLgAdapter.java:59 · id `0194a0491777`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] DM_CONVERT_CASE — com/messagegate/carrier/RandomWeightedCarrierSelector.java:51 · id `7f72c7ff38ed`
- 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/common/exception/GlobalExceptionHandler.java:72 · id `67289f226487`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/common/exception/GlobalExceptionHandler.java:74 · id `4764aeea1afe`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] RCN_REDUNDANT_NULLCHECK_OF_NONNULL_VALUE — com/messagegate/common/exception/GlobalExceptionHandler.java:96 · id `fc81a7a28879`
- 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/common/exception/MessageGateException.java:33 · id `10bcaf842ae3`
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/common/exception/MessageGateException.java:47 · id `71f5c80c26ea`
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP — com/messagegate/common/exception/MessageGateException.java:55 · id `43bce4e15d1d`
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] SE_BAD_FIELD — com/messagegate/common/exception/MessageGateException.java · id `5337751067c1`
- 탐지: spotbugs (합의 1)

### [일반] SE_BAD_FIELD — com/messagegate/common/exception/PayloadValidationException.java · id `416d43292416`
- 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/config/CarrierBulkheadConfig.java:22 · id `3ff4066b6ec3`
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/config/CarrierCircuitBreakerConfig.java:29 · id `bf9677478883`
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/config/CarrierCircuitBreakerConfig.java:82 · id `8f2d2e38db79`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/config/CarrierCircuitBreakerConfig.java:88 · id `89a2ecf7b22d`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/config/HttpLoggingFilter.java:34 · id `443ccd8b2f43`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/config/KmsCircuitBreakerConfig.java:155 · id `e912f22d717f`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/config/KmsCircuitBreakerConfig.java:161 · id `3c5c8ee456b5`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/config/LifecycleLoggingListener.java:34 · id `12c55c157939`
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/config/LifecycleLoggingListener.java:41 · id `a88e76266da2`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/config/LifecycleLoggingListener.java:48 · id `7e6d3f1e3c7d`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/AdminController.java:113 · id `9839128da469`
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/AdminController.java:133 · id `0f5251e6c739`
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/AdminController.java:147 · id `b7b276af6b08`
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/AdminController.java:168 · id `bd65ec61abfa`
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/AdminController.java:184 · id `bd823c664518`
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/AdminController.java:203 · id `7776e575ffa8`
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/AdminController.java:217 · id `f35ead78b3aa`
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/AdminController.java:238 · id `d2dc0370543a`
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/AdminController.java:261 · id `786940013dc0`
- 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/controller/AdminController.java:270 · id `5ba59aa8b65a`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/AdminController.java:291 · id `a33e696deb48`
- 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/controller/AdminController.java:299 · id `39d536812078`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/AdminController.java:333 · id `33f4e332a3f4`
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/AdminController.java:360 · id `636c2bf55d9b`
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/AdminController.java:390 · id `3b82ab4f362a`
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/AdminController.java:416 · id `3154b1675a13`
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/AdminController.java:445 · id `0a4eb161004e`
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/AdminController.java:460 · id `a49b64596132`
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/AdminController.java:477 · id `b1f1b095a18b`
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/AdminController.java:500 · id `41c5c2f705e0`
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/AdminController.java:525 · id `4d96ccc23402`
- 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/controller/AdminController.java:96 · id `cd83da8e4567`
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/controller/AdminController.java:97 · id `c7e165a39202`
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/HealthController.java:24 · id `ead556aa9ca9`
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/LoadtestOutboxInsertController.java:46 · id `609e8ba4f357`
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/LoadtestOutboxWorkerController.java:46 · id `0e9a2ce548ac`
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/LoadtestOutboxWorkerController.java:60 · id `0b62fc50db4d`
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/MessageController.java:107 · id `551bfbbe5ac4`
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/MessageController.java:125 · id `f2074519f87d`
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/MessageController.java:144 · id `107aaf3775f3`
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/MessageController.java:162 · id `b0d8b73fbf7a`
- 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/controller/MessageController.java:68 · id `421fe3777787`
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/MessageController.java:84 · id `23ed3845e201`
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/OutboxAdminController.java:44 · id `d4ea73f7355f`
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/OutboxAdminController.java:58 · id `e647ef6eb0cd`
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/PasswordStatusController.java:47 · id `848e5078bfa1`
- 탐지: spotbugs (합의 1)

### [일반] SPRING_ENDPOINT — com/messagegate/controller/PasswordStatusController.java:69 · id `79c069ec3d53`
- 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/dto/ErrorResponse.java:21 · id `d4333d4e9af6`
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP — com/messagegate/dto/SendOutcome.java:3 · id `4b864dcb16e1`
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/dto/SendOutcome.java:3 · id `65a792945e27`
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] SE_NO_SERIALVERSIONID — com/messagegate/entity/CarrierWeightId.java:9 · id `0c859f74cf1e`
- 탐지: spotbugs (합의 1)

### [일반] CT_CONSTRUCTOR_THROW — com/messagegate/entity/MessageErrorLog.java:99 · id `f73f2e8abd23`
- 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QCarrierWeight.java:25 · id `8b854e7a866f`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QCarrierWeight.java:27 · id `d7ac89c6fa5b`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QCarrierWeight.java:29 · id `dcc0d01085fb`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QCarrierWeight.java:31 · id `ebfdff0b621b`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QCarrierWeight.java:33 · id `21e2ff39cbb8`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QCarrierWeight.java:35 · id `0fac5d881f55`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QConfigAudit.java:25 · id `72f26bd9ac6f`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QConfigAudit.java:27 · id `7f48410abec8`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QConfigAudit.java:29 · id `d965bc9c36ac`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QConfigAudit.java:31 · id `5cb69697e4b0`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QConfigAudit.java:33 · id `33cdac41afa5`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QConfigAudit.java:35 · id `a261e861d39c`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QDailyReportMailLog.java:25 · id `30ae185181eb`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QDailyReportMailLog.java:27 · id `55e0a627f634`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QDailyReportMailLog.java:29 · id `3435d94e40a3`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QDailyReportMailLog.java:31 · id `2c3b0404cf21`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QDailyReportMailLog.java:33 · id `52c4b8dc62f7`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QDailyReportMailLog.java:35 · id `7eb6fc75f37f`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QDailyReportMailLog.java:37 · id `172663f3a321`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QDailyReportMailLog.java:39 · id `ba12e0f1819b`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QJobLock.java:25 · id `97fc3dcc44d8`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QJobLock.java:27 · id `8a849c3a31f1`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QJobLock.java:29 · id `214e12598deb`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QJobLock.java:31 · id `e4d2daa40fc8`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QJobLock.java:33 · id `74da1ca533b3`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageErrorLog.java:25 · id `c4321391c187`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageErrorLog.java:27 · id `3f72bfe01c78`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageErrorLog.java:29 · id `de3d9598d3a3`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageErrorLog.java:31 · id `040e401806b1`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageErrorLog.java:33 · id `a3eeec47ba63`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageErrorLog.java:35 · id `b9153640113e`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageErrorLog.java:37 · id `3c378858e339`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageErrorLog.java:39 · id `4a4fc9e12178`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageErrorLog.java:41 · id `2cefec57c47e`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageErrorLog.java:43 · id `46a5db8006f8`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageErrorLog.java:45 · id `c6d2114dd9ba`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageMeta.java:25 · id `7c2c1643607f`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageMeta.java:27 · id `33ca8ce4e573`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageMeta.java:29 · id `0664b1f02c23`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageMeta.java:31 · id `2790cb59126a`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageMeta.java:33 · id `a1d40a6c0a71`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageMeta.java:35 · id `05eca97087ea`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageMeta.java:37 · id `9003319b5ec3`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageMeta.java:39 · id `74a0b9ec5a91`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageMeta.java:41 · id `ee88ad649386`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageMeta.java:43 · id `09e0b6eb10ec`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageMeta.java:45 · id `03999e57e40a`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageMeta.java:47 · id `de6e81335b71`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageMeta.java:49 · id `9a8563544ab7`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageMeta.java:51 · id `c8cb7cd1b9d9`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QMessageMeta.java:53 · id `96515541e3e6`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QOutboxLoadtestRow.java:25 · id `67519f0c04e1`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QOutboxLoadtestRow.java:27 · id `345ef08f2704`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QOutboxLoadtestRow.java:29 · id `c0ccfdf1cc27`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QOutboxLoadtestRow.java:31 · id `3b23b54f774d`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QOutboxLoadtestRow.java:33 · id `d7db4edf0d26`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QOutboxLoadtestRow.java:35 · id `5a5930130527`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QOutboxLoadtestRow.java:37 · id `4c029ed6c761`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QPasswordHistory.java:25 · id `6883f5efcac5`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QPasswordHistory.java:27 · id `ceb107920ae5`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QPasswordHistory.java:29 · id `a91f46aed148`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QPasswordHistory.java:31 · id `2fa6f55cbb12`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QPasswordHistory.java:33 · id `2f90dbfa7f05`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QPasswordHistory.java:35 · id `ed6fa2a876d3`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QPasswordHistory.java:37 · id `878d52ad7b6d`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QPasswordHistory.java:39 · id `e888942da1c7`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QPasswordHistory.java:41 · id `4dc672920bd7`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QPasswordHistory.java:43 · id `6eab3face189`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QPasswordHistory.java:45 · id `f8d5caea9bc8`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QPasswordHistory.java:47 · id `3211b8db9e0d`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QPasswordHistory.java:49 · id `913fbd091ee3`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QPasswordHistory.java:51 · id `5ca196fc7224`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QPasswordHistory.java:53 · id `02a35424d443`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuth.java:30 · id `a31f19b58e03`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuth.java:32 · id `8566f7917af0`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuth.java:34 · id `04c929cb7876`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuth.java:36 · id `c122184b70e8`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuth.java:46 · id `1988518051c8`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuth.java:50 · id `403920424afd`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuth.java:52 · id `491e2cc76e24`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuth.java:54 · id `e79da2bd0cd6`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuth.java:63 · id `e47ee19d4f2d`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuthHistory.java:25 · id `145299e5980b`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuthHistory.java:27 · id `7280b815ee2d`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuthHistory.java:29 · id `187cddd48d2f`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuthHistory.java:31 · id `b9c1e6e1f103`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuthHistory.java:33 · id `5ff137de7b4e`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuthHistory.java:35 · id `d12cf1a21760`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuthHistory.java:37 · id `f93f5b3c4553`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuthHistory.java:39 · id `e4341b67c6f8`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuthHistory.java:41 · id `b7fc1593f330`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuthHistory.java:43 · id `aca696f22b44`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuthHistory.java:45 · id `83c7d1fa7f9d`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuthHistory.java:47 · id `1f86a7e3add1`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuthHistory.java:49 · id `29974b7ec556`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuthHistory.java:51 · id `14b92ea673e0`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceAuthHistory.java:53 · id `c47ce801306a`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceCarrierOverride.java:25 · id `8f75fa7da5a9`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceCarrierOverride.java:27 · id `af7814125c7c`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceCarrierOverride.java:29 · id `96accc8bb71f`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceCarrierOverride.java:31 · id `095b022fc719`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceCarrierOverride.java:33 · id `750ef1ef8f37`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceCarrierOverride.java:35 · id `083032c2aa72`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceCarrierOverride.java:37 · id `480b6dd71c0e`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceSalt.java:25 · id `3c3df66b369f`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceSalt.java:27 · id `5131cc18413a`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QServiceSalt.java:29 · id `3dc976b323a3`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QSystemConfig.java:25 · id `546a9bc1022a`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QSystemConfig.java:27 · id `9d8cc6750a0d`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QSystemConfig.java:29 · id `24af5ff03f2f`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QSystemConfig.java:31 · id `31c2bfdc99a3`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD — com/messagegate/entity/QSystemConfig.java:33 · id `c8d32b4cb8a4`
- CWE-563 · 탐지: spotbugs (합의 1)

### [일반] SE_NO_SERIALVERSIONID — com/messagegate/entity/ServiceCarrierOverrideId.java:8 · id `7861f1b8e4fa`
- 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/logging/AccessEventLogger.java:108 · id `2a1ae613e6da`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/logging/AccessEventLogger.java:124 · id `4376ddd86a3e`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/logging/AccessEventLogger.java:134 · id `354f45419561`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/logging/AccessEventLogger.java:150 · id `0c7243af5dea`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/logging/AccessEventLogger.java:161 · id `d7fb05335466`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/logging/AccessEventLogger.java:175 · id `804683ecf3e7`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/logging/AccessEventLogger.java:189 · id `e39262334339`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/logging/AccessEventLogger.java:53 · id `6c57ad0c64c3`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/logging/AccessEventLogger.java:74 · id `37118fbfba62`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/logging/AccessEventLogger.java:91 · id `d45243a01bf4`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/repository/jpa/ServiceAuthQueryRepositoryImpl.java:170 · id `2b4ecb390582`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/repository/jpa/ServiceAuthQueryRepositoryImpl.java:212 · id `9e5a93a03649`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/scheduler/DailyReportJob.java:50 · id `a45817960f0a`
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/scheduler/InactiveAccountLockerJob.java:42 · id `d55a573adb04`
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/scheduler/JobFailureTracker.java:59 · id `8d3d3ff2be7d`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/scheduler/JobFailureTracker.java:65 · id `d79629f218a1`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/scheduler/JobFailureTracker.java:72 · id `2384cc7ee98e`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/scheduler/JobFailureTracker.java:86 · id `2521065643e7`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/scheduler/JobLockService.java:22 · id `db6208f7bb8f`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/scheduler/JobLockService.java:34 · id `549a0e838ebf`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/scheduler/JobLockService.java:46 · id `91e384ff871d`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/scheduler/MessageMonitoringJob.java:134 · id `19d0d90328d1`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/scheduler/MessageMonitoringJob.java:155 · id `e7c3ab8b9a38`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/scheduler/MessageMonitoringJob.java:160 · id `7ea422d188ae`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/scheduler/MessageMonitoringJob.java:179 · id `5aaa317e34c3`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/scheduler/MessageMonitoringJob.java:185 · id `e9d3a5b34c4d`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/scheduler/MessageMonitoringJob.java:210 · id `f066af2e4034`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/scheduler/MessageMonitoringJob.java:83 · id `ce36b5e945a0`
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/scheduler/PasswordExpiryReminderJob.java:58 · id `060d788f7d74`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP — com/messagegate/security/password/PasswordEncoderProperties.java:30 · id `df5a0d3846b2`
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/security/password/PasswordEncoderProperties.java:34 · id `2c09522b4318`
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP — com/messagegate/security/password/PasswordEncoderProperties.java:38 · id `9a896d11371c`
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/security/password/PasswordEncoderProperties.java:42 · id `36183bb0ad2c`
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP — com/messagegate/security/password/PropertyHmacKeyProvider.java:104 · id `b228619ddee1`
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/security/password/PropertyHmacKeyProvider.java:47 · id `972d42f6bd3c`
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] IMPROPER_UNICODE — com/messagegate/security/password/PropertyHmacKeyProvider.java:62 · id `03504201e7ef`
- CWE-176 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/security/password/SidAwareHashServiceImpl.java:65 · id `77729a0bfbba`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/security/password/SidAwareHashServiceImpl.java:74 · id `361dab038dbd`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/security/payload/OutboxAtRestCipher.java:109 · id `da8c50bdc458`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/security/payload/OutboxAtRestCipher.java:80 · id `bbf00c854856`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/security/payload/PayloadDecryptionService.java:223 · id `89450d065f5f`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/security/payload/PayloadDecryptionService.java:249 · id `60d68d549da2`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/security/payload/PayloadDecryptionService.java:310 · id `9e6c1b45fccc`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/security/payload/PayloadDecryptionService.java:341 · id `d09a3b6cd35e`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/security/payload/PayloadDecryptionService.java:368 · id `24e7f87e710a`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/CarrierDispatchService.java:171 · id `508c2b757030`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/CarrierOverrideService.java:113 · id `b8a7e889d066`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] DM_CONVERT_CASE — com/messagegate/service/CarrierRoutingStatusService.java:52 · id `19f0ce80fd28`
- 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/CarrierWeightService.java:150 · id `81231253a8b3`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/GracePeriodService.java:148 · id `4b2528f2d98c`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/IdempotencyGuardImpl.java:42 · id `fbe2f76c1f7d`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/InactiveAccountTransactionalHelper.java:105 · id `cc924a34a0ef`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/InactiveAccountTransactionalHelper.java:59 · id `a33ae96c73a8`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/InactiveAccountTransactionalHelper.java:67 · id `dc3b400b07a0`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/InactiveAccountTransactionalHelper.java:82 · id `8fa0d9b1c200`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/InactiveAccountTransactionalHelper.java:87 · id `83a58ef2778c`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/service/MessageResendService.java:157 · id `4c72db3bff99`
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/MessageResendService.java:235 · id `5807d5ed5ca9`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/MessageResendService.java:278 · id `ea6ba471df67`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/MessageResendService.java:292 · id `c9bbaf1742b6`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/MessageResendService.java:311 · id `67abcbb62b3d`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/MessageResendService.java:316 · id `47c145be1494`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/MessageResendService.java:334 · id `9e6b8bf194b1`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/MessageResendService.java:351 · id `3811b49c0c1f`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/MessageResendService.java:362 · id `6402e90dc802`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/MessageResendService.java:374 · id `c6f613a13942`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] THROWS_METHOD_THROWS_RUNTIMEEXCEPTION — com/messagegate/service/MessageResendService.java:383 · id `631818c59397`
- CWE-397 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/MessageResendService.java:393 · id `ed5f11e455e5`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/MessageService.java:176 · id `6a9ae702164d`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/MessageService.java:186 · id `872d80d1ab4b`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/MessageService.java:189 · id `c412f77456f1`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/MessageService.java:205 · id `966fe55f53fd`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/MessageService.java:211 · id `55cbf13eae02`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/MessageService.java:230 · id `ff25a4ff6913`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/MessageService.java:232 · id `651ae43d6b36`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/MessageService.java:251 · id `7c412d4f4ada`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/MessageService.java:281 · id `ecd34fe39f5c`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] DM_CONVERT_CASE — com/messagegate/service/MessageService.java:338 · id `3a89c8f16c57`
- 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/service/OutboxAcceptService.java:112 · id `44b1c731c495`
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/OutboxAcceptService.java:141 · id `7ebdbd2bcbb7`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/OutboxAdminService.java:145 · id `bd1b1432bd24`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/service/OutboxDrainSimulator.java:89 · id `f0e98f754b90`
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/OutboxStatusService.java:99 · id `9df27caa5c6d`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CT_CONSTRUCTOR_THROW — com/messagegate/service/OutboxWorker.java:204 · id `206fd7921836`
- 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/service/OutboxWorker.java:209 · id `2dc79c3d1307`
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/service/OutboxWorker.java:216 · id `5513da287722`
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/OutboxWorker.java:343 · id `7ced736fa71c`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/OutboxWorker.java:358 · id `603387e8e1af`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/OutboxWorker.java:383 · id `c6fc2c7d3de0`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] SQL_PREPARED_STATEMENT_GENERATED_FROM_NONCONSTANT_STRING — com/messagegate/service/OutboxWorker.java:492 · id `7aaa4df5b87e`
- CWE-89 · 탐지: spotbugs (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/OutboxWorker.java:523 · id `7c734594ab8b`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/OutboxWorker.java:546 · id `2a78ee6b4eda`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/OutboxWorker.java:559 · id `d804c54443d5`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/OutboxWorker.java:593 · id `d7c9d9dfa233`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/OutboxWorker.java:605 · id `9c4e89cb129f`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/OutboxWorker.java:609 · id `30e11be6d4ce`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/OutboxWorker.java:619 · id `74be9aac99c5`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/OutboxWorker.java:645 · id `0d23a960c25d`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/OutboxWorker.java:683 · id `51e3d36ecea1`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/OutboxWorker.java:695 · id `f1b5ecdce35c`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/OutboxWorker.java:703 · id `2bcaf52e5b32`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/OutboxWorker.java:724 · id `2832904e9208`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/OutboxWorker.java:756 · id `3672f3373121`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/PasswordService.java:129 · id `2f46d1a65d38`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/PasswordService.java:135 · id `693d7cb65d32`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/PayloadProfileService.java:135 · id `99290bb26fed`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP — com/messagegate/service/ReportService.java:161 · id `6c53eb422eb9`
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/service/ReportService.java:161 · id `ccf0fb04bf34`
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:103 · id `31353fed8ce5`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:110 · id `bc755734c019`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:139 · id `9c4a55747d77`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:158 · id `2cde2614b919`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:191 · id `a5ea7eb0dc70`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:200 · id `362f055327e1`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:206 · id `ef72c1f9b95e`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:279 · id `61612ebbd9f8`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:288 · id `23eb4ae863a2`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:297 · id `53f5c0df1cbf`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:382 · id `aa3e7bc9b0aa`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:391 · id `f9844ea4b48b`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:409 · id `b95dea4f5117`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:429 · id `65527c91c7f8`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:478 · id `2403e9f57ce7`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/ServiceAccountManagementService.java:512 · id `f893cc340c6d`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/service/ServiceAccountManagementService.java:86 · id `be1ab8b8f35a`
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/SystemAlertService.java:196 · id `2deb9748723f`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/SystemAlertService.java:200 · id `d8ccfe9164d1`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/SystemAlertService.java:213 · id `05d32d444a91`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/SystemAlertService.java:217 · id `fe4b7c290b38`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/SystemAlertService.java:245 · id `7279ee67a98f`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/service/SystemAlertService.java:254 · id `601f9d430f4c`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] EI_EXPOSE_REP2 — com/messagegate/service/SystemAlertService.java:78 · id `7825e9a90219`
- CWE-374 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/util/EmailNotificationHelper.java:54 · id `41b883007c68`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

### [일반] CRLF_INJECTION_LOGS — com/messagegate/util/MonthSuffixValidator.java:41 · id `6eddd74bf2ca`
- CWE-117 CWE-93 · 탐지: spotbugs (합의 1)

## 낮은 우선순위 — 도달 불가 (SCA)
_해당 없음._
