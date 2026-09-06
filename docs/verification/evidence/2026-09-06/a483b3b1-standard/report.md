# 보안 점검 보고서 — secscan

- 대상: `a483b3b1`
- 스캐너: gitleaks ok (0.884s) · semgrep ok (6.99s) · trivy ok (0.537s)

## 요약
- 총 **73건** — 심각 3, 위험 27, 보통 39, 일반 4
- 도달성: 도달 가능 **0** · 도달 불가 **48** · 미상 **25**
- ℹ️ 도달 불가 48건은 우선순위가 낮습니다(노이즈 후보).
- 컴플라이언스: KISA 약점 매핑 **25건** · PCI-DSS 6.2.4 관련 **25건**

> ⚠️ **정적 분석 사각지대**: 도달성 판정은 리플렉션·DI(Spring proxy)·역직렬화·동적 디스패치·애노테이션 라우팅을 놓칠 수 있습니다. '도달 불가'는 *우선순위 강등* 근거일 뿐 안전 보증이 아닙니다. 억제는 사람이 증거를 확인해 확정하세요(자동 억제 없음).

> ℹ️ **SAST(Semgrep CE) 주의**: taint 분석이 **intraprocedural**(함수 내)로 제한되어 함수·파일 경계를 넘는 데이터 흐름은 놓칠 수 있습니다(spec §10.2). CE 에서는 일부 Pro 전용·프레임워크 룰이 발화하지 않으며, Kotlin 커버리지는 Java 보다 약합니다(못 잡는 것을 숨기지 않습니다). 깊은 cross-function 분석은 향후 CodeQL(C)로 보강 예정.

## 우선 조치
### [위험] secscan.rules.hardcoded-credential — src/main/java/com/messagegate/common/constants/KmsProfilePolicy.java:30 · id `3c515977938d`
- CWE-798 CWE-259 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA 하드코드된 중요정보 · PCI-DSS 6.2.4 — access control

### [위험] generic-api-key — docs/superpowers/plans/2026-05-20-sha512-password-encoder.md:960 · id `476a08d084f4`
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — docs/superpowers/plans/2026-05-20-sha512-password-encoder.md:977 · id `2b78c2db86f3`
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — docs/superpowers/plans/2026-06-07-kms-cbc-payload-encryption.md:182 · id `675cff8c0fd4`
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — docs/superpowers/specs/2026-06-29-password-self-renewal-design.md:79 · id `e6c03578d14c`
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — docs/superpowers/specs/2026-06-30-structured-access-logging-design.md:104 · id `35d37f1243b5`
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — docs/superpowers/specs/2026-06-30-structured-access-logging-design.md:99 · id `8da7b0f560ae`
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — docs/testing/api-test-cases.md:860 · id `4d1d0356c0de`
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — docs/testing/api-test-cases.md:909 · id `4b15161ba0ad`
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — src/main/resources/application-example.yml:76 · id `44d6884c37aa`
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — src/main/resources/application-loadtest.yml:118 · id `46f56fbd51f4`
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — src/test/java/com/messagegate/auth/AuthServiceTest.java:630 · id `a345308dff24`
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — src/test/resources/application-test.yml:132 · id `59ae8507845e`
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — src/test/resources/application-test.yml:84 · id `b6629e49c8ba`
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

## 검토 후보 (낮은 신뢰)
### [보통] secscan.rules.mybatis-sqli-identifier — src/main/java/com/messagegate/mapper/lg/LgCarrierMapper.java:40 · id `6b755dee0421`
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] secscan.rules.mybatis-sqli-identifier — src/main/java/com/messagegate/mapper/oldlg/OldLgCarrierMapper.java:70 · id `f940134d24a8`
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] secscan.rules.mybatis-sqli-identifier — src/main/java/com/messagegate/mapper/oldlg/OldLgCarrierMapper.java:92 · id `4db956798d6a`
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] secscan.rules.mybatis-sqli-identifier — src/main/resources/mybatis/mapper/lg/LgCarrierMapper.xml:18 · id `dfd8e958e0a2`
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] secscan.rules.mybatis-sqli-identifier — src/main/resources/mybatis/mapper/lg/LgCarrierMapper.xml:19 · id `b2274769a4d7`
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] secscan.rules.mybatis-sqli-identifier — src/main/resources/mybatis/mapper/lg/LgCarrierMapper.xml:27 · id `bf038aa3a89b`
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] secscan.rules.mybatis-sqli-identifier — src/main/resources/mybatis/mapper/oldlg/OldLgCarrierMapper.xml:36 · id `d00efbc757bd`
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] secscan.rules.mybatis-sqli-identifier — src/main/resources/mybatis/mapper/oldlg/OldLgCarrierMapper.xml:37 · id `518a733267ca`
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] secscan.rules.mybatis-sqli-identifier — src/main/resources/mybatis/mapper/oldlg/OldLgCarrierMapper.xml:46 · id `4aa2d344ae87`
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] secscan.rules.mybatis-sqli-identifier — src/main/resources/mybatis/mapper/oldlg/OldLgCarrierMapper.xml:60 · id `87f6be044225`
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] secscan.rules.mybatis-sqli-identifier — src/main/resources/mybatis/mapper/oldlg/OldLgCarrierMapper.xml:69 · id `e7ab5de86297`
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

## 낮은 우선순위 — 도달 불가 (SCA)
### [심각] CVE-2026-65182 — org.apache.tomcat.embed:tomcat-embed-core@11.0.22 · id `494bf1b2dc7d`
- 도달성: **도달 불가** (dep-scan)
- 수정: `11.0.25, 10.1.58, 9.0.121` 이상으로 업그레이드
- CWE-284 CWE-863 · 탐지: trivy (합의 1)

### [심각] CVE-2026-65905 — org.apache.tomcat.embed:tomcat-embed-core@11.0.22 · id `eca2f3434dc5`
- 도달성: **도달 불가** (dep-scan)
- 수정: `11.0.25, 10.1.58, 9.0.121` 이상으로 업그레이드
- CWE-294 · 탐지: trivy (합의 1)

### [심각] CVE-2026-68525 — org.apache.tomcat.embed:tomcat-embed-core@11.0.22 · id `f95f95fa4dd7`
- 도달성: **도달 불가** (dep-scan)
- 수정: `11.0.25, 10.1.58, 9.0.121` 이상으로 업그레이드
- CWE-863 · 탐지: trivy (합의 1)

### [위험] GHSA-r7wm-3cxj-wff9 — com.fasterxml.jackson.core:jackson-core@2.21.2 · id `97b125c3ca5a`
- 도달성: **도달 불가** (dep-scan)
- 수정: `2.18.8, 2.21.4` 이상으로 업그레이드
- 탐지: trivy (합의 1)

### [위험] CVE-2026-54512 — com.fasterxml.jackson.core:jackson-databind@2.21.2 · id `5a948d71dd88`
- 도달성: **도달 불가** (dep-scan)
- 수정: `2.18.8, 3.1.4, 2.21.4` 이상으로 업그레이드
- CWE-184 CWE-502 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 신뢰할 수 없는 데이터의 역직렬화 · PCI-DSS 6.2.4 — injection

### [위험] CVE-2026-54513 — com.fasterxml.jackson.core:jackson-databind@2.21.2 · id `dee6ba128869`
- 도달성: **도달 불가** (dep-scan)
- 수정: `2.18.8, 2.21.4, 3.1.4` 이상으로 업그레이드
- CWE-184 · 탐지: trivy (합의 1)

### [위험] CVE-2026-40983 — io.micrometer:micrometer-core@1.16.5 · id `ec2ddc6ed4d6`
- 도달성: **도달 불가** (dep-scan)
- 수정: `1.16.6, 1.15.12` 이상으로 업그레이드
- CWE-400 CWE-770 · 탐지: trivy (합의 1)

### [위험] CVE-2026-40984 — io.micrometer:micrometer-core@1.16.5 · id `63c7e5b17ce4`
- 도달성: **도달 불가** (dep-scan)
- 수정: `1.16.6, 1.15.12` 이상으로 업그레이드
- CWE-400 CWE-770 · 탐지: trivy (합의 1)

### [위험] CVE-2026-41695 — org.springframework.data:spring-data-commons@4.0.5 · id `27770b969d5c`
- 도달성: **도달 불가** (dep-scan)
- 수정: `4.0.6, 3.5.12` 이상으로 업그레이드
- CWE-400 · 탐지: trivy (합의 1)

### [위험] CVE-2026-41716 — org.springframework.data:spring-data-commons@4.0.5 · id `63ae23f65444`
- 도달성: **도달 불가** (dep-scan)
- 수정: `4.0.6, 3.5.12` 이상으로 업그레이드
- CWE-770 · 탐지: trivy (합의 1)

### [위험] CVE-2026-41850 — org.springframework:spring-expression@7.0.7 · id `ec11668ec58e`
- 도달성: **도달 불가** (dep-scan)
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-407 · 탐지: trivy (합의 1)

### [위험] CVE-2026-41842 — org.springframework:spring-webmvc@7.0.7 · id `2bd37a7f5e43`
- 도달성: **도달 불가** (dep-scan)
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-400 · 탐지: trivy (합의 1)

### [위험] CVE-2026-41845 — org.springframework:spring-webmvc@7.0.7 · id `f83f4a9723f8`
- 도달성: **도달 불가** (dep-scan)
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-79 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 크로스사이트 스크립트(XSS) · PCI-DSS 6.2.4 — injection

### [위험] GHSA-r7wm-3cxj-wff9 — tools.jackson.core:jackson-core@3.1.2 · id `32d151df56d7`
- 도달성: **도달 불가** (dep-scan)
- 수정: `3.1.4` 이상으로 업그레이드
- 탐지: trivy (합의 1)

### [위험] CVE-2026-54512 — tools.jackson.core:jackson-databind@3.1.2 · id `5381c1a80d26`
- 도달성: **도달 불가** (dep-scan)
- 수정: `3.1.4` 이상으로 업그레이드
- CWE-184 CWE-502 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 신뢰할 수 없는 데이터의 역직렬화 · PCI-DSS 6.2.4 — injection

### [위험] CVE-2026-54513 — tools.jackson.core:jackson-databind@3.1.2 · id `f973cf6af03a`
- 도달성: **도달 불가** (dep-scan)
- 수정: `3.1.4` 이상으로 업그레이드
- CWE-184 · 탐지: trivy (합의 1)

### [보통] CVE-2026-54514 — com.fasterxml.jackson.core:jackson-databind@2.21.2 · id `6a8468772377`
- 도달성: **도달 불가** (dep-scan)
- 수정: `2.18.8, 2.21.4, 3.1.4` 이상으로 업그레이드
- CWE-918 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 서버사이드 요청 위조(SSRF) · PCI-DSS 6.2.4 — business logic

### [보통] CVE-2026-54515 — com.fasterxml.jackson.core:jackson-databind@2.21.2 · id `70f5ca7b9c8d`
- 도달성: **도달 불가** (dep-scan)
- 수정: `3.1.4, 2.18.9, 2.21.5, 2.22.1` 이상으로 업그레이드
- CWE-915 · 탐지: trivy (합의 1)

### [보통] CVE-2026-54516 — com.fasterxml.jackson.core:jackson-databind@2.21.2 · id `26157a86e040`
- 도달성: **도달 불가** (dep-scan)
- 수정: `2.21.4, 3.1.4` 이상으로 업그레이드
- CWE-915 · 탐지: trivy (합의 1)

### [보통] CVE-2026-54517 — com.fasterxml.jackson.core:jackson-databind@2.21.2 · id `da7a8a4395ac`
- 도달성: **도달 불가** (dep-scan)
- 수정: `2.21.4, 3.1.4` 이상으로 업그레이드
- CWE-863 · 탐지: trivy (합의 1)

### [보통] CVE-2026-54518 — com.fasterxml.jackson.core:jackson-databind@2.21.2 · id `8ea8abe066bd`
- 도달성: **도달 불가** (dep-scan)
- 수정: `2.21.4` 이상으로 업그레이드
- CWE-863 · 탐지: trivy (합의 1)

### [보통] CVE-2026-59888 — com.fasterxml.jackson.core:jackson-databind@2.21.2 · id `73193fb7f937`
- 도달성: **도달 불가** (dep-scan)
- 수정: `2.18.8, 2.21.4` 이상으로 업그레이드
- CWE-915 · 탐지: trivy (합의 1)

### [보통] CVE-2026-59889 — com.fasterxml.jackson.core:jackson-databind@2.21.2 · id `9cb4c6240105`
- 도달성: **도달 불가** (dep-scan)
- 수정: `2.21.5, 2.18.9, 2.22.1` 이상으로 업그레이드
- CWE-863 · 탐지: trivy (합의 1)

### [보통] GHSA-mhm7-754m-9p8w — com.fasterxml.jackson.core:jackson-databind@2.21.2 · id `849aa917d353`
- 도달성: **도달 불가** (dep-scan)
- 수정: `2.18.9, 2.21.5` 이상으로 업그레이드
- 탐지: trivy (합의 1)

### [보통] CVE-2026-49844 — org.apache.logging.log4j:log4j-api@2.25.4 · id `e0bd29ddbb20`
- 도달성: **도달 불가** (dep-scan)
- 수정: `2.25.5, 2.26.1` 이상으로 업그레이드
- CWE-116 · 탐지: trivy (합의 1)

### [보통] CVE-2026-41001 — org.springframework.boot:spring-boot-autoconfigure@4.0.6 · id `d90388f4a666`
- 도달성: **도달 불가** (dep-scan)
- 수정: `4.0.7, 3.5.15` 이상으로 업그레이드
- CWE-377 · 탐지: trivy (합의 1)

### [보통] CVE-2026-40992 — org.springframework.boot:spring-boot-starter-mail@4.0.6 · id `50e2592380a5`
- 도달성: **도달 불가** (dep-scan)
- 수정: `4.0.7, 3.5.15` 이상으로 업그레이드
- CWE-295 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 부적절한 인증서 유효성 검증 · PCI-DSS 6.2.4 — cryptography

### [보통] CVE-2026-41711 — org.springframework.data:spring-data-commons@4.0.5 · id `32a87b644940`
- 도달성: **도달 불가** (dep-scan)
- 수정: `4.0.6, 3.5.12` 이상으로 업그레이드
- CWE-400 · 탐지: trivy (합의 1)

### [보통] CVE-2026-41721 — org.springframework.data:spring-data-commons@4.0.5 · id `da73be808e24`
- 도달성: **도달 불가** (dep-scan)
- 수정: `4.0.6, 3.5.12` 이상으로 업그레이드
- CWE-400 · 탐지: trivy (합의 1)

### [보통] CVE-2026-41706 — org.springframework.security:spring-security-web@7.0.5 · id `f8eeb1ae7dec`
- 도달성: **도달 불가** (dep-scan)
- 수정: `7.0.6, 6.5.11` 이상으로 업그레이드
- CWE-601 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 신뢰되지 않는 URL 주소로 자동접속 연결 · PCI-DSS 6.2.4 — business logic

### [보통] CVE-2026-41851 — org.springframework:spring-expression@7.0.7 · id `597228550044`
- 도달성: **도달 불가** (dep-scan)
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-770 · 탐지: trivy (합의 1)

### [보통] CVE-2026-41841 — org.springframework:spring-webmvc@7.0.7 · id `a32cec304e8e`
- 도달성: **도달 불가** (dep-scan)
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-524 · 탐지: trivy (합의 1)

### [보통] CVE-2026-41843 — org.springframework:spring-webmvc@7.0.7 · id `1152f302a96c`
- 도달성: **도달 불가** (dep-scan)
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-22 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 경로 조작 및 자원 삽입 · PCI-DSS 6.2.4 — injection

### [보통] CVE-2026-41844 — org.springframework:spring-webmvc@7.0.7 · id `721c61d5119b`
- 도달성: **도달 불가** (dep-scan)
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-601 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 신뢰되지 않는 URL 주소로 자동접속 연결 · PCI-DSS 6.2.4 — business logic

### [보통] CVE-2026-41846 — org.springframework:spring-webmvc@7.0.7 · id `1c725b3e6882`
- 도달성: **도달 불가** (dep-scan)
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-79 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 크로스사이트 스크립트(XSS) · PCI-DSS 6.2.4 — injection

### [보통] CVE-2026-41853 — org.springframework:spring-webmvc@7.0.7 · id `21037de4c299`
- 도달성: **도달 불가** (dep-scan)
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-444 · 탐지: trivy (합의 1)

### [보통] CVE-2026-41854 — org.springframework:spring-web@7.0.7 · id `c9d6e8495d18`
- 도달성: **도달 불가** (dep-scan)
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-918 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 서버사이드 요청 위조(SSRF) · PCI-DSS 6.2.4 — business logic

### [보통] CVE-2026-54514 — tools.jackson.core:jackson-databind@3.1.2 · id `b51207774023`
- 도달성: **도달 불가** (dep-scan)
- 수정: `2.21.4, 3.1.4` 이상으로 업그레이드
- CWE-918 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 서버사이드 요청 위조(SSRF) · PCI-DSS 6.2.4 — business logic

### [보통] CVE-2026-54515 — tools.jackson.core:jackson-databind@3.1.2 · id `e340a403d09c`
- 도달성: **도달 불가** (dep-scan)
- 수정: `3.1.4` 이상으로 업그레이드
- CWE-915 · 탐지: trivy (합의 1)

### [보통] CVE-2026-54516 — tools.jackson.core:jackson-databind@3.1.2 · id `36dc696461c0`
- 도달성: **도달 불가** (dep-scan)
- 수정: `3.1.4` 이상으로 업그레이드
- CWE-915 · 탐지: trivy (합의 1)

### [보통] CVE-2026-54517 — tools.jackson.core:jackson-databind@3.1.2 · id `a5fb2a0b5507`
- 도달성: **도달 불가** (dep-scan)
- 수정: `3.1.4` 이상으로 업그레이드
- CWE-863 · 탐지: trivy (합의 1)

### [보통] CVE-2026-54518 — tools.jackson.core:jackson-databind@3.1.2 · id `338c83011c94`
- 도달성: **도달 불가** (dep-scan)
- 수정: `3.1.4` 이상으로 업그레이드
- CWE-863 · 탐지: trivy (합의 1)

### [보통] CVE-2026-59888 — tools.jackson.core:jackson-databind@3.1.2 · id `4f7f6582dfc0`
- 도달성: **도달 불가** (dep-scan)
- 수정: `3.1.4` 이상으로 업그레이드
- CWE-915 · 탐지: trivy (합의 1)

### [보통] CVE-2026-59889 — tools.jackson.core:jackson-databind@3.1.2 · id `9baaafc6e4d2`
- 도달성: **도달 불가** (dep-scan)
- 수정: `3.1.5, 3.2.1` 이상으로 업그레이드
- CWE-863 · 탐지: trivy (합의 1)

### [일반] CVE-2026-10532 — ch.qos.logback:logback-core@1.5.32 · id `6fd0eca65eae`
- 도달성: **도달 불가** (dep-scan)
- 수정: `1.5.34` 이상으로 업그레이드
- CWE-502 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 신뢰할 수 없는 데이터의 역직렬화 · PCI-DSS 6.2.4 — injection

### [일반] CVE-2026-9828 — ch.qos.logback:logback-core@1.5.32 · id `1a4f28dc8fac`
- 도달성: **도달 불가** (dep-scan)
- 수정: `1.5.33` 이상으로 업그레이드
- CWE-502 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 신뢰할 수 없는 데이터의 역직렬화 · PCI-DSS 6.2.4 — injection

### [일반] CVE-2026-41848 — org.springframework:spring-core@7.0.7 · id `12ef34192ff5`
- 도달성: **도달 불가** (dep-scan)
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-1333 · 탐지: trivy (합의 1)

### [일반] CVE-2026-41852 — org.springframework:spring-expression@7.0.7 · id `c986cf4e4411`
- 도달성: **도달 불가** (dep-scan)
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-863 · 탐지: trivy (합의 1)
