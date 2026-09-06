# 보안 점검 보고서 — secscan

- 대상: `81f4f31b`
- 스캐너: gitleaks ok · semgrep ok · trivy ok

## 요약
- 총 **82건** — 심각 7, 위험 31, 보통 37, 일반 7
- 도달성: 도달 가능 **0** · 도달 불가 **0** · 미상 **82**
- 컴플라이언스: KISA 약점 매핑 **22건** · PCI-DSS 6.2.4 관련 **22건**

> ⚠️ **정적 분석 사각지대**: 도달성 판정은 리플렉션·DI(Spring proxy)·역직렬화·동적 디스패치·애노테이션 라우팅을 놓칠 수 있습니다. '도달 불가'는 *우선순위 강등* 근거일 뿐 안전 보증이 아닙니다. 억제는 사람이 증거를 확인해 확정하세요(자동 억제 없음).

> ℹ️ **SAST(Semgrep CE) 주의**: taint 분석이 **intraprocedural**(함수 내)로 제한되어 함수·파일 경계를 넘는 데이터 흐름은 놓칠 수 있습니다(spec §10.2). CE 에서는 일부 Pro 전용·프레임워크 룰이 발화하지 않으며, Kotlin 커버리지는 Java 보다 약합니다(못 잡는 것을 숨기지 않습니다). 깊은 cross-function 분석은 향후 CodeQL(C)로 보강 예정.

## 우선 조치
### [심각] CVE-2026-41293 — org.apache.tomcat.embed:tomcat-embed-core@11.0.20 · id `57266c8c4142`
- 도달성: **도달성 미상**
- 수정: `9.0.118, 10.1.55, 11.0.22` 이상으로 업그레이드
- CWE-20 · 탐지: trivy (합의 1)

### [심각] CVE-2026-43512 — org.apache.tomcat.embed:tomcat-embed-core@11.0.20 · id `d06b14c9205b`
- 도달성: **도달성 미상**
- 수정: `9.0.118, 10.1.55, 11.0.22` 이상으로 업그레이드
- CWE-592 · 탐지: trivy (합의 1)

### [심각] CVE-2026-43515 — org.apache.tomcat.embed:tomcat-embed-core@11.0.20 · id `3bc224a62def`
- 도달성: **도달성 미상**
- 수정: `9.0.118, 10.1.55, 11.0.22` 이상으로 업그레이드
- CWE-285 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 부적절한 인가 · PCI-DSS 6.2.4 — access control

### [심각] CVE-2026-65182 — org.apache.tomcat.embed:tomcat-embed-core@11.0.20 · id `aa732bf8d735`
- 도달성: **도달성 미상**
- 수정: `11.0.25, 10.1.58, 9.0.121` 이상으로 업그레이드
- CWE-284 CWE-863 · 탐지: trivy (합의 1)

### [심각] CVE-2026-65905 — org.apache.tomcat.embed:tomcat-embed-core@11.0.20 · id `af6adbd90816`
- 도달성: **도달성 미상**
- 수정: `11.0.25, 10.1.58, 9.0.121` 이상으로 업그레이드
- CWE-294 · 탐지: trivy (합의 1)

### [심각] CVE-2026-68525 — org.apache.tomcat.embed:tomcat-embed-core@11.0.20 · id `30a5f94fc8c3`
- 도달성: **도달성 미상**
- 수정: `11.0.25, 10.1.58, 9.0.121` 이상으로 업그레이드
- CWE-863 · 탐지: trivy (합의 1)

### [심각] CVE-2026-40976 — org.springframework.boot:spring-boot@4.0.5 · id `0f11d4a61b2e`
- 도달성: **도달성 미상**
- 수정: `4.0.6` 이상으로 업그레이드
- CWE-862 CWE-305 · 탐지: trivy (합의 1)

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

### [위험] CVE-2026-40983 — io.micrometer:micrometer-core@1.16.4 · id `e5a4d480dca3`
- 도달성: **도달성 미상**
- 수정: `1.16.6, 1.15.12` 이상으로 업그레이드
- CWE-400 CWE-770 · 탐지: trivy (합의 1)

### [위험] CVE-2026-40984 — io.micrometer:micrometer-core@1.16.4 · id `bea6fd12bfd7`
- 도달성: **도달성 미상**
- 수정: `1.16.6, 1.15.12` 이상으로 업그레이드
- CWE-400 CWE-770 · 탐지: trivy (합의 1)

### [위험] CVE-2026-34483 — org.apache.tomcat.embed:tomcat-embed-core@11.0.20 · id `ce571cb765db`
- 도달성: **도달성 미상**
- 수정: `9.0.116, 10.1.54, 11.0.21` 이상으로 업그레이드
- CWE-116 · 탐지: trivy (합의 1)

### [위험] CVE-2026-34487 — org.apache.tomcat.embed:tomcat-embed-core@11.0.20 · id `6c0d42de1f48`
- 도달성: **도달성 미상**
- 수정: `9.0.117, 10.1.54, 11.0.21` 이상으로 업그레이드
- CWE-532 · 탐지: trivy (합의 1)

### [위험] CVE-2026-41284 — org.apache.tomcat.embed:tomcat-embed-core@11.0.20 · id `ac3c9131930c`
- 도달성: **도달성 미상**
- 수정: `9.0.118, 10.1.55, 11.0.22` 이상으로 업그레이드
- CWE-770 · 탐지: trivy (합의 1)

### [위험] CVE-2026-42498 — org.apache.tomcat.embed:tomcat-embed-core@11.0.20 · id `c5171b234c63`
- 도달성: **도달성 미상**
- 수정: `9.0.118, 10.1.55, 11.0.22` 이상으로 업그레이드
- CWE-200 · 탐지: trivy (합의 1)

### [위험] CVE-2026-43513 — org.apache.tomcat.embed:tomcat-embed-core@11.0.20 · id `f641a8abd8b8`
- 도달성: **도달성 미상**
- 수정: `9.0.118, 10.1.55, 11.0.22` 이상으로 업그레이드
- CWE-178 · 탐지: trivy (합의 1)

### [위험] CVE-2026-40973 — org.springframework.boot:spring-boot@4.0.5 · id `a4ebe65e499c`
- 도달성: **도달성 미상**
- 수정: `4.0.6, 3.5.14` 이상으로 업그레이드
- CWE-377 · 탐지: trivy (합의 1)

### [위험] CVE-2026-41695 — org.springframework.data:spring-data-commons@4.0.4 · id `43bf08743eb1`
- 도달성: **도달성 미상**
- 수정: `4.0.6, 3.5.12` 이상으로 업그레이드
- CWE-400 · 탐지: trivy (합의 1)

### [위험] CVE-2026-41716 — org.springframework.data:spring-data-commons@4.0.4 · id `aa865681c0ec`
- 도달성: **도달성 미상**
- 수정: `4.0.6, 3.5.12` 이상으로 업그레이드
- CWE-770 · 탐지: trivy (합의 1)

### [위험] CVE-2026-22753 — org.springframework.security:spring-security-config@7.0.4 · id `1426d050ad80`
- 도달성: **도달성 미상**
- 수정: `7.0.5` 이상으로 업그레이드
- CWE-693 · 탐지: trivy (합의 1)

### [위험] CVE-2026-22754 — org.springframework.security:spring-security-config@7.0.4 · id `0b0e0488cb64`
- 도달성: **도달성 미상**
- 수정: `7.0.5` 이상으로 업그레이드
- CWE-284 CWE-551 · 탐지: trivy (합의 1)

### [위험] CVE-2026-41850 — org.springframework:spring-expression@7.0.6 · id `33c2321614d9`
- 도달성: **도달성 미상**
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-407 · 탐지: trivy (합의 1)

### [위험] CVE-2026-41842 — org.springframework:spring-webmvc@7.0.6 · id `03cf125e1b0f`
- 도달성: **도달성 미상**
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-400 · 탐지: trivy (합의 1)

### [위험] CVE-2026-41845 — org.springframework:spring-webmvc@7.0.6 · id `93264fb08de1`
- 도달성: **도달성 미상**
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-79 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 크로스사이트 스크립트(XSS) · PCI-DSS 6.2.4 — injection

### [위험] GHSA-2m67-wjpj-xhg9 — tools.jackson.core:jackson-core@3.1.0 · id `673c4b1d4539`
- 도달성: **도달성 미상**
- 수정: `3.1.1` 이상으로 업그레이드
- 탐지: trivy (합의 1)

### [위험] GHSA-r7wm-3cxj-wff9 — tools.jackson.core:jackson-core@3.1.0 · id `7426c5c77acb`
- 도달성: **도달성 미상**
- 수정: `3.1.4` 이상으로 업그레이드
- 탐지: trivy (합의 1)

### [위험] CVE-2026-54512 — tools.jackson.core:jackson-databind@3.1.0 · id `97200f954a9b`
- 도달성: **도달성 미상**
- 수정: `3.1.4` 이상으로 업그레이드
- CWE-184 CWE-502 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 신뢰할 수 없는 데이터의 역직렬화 · PCI-DSS 6.2.4 — injection

### [위험] CVE-2026-54513 — tools.jackson.core:jackson-databind@3.1.0 · id `2d6f3f77682b`
- 도달성: **도달성 미상**
- 수정: `3.1.4` 이상으로 업그레이드
- CWE-184 · 탐지: trivy (합의 1)

### [위험] generic-api-key — /private/tmp/secscan-verify/81f4f31b/repo/docs/superpowers/plans/2026-05-20-sha512-password-encoder.md:953 · id `bd2064eb9bb2`
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — /private/tmp/secscan-verify/81f4f31b/repo/docs/superpowers/plans/2026-05-20-sha512-password-encoder.md:970 · id `eb4739a03c80`
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — /private/tmp/secscan-verify/81f4f31b/repo/docs/superpowers/plans/2026-06-07-kms-cbc-payload-encryption.md:182 · id `a06f61feccbd`
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — /private/tmp/secscan-verify/81f4f31b/repo/src/main/resources/application-example.yml:69 · id `033534c73952`
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — /private/tmp/secscan-verify/81f4f31b/repo/src/main/resources/application-loadtest.yml:117 · id `a7e39981bf7a`
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — /private/tmp/secscan-verify/81f4f31b/repo/src/test/java/com/messagegate/auth/AuthServiceTest.java:525 · id `541b5a87bc21`
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — /private/tmp/secscan-verify/81f4f31b/repo/src/test/resources/application-test.yml:110 · id `bd3812aad828`
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] generic-api-key — /private/tmp/secscan-verify/81f4f31b/repo/src/test/resources/application-test.yml:61 · id `4e223c017a07`
- 하드코딩된 시크릿 — **즉시 회수(revoke)·교체**하고 코드/히스토리에서 제거
- 탐지: gitleaks (합의 1)

### [위험] private-key — /private/tmp/secscan-verify/81f4f31b/repo/src/test/resources/tls/test-server.key:1 · id `ca387b593ae5`
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

### [보통] CVE-2026-49844 — org.apache.logging.log4j:log4j-api@2.25.3 · id `a51695e3fc60`
- 도달성: **도달성 미상**
- 수정: `2.25.5, 2.26.1` 이상으로 업그레이드
- CWE-116 · 탐지: trivy (합의 1)

### [보통] CVE-2026-41001 — org.springframework.boot:spring-boot-autoconfigure@4.0.5 · id `45f91a963862`
- 도달성: **도달성 미상**
- 수정: `4.0.7, 3.5.15` 이상으로 업그레이드
- CWE-377 · 탐지: trivy (합의 1)

### [보통] CVE-2026-40992 — org.springframework.boot:spring-boot-starter-mail@4.0.5 · id `d799cec454c5`
- 도달성: **도달성 미상**
- 수정: `4.0.7, 3.5.15` 이상으로 업그레이드
- CWE-295 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 부적절한 인증서 유효성 검증 · PCI-DSS 6.2.4 — cryptography

### [보통] CVE-2026-41711 — org.springframework.data:spring-data-commons@4.0.4 · id `631c01f10a8b`
- 도달성: **도달성 미상**
- 수정: `4.0.6, 3.5.12` 이상으로 업그레이드
- CWE-400 · 탐지: trivy (합의 1)

### [보통] CVE-2026-41721 — org.springframework.data:spring-data-commons@4.0.4 · id `e0f4974ee657`
- 도달성: **도달성 미상**
- 수정: `4.0.6, 3.5.12` 이상으로 업그레이드
- CWE-400 · 탐지: trivy (합의 1)

### [보통] CVE-2026-22751 — org.springframework.security:spring-security-core@7.0.4 · id `6b6234ac3d03`
- 도달성: **도달성 미상**
- 수정: `6.5.10, 7.0.5` 이상으로 업그레이드
- CWE-367 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 경쟁조건: 검사시점과 사용시점(TOCTOU) · PCI-DSS 6.2.4 — business logic

### [보통] CVE-2026-22747 — org.springframework.security:spring-security-web@7.0.4 · id `b84ef2ad090c`
- 도달성: **도달성 미상**
- 수정: `7.0.5` 이상으로 업그레이드
- CWE-297 CWE-295 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 부적절한 인증서 유효성 검증 · PCI-DSS 6.2.4 — cryptography

### [보통] CVE-2026-41706 — org.springframework.security:spring-security-web@7.0.4 · id `b3f2a05c484e`
- 도달성: **도달성 미상**
- 수정: `7.0.6, 6.5.11` 이상으로 업그레이드
- CWE-601 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 신뢰되지 않는 URL 주소로 자동접속 연결 · PCI-DSS 6.2.4 — business logic

### [보통] CVE-2026-41851 — org.springframework:spring-expression@7.0.6 · id `ed3baf89d160`
- 도달성: **도달성 미상**
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-770 · 탐지: trivy (합의 1)

### [보통] CVE-2026-22745 — org.springframework:spring-webmvc@7.0.6 · id `7effa40d2277`
- 도달성: **도달성 미상**
- 수정: `7.0.7, 6.2.18` 이상으로 업그레이드
- CWE-400 · 탐지: trivy (합의 1)

### [보통] CVE-2026-41841 — org.springframework:spring-webmvc@7.0.6 · id `885fd1245028`
- 도달성: **도달성 미상**
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-524 · 탐지: trivy (합의 1)

### [보통] CVE-2026-41843 — org.springframework:spring-webmvc@7.0.6 · id `9e30cb04f7fd`
- 도달성: **도달성 미상**
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-22 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 경로 조작 및 자원 삽입 · PCI-DSS 6.2.4 — injection

### [보통] CVE-2026-41844 — org.springframework:spring-webmvc@7.0.6 · id `8c57065fd8c4`
- 도달성: **도달성 미상**
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-601 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 신뢰되지 않는 URL 주소로 자동접속 연결 · PCI-DSS 6.2.4 — business logic

### [보통] CVE-2026-41846 — org.springframework:spring-webmvc@7.0.6 · id `ce30e2e3b18a`
- 도달성: **도달성 미상**
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-79 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 크로스사이트 스크립트(XSS) · PCI-DSS 6.2.4 — injection

### [보통] CVE-2026-41853 — org.springframework:spring-webmvc@7.0.6 · id `ad70fdb36295`
- 도달성: **도달성 미상**
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-444 · 탐지: trivy (합의 1)

### [보통] CVE-2026-41854 — org.springframework:spring-web@7.0.6 · id `e459cd34994a`
- 도달성: **도달성 미상**
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-918 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 서버사이드 요청 위조(SSRF) · PCI-DSS 6.2.4 — business logic

### [보통] CVE-2026-54514 — tools.jackson.core:jackson-databind@3.1.0 · id `ac5af2d66c03`
- 도달성: **도달성 미상**
- 수정: `2.21.4, 3.1.4` 이상으로 업그레이드
- CWE-918 · 탐지: trivy (합의 1)
- 컴플라이언스: KISA 서버사이드 요청 위조(SSRF) · PCI-DSS 6.2.4 — business logic

### [보통] CVE-2026-54515 — tools.jackson.core:jackson-databind@3.1.0 · id `465c1fefc9d5`
- 도달성: **도달성 미상**
- 수정: `3.1.4` 이상으로 업그레이드
- CWE-915 · 탐지: trivy (합의 1)

### [보통] CVE-2026-54516 — tools.jackson.core:jackson-databind@3.1.0 · id `0c4b6fc31c77`
- 도달성: **도달성 미상**
- 수정: `3.1.4` 이상으로 업그레이드
- CWE-915 · 탐지: trivy (합의 1)

### [보통] CVE-2026-54517 — tools.jackson.core:jackson-databind@3.1.0 · id `e3a75d74630f`
- 도달성: **도달성 미상**
- 수정: `3.1.4` 이상으로 업그레이드
- CWE-863 · 탐지: trivy (합의 1)

### [보통] CVE-2026-54518 — tools.jackson.core:jackson-databind@3.1.0 · id `3a3a45e383f7`
- 도달성: **도달성 미상**
- 수정: `3.1.4` 이상으로 업그레이드
- CWE-863 · 탐지: trivy (합의 1)

### [보통] CVE-2026-59888 — tools.jackson.core:jackson-databind@3.1.0 · id `7b932cedcb00`
- 도달성: **도달성 미상**
- 수정: `3.1.4` 이상으로 업그레이드
- CWE-915 · 탐지: trivy (합의 1)

### [보통] CVE-2026-59889 — tools.jackson.core:jackson-databind@3.1.0 · id `70e99137c88c`
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

### [일반] CVE-2026-43514 — org.apache.tomcat.embed:tomcat-embed-core@11.0.20 · id `e07b6eb0aefb`
- 도달성: **도달성 미상**
- 수정: `9.0.118, 10.1.55, 11.0.22` 이상으로 업그레이드
- CWE-208 · 탐지: trivy (합의 1)

### [일반] CVE-2026-22746 — org.springframework.security:spring-security-core@7.0.4 · id `d48dcfe93394`
- 도달성: **도달성 미상**
- 수정: `6.5.10, 7.0.5` 이상으로 업그레이드
- CWE-208 · 탐지: trivy (합의 1)

### [일반] CVE-2026-41848 — org.springframework:spring-core@7.0.6 · id `8595f12d0703`
- 도달성: **도달성 미상**
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-1333 · 탐지: trivy (합의 1)

### [일반] CVE-2026-41852 — org.springframework:spring-expression@7.0.6 · id `0e3ced74dd9f`
- 도달성: **도달성 미상**
- 수정: `7.0.8, 6.2.19` 이상으로 업그레이드
- CWE-863 · 탐지: trivy (합의 1)

### [일반] CVE-2026-22741 — org.springframework:spring-webmvc@7.0.6 · id `e06e759d9cc3`
- 도달성: **도달성 미상**
- 수정: `7.0.7, 6.2.18` 이상으로 업그레이드
- CWE-524 · 탐지: trivy (합의 1)

## 검토 후보 (낮은 신뢰)
### [보통] secscan.rules.mybatis-sqli-identifier — /private/tmp/secscan-verify/81f4f31b/repo/src/main/java/com/messagegate/mapper/lg/LgCarrierMapper.java:40 · id `97ba29be6705`
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] secscan.rules.mybatis-sqli-identifier — /private/tmp/secscan-verify/81f4f31b/repo/src/main/resources/mybatis/mapper/lg/LgCarrierMapper.xml:19 · id `316b176c59a4`
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] secscan.rules.mybatis-sqli-identifier — /private/tmp/secscan-verify/81f4f31b/repo/src/main/resources/mybatis/mapper/lg/LgCarrierMapper.xml:24 · id `dbf86e40890a`
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] secscan.rules.mybatis-sqli-identifier — /private/tmp/secscan-verify/81f4f31b/repo/src/main/resources/mybatis/mapper/oldlg/OldLgCarrierMapper.xml:36 · id `6c49e2b26010`
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] secscan.rules.mybatis-sqli-identifier — /private/tmp/secscan-verify/81f4f31b/repo/src/main/resources/mybatis/mapper/oldlg/OldLgCarrierMapper.xml:41 · id `f0684ceb66dc`
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

### [보통] secscan.rules.mybatis-sqli-identifier — /private/tmp/secscan-verify/81f4f31b/repo/src/main/resources/mybatis/mapper/oldlg/OldLgCarrierMapper.xml:60 · id `6a5e198ab0bb`
- CWE-89 · 탐지: semgrep (합의 1)
- 컴플라이언스: KISA SQL 삽입 · PCI-DSS 6.2.4 — injection

## 낮은 우선순위 — 도달 불가 (SCA)
_해당 없음._
