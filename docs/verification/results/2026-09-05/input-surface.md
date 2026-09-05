# 입력면 교차 — jar 빌드/스캔 성공

## 인벤토리 차이 (BOM=a, jar=b)
- BOM 에만: 77 — biz.aQute.bnd:biz.aQute.bnd.annotation, com.fasterxml.jackson:jackson-bom, com.jayway.jsonpath:json-path, com.squareup.okhttp3:mockwebserver, com.squareup.okhttp3:okhttp, com.squareup.okio:okio, com.squareup.okio:okio-jvm, com.vaadin.external.google:android-json, io.github.classgraph:classgraph, io.github.openfeign.querydsl:querydsl-apt, io.github.openfeign.querydsl:querydsl-codegen, io.github.openfeign.querydsl:querydsl-codegen-utils, junit:junit, net.bytebuddy:byte-buddy-agent, net.minidev:accessors-smart, net.minidev:json-smart, org.apiguardian:apiguardian-api, org.assertj:assertj-core, org.awaitility:awaitility, org.eclipse.jdt:ecj, org.hamcrest:hamcrest, org.hamcrest:hamcrest-core, org.hibernate.orm:hibernate-core, org.jacoco:org.jacoco.agent, org.jacoco:org.jacoco.ant, org.jacoco:org.jacoco.core, org.jacoco:org.jacoco.report, org.jetbrains.kotlin:kotlin-stdlib, org.jetbrains.kotlin:kotlin-stdlib-common, org.jetbrains.kotlin:kotlin-stdlib-jdk7
- jar 에만: 9 — ognl:ognl, org.eclipse.angus:angus-core, org.eclipse.angus:imap, org.eclipse.angus:logging-mailhandler, org.eclipse.angus:pop3, org.eclipse.angus:smtp, org.hibernate:hibernate-core, org.javassist:javassist, org.springframework.boot:spring-boot-jarmode-tools
- 버전 차이:

## 정답지 설치버전 대조
| 패키지 | 보안팀 | BOM | jar |
|---|---|---|---|
| com.fasterxml.jackson.core:jackson-core | 2.21.2 | 2.21.2 | 2.21.2 |
| tools.jackson.core:jackson-core | 3.1.2 | 3.1.2 | 3.1.2 |
| com.microsoft.sqlserver:mssql-jdbc | 13.2.1.jre11 | 13.2.1.jre11 | 13.2.1.jre11 |
| com.fasterxml.jackson.core:jackson-databind | 2.21.2 | 2.21.2 | 2.21.2 |
| tools.jackson.core:jackson-databind | 3.1.2 | 3.1.2 | 3.1.2 |
| io.micrometer:micrometer-core | 1.16.5 | 1.16.5 | 1.16.5 |
| org.springframework.data:spring-data-commons | 4.0.5 | 4.0.5 | 4.0.5 |
| org.springframework:spring-webmvc | 7.0.7 | 7.0.7 | 7.0.7 |
| org.springframework:spring-expression | 7.0.7 | 7.0.7 | 7.0.7 |
| org.springframework:spring-web | 7.0.7 | 7.0.7 | 7.0.7 |
| org.springframework.security:spring-security-web | 7.0.5 | 7.0.5 | 7.0.5 |
| org.apache.logging.log4j:log4j-api | 2.25.4 | 2.25.4 | 2.25.4 |
| org.springframework.boot:spring-boot-autoconfigure | 4.0.6 | 4.0.6 | 4.0.6 |
| org.springframework:spring-core | 7.0.7 | 7.0.7 | 7.0.7 |
| ch.qos.logback:logback-core | 1.5.32 | 1.5.32 | 1.5.32 |
| org.apache.tomcat.embed:tomcat-embed-core | 11.0.22 | 11.0.22 | 11.0.22 |