# 입력면 교차 — jar 빌드/스캔 성공

## 인벤토리 차이 (BOM=a, jar=b)
- BOM 에만: 195 — biz.aQute.bnd:biz.aQute.bnd.annotation, ch.qos.logback:logback-classic, ch.qos.logback:logback-core, com.fasterxml.jackson.core:jackson-annotations, com.fasterxml.jackson.core:jackson-core, com.fasterxml.jackson.core:jackson-databind, com.fasterxml.jackson.datatype:jackson-datatype-jsr310, com.fasterxml.jackson:jackson-bom, com.fasterxml:classmate, com.github.ben-manes.caffeine:caffeine, com.google.errorprone:error_prone_annotations, com.jayway.jsonpath:json-path, com.microsoft.sqlserver:mssql-jdbc, com.oracle.database.jdbc:ojdbc11, com.squareup.okhttp3:mockwebserver, com.squareup.okhttp3:okhttp, com.squareup.okio:okio, com.squareup.okio:okio-jvm, com.sun.istack:istack-commons-runtime, com.vaadin.external.google:android-json, com.zaxxer:HikariCP, commons-codec:commons-codec, commons-logging:commons-logging, io.github.classgraph:classgraph, io.github.openfeign.querydsl:querydsl-apt, io.github.openfeign.querydsl:querydsl-codegen, io.github.openfeign.querydsl:querydsl-codegen-utils, io.github.openfeign.querydsl:querydsl-core, io.github.openfeign.querydsl:querydsl-jpa, io.github.resilience4j:resilience4j-bulkhead
- jar 에만: 0 — 
- 버전 차이:

## 정답지 설치버전 대조
| 패키지 | 보안팀 | BOM | jar |
|---|---|---|---|
| com.fasterxml.jackson.core:jackson-core | 2.21.2 | 2.21.2 | - |
| tools.jackson.core:jackson-core | 3.1.2 | 3.1.2 | - |
| com.microsoft.sqlserver:mssql-jdbc | 13.2.1.jre11 | 13.2.1.jre11 | - |
| com.fasterxml.jackson.core:jackson-databind | 2.21.2 | 2.21.2 | - |
| tools.jackson.core:jackson-databind | 3.1.2 | 3.1.2 | - |
| io.micrometer:micrometer-core | 1.16.5 | 1.16.5 | - |
| org.springframework.data:spring-data-commons | 4.0.5 | 4.0.5 | - |
| org.springframework:spring-webmvc | 7.0.7 | 7.0.7 | - |
| org.springframework:spring-expression | 7.0.7 | 7.0.7 | - |
| org.springframework:spring-web | 7.0.7 | 7.0.7 | - |
| org.springframework.security:spring-security-web | 7.0.5 | 7.0.5 | - |
| org.apache.logging.log4j:log4j-api | 2.25.4 | 2.25.4 | - |
| org.springframework.boot:spring-boot-autoconfigure | 4.0.6 | 4.0.6 | - |
| org.springframework:spring-core | 7.0.7 | 7.0.7 | - |
| ch.qos.logback:logback-core | 1.5.32 | 1.5.32 | - |
| org.apache.tomcat.embed:tomcat-embed-core | 11.0.22 | 11.0.22 | - |