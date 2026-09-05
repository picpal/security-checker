package com.example;

/** (a) 저엔트로피 도메인 비밀번호 — 커스텀 룰 hardcoded-credential 의 양성 케이스. 가짜값.
 * 변수명은 PASSWORD 로 시작해야 한다 — 룰의 metavariable-regex 는 접두사 매칭이라
 * DB_PASSWORD 처럼 키워드가 앞에 오지 않는 이름은 실도구 실측상 매칭되지 않는다.
 */
public class Config {
    static final String PASSWORD = "Passw0rd!2024";
    static final String DB_USER = "app";
}
