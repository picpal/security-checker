package com.example;

/** (a) 저엔트로피 도메인 비밀번호 — 커스텀 룰 hardcoded-credential 의 관측 사례. 가짜값.
 * PASSWORD: 양성(탐지) — 룰의 metavariable-regex 는 식별자 접두사 매칭이라 키워드가
 * 변수명 앞에 와야 탐지된다.
 * DB_PASSWORD: 관측된 미탐 — 같은 값이라도 키워드가 접두사가 아니면(DB_ 뒤에 옴)
 * 실도구 실측상 매칭되지 않는다. 픽스처를 룰에 맞추지 않고 갭을 그대로 고정한다
 * (룰 개선은 백로그 후보, 이 픽스처의 목적이 아님).
 */
public class Config {
    static final String PASSWORD = "Passw0rd!2024";
    static final String DB_PASSWORD = "Passw0rd!2024";
    static final String DB_USER = "app";
}
