package com.example;

public class Creds {
    // 양성: 하드코딩 자격증명 (main 경로 → actionable)
    private static final String PASSWORD = "loadtest-pw";
    private String apiKey = "sk-abc123def456";

    // 음성: 환경변수 주입 (우변이 리터럴이 아님 → 미탐이어야)
    private String dbPassword = System.getenv("DB_PASSWORD");

    // 음성: 빈 문자열 (자격증명 아님)
    private String emptyToken = "";
}
