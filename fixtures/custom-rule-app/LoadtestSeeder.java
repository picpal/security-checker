package com.example;

// 파일명에 loadtest 포함 → is_test_path 강등 대상(actionable 아닌 review).
// message-gate LoadtestSeederConfig 의 CWE-259 갭(src/main 의 loadtest 코드) 재현.
public class LoadtestSeeder {
    private static final String PASSWORD = "loadtest-pw";
}
