# 증거 동결 2026-09-06 (생성 문서 — tools/verify/evidence_readme.py)

| 디렉토리 | 스냅샷 | 프로파일 | 스캐너 status | findings | 소요(s) | 도달성 사유 | 재입력 |
|---|---|---|---|---|---|---|---|
| 1052b80d-standard | 1052b80d | standard | gitleaks(ok), semgrep(ok), trivy(ok) | 82 | 32.5 | off | 예 |
| 29bfb5ba-standard | 29bfb5ba | standard | gitleaks(ok), semgrep(ok), trivy(ok) | 85 | 42.9 | off | 예 |
| 55e58bc6-standard | 55e58bc6 | standard | gitleaks(ok), semgrep(ok), trivy(ok) | 85 | 33.1 | off | 예 |
| 5895c9f4-standard | 5895c9f4 | standard | gitleaks(ok), semgrep(ok), trivy(ok) | 85 | 36.2 | off | 예 |
| 72e49a1b-standard | 72e49a1b | standard | gitleaks(ok), semgrep(ok), trivy(ok) | 84 | 32.6 | off | 예 |
| 81f4f31b-standard | 81f4f31b | standard | gitleaks(ok), semgrep(ok), trivy(ok) | 82 | 30.9 | off | 예 |
| 8428e646-standard | 8428e646 | standard | gitleaks(ok), semgrep(ok), trivy(ok) | 87 | 31.4 | off | 예 |
| a483b3b1-deep | a483b3b1 | deep | trivy(ok), gitleaks(ok), semgrep(ok), spotbugs(ok) | 483 | 19.0 | off | 예 |
| a483b3b1-standard | a483b3b1 | standard | gitleaks(ok), semgrep(ok), trivy(ok) | 73 | 156.9 | ok |  |
| d4a1ded0-standard | d4a1ded0 | standard | gitleaks(ok), semgrep(ok), trivy(ok) | 86 | 34.1 | off | 예 |

- 도구 버전: 각 `meta.json` `tool_versions`. 격리: 스냅샷별 scratch·GRADLE_USER_HOME·크리덴셜 제거·secret 검증 never(`meta.isolated`).
