# 프로파일 계약 (spec §8 vs 구현 vs 실제)

| 프로파일 | spec §8 | 구현 | 누락 | 초과 | 실제 status |
|---|---|---|---|---|---|
| quick | gitleaks, trivy | gitleaks, trivy | - | - | gitleaks=ok, trivy=ok |
| accurate-sca | osv-scanner, trivy | trivy | osv-scanner | - | trivy=ok |
| standard | gitleaks, osv-scanner, semgrep, trivy | gitleaks, semgrep, trivy | osv-scanner | - | gitleaks=ok, semgrep=ok, trivy=ok |
| deep | gitleaks, osv-scanner, semgrep, spotbugs, trivy | gitleaks, semgrep, spotbugs, trivy | osv-scanner | - | gitleaks=ok, semgrep=ok, spotbugs=ok, trivy=ok |
