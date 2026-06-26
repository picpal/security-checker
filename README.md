# secscan — JVM 보안 점검 하이브리드 CLI

JVM(Java/Kotlin) 프로젝트용 보안 점검 도구. 결정적 오케스트레이터가 오픈소스 스캐너를
병렬 실행·정규화하고, **도달성(reachability) 분석으로 노이즈를 걷어낸 뒤**, Claude가
증거를 해석해 보고서를 낸다.

- **설계(spec)**: [`docs/superpowers/specs/2026-06-26-jvm-security-scanner-design.md`](docs/superpowers/specs/2026-06-26-jvm-security-scanner-design.md)
- **실측 리포트**: [`docs/measurements/2026-06-27-m1-reachability-fp.md`](docs/measurements/2026-06-27-m1-reachability-fp.md)
- **진행/상태**: [`PROGRESS.md`](PROGRESS.md)

## 핵심 가치
**정확도 우선.** "FP가 많으면 아무도 안 쓴다"가 1번 설계 제약. 도달성 분석으로 실제
악용 가능한 것만 우선순위에 올린다(픽스처 실측: 조치대상 **9→1, 노이즈 89% 감소**).

## 구성
| 영역 | 도구 |
|---|---|
| SCA(의존성) | Trivy + osv-scanner (합의 dedup) |
| 도달성 | OWASP dep-scan + atom (usage 슬라이스) |
| Secret | Gitleaks (+ opt-in TruffleHog 검증) |
| SAST | Semgrep CE (deep: SpotBugs + FindSecBugs 바이트코드) |

## 설치 / 개발
```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest                  # 160 tests
.venv/bin/secscan doctor          # 스캐너/런타임/메모리 점검
```
스캐너: `brew install trivy osv-scanner gitleaks semgrep trufflehog spotbugs` ·
`pipx install owasp-depscan` · `npm i -g @appthreat/atom @cyclonedx/cdxgen` ·
FindSecBugs 플러그인 jar → `~/.local/share/secscan/findsecbugs-plugin.jar`. (누락 시 `doctor`가 안내)

## 사용
```bash
# 1) 스택 감지 + 프로파일 추천
secscan detect --target <프로젝트> --intent full

# 2) 점검 실행 → out/report.md + out/findings.sarif
secscan scan --target <프로젝트> --profile standard --out out
```

### 프로파일
| 프로파일 | 구성 | 용도 |
|---|---|---|
| `quick` | Trivy + Gitleaks (도달성 X) | 초고속 확인 |
| `accurate-sca` | Trivy+osv + 도달성 | 정확한 의존성/패치 체크 |
| `standard` | Semgrep + SCA+도달성 + Gitleaks | 기본 풀스캔 |
| `deep` | standard + SpotBugs/FindSecBugs(바이트코드) | 정밀(빌드 필요, experimental) |

### 주요 플래그
- `--verify-secrets` : TruffleHog 라이브 검증(자격증명을 제3자로 전송, opt-in) · `--network-off` : 검증 강제 차단
- `--suppressions <file>` / `--baseline <file>` / `--write-baseline <file>` : 억제(사람 확정) · baseline
- `--allow-large` : 대형 코드베이스에서도 도달성 강제 · `--no-reachability` : 도달성 생략

## 하이브리드 동작 (Claude 레이어)
1. Claude가 자연어 요청("이 프로젝트 점검해줘")을 **intent**로 해석
2. `secscan detect`로 스택/빌드도구 감지 → 프로파일 결정
3. `secscan scan`이 결정적으로 스캐너 병렬 실행 → 정규화 → 도달성 → typed findings → SARIF/MD
4. Claude가 보고서·증거를 해석하고 억제 **후보를 제안**(자동 억제 없음 — 사람이 확정)

## 설계 원칙 (위반 금지)
1. 정확도 우선 2. 결정적/LLM 경계(Claude는 증거 해석자) 3. 내부 typed model, SARIF는 출력 전용
4. 자동 억제 금지 5. 부분 실패는 정상(격리·보고) 6. 어댑터 추상화(새 스캐너 = 어댑터 1개)

## 범위 밖(백로그)
IaC/컨테이너, DAST, CI 게이트, 주기 점검, Dependency-Track, Opengrep/CodeQL(cross-function taint).
