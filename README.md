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

# 3) 보고서 워크북(사람·LLM 겸용) 단독 실행 / 결과 검증
secscan report --findings out/findings.json --bom <bom.cdx.json> [--interpretations interpretations.json] --out out   # 사람·LLM 겸용 워크북 report.xlsx
secscan report --check-result result.json --rescan out2/findings.json   # LLM 결과 반환 검증(불일치 exit 2)
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
- `--no-bom-cache` : BOM(의존성 그래프) 캐시를 무시하고 새로 해석. BOM 캐시는 **의존성 매니페스트
  내용 해시**로 잡히므로 버전을 올리면 자동으로 다시 만들어진다. 매니페스트가 그대로여도 결과가
  달라지는 선언 — 동적 버전(`2.+`·`latest.release`·`[1.0,2.0)`)·SNAPSHOT·원격 parent pom — 은
  스캔 시작 때 감지해 **자동으로 캐시를 우회**하고 그 사실을 출력·`findings.json`(`meta.bom_cache`)에 남긴다.
  판정은 fail-closed — 로컬에서 풀리는 표현(`def v = "1.2.3"`, 부모 pom `<properties>`, 버전 카탈로그)은
  풀어서 고정으로 보고, **끝내 못 푼 표현은 동적으로 간주**한다. 캐시 키에는 빌드가 실제로 읽는
  대상 밖 파일(maven 로컬 parent 체인, gradle 빌드 루트 하위 전체)도 포함된다
- `--bom-max-age <시간>` : BOM 캐시 수명(기본 24시간, `0`=매 스캔 재생성, 음수=무제한). 정적 분석이
  **원리적으로** 못 보는 변화(실행 시점 주입값·플러그인이 주입하는 의존성·원격 아티팩트 재배포 등,
  전체 목록은 `PROGRESS.md`)의 하한선이다 — 매니페스트 해시가 1차 방어, 이건 마지막 안전망

## 슬래시 커맨드 (Claude Code)

이 저장소를 clone 한 뒤 그 디렉터리에서 Claude Code 를 실행하면 바로 쓸 수 있다.

| 커맨드 | 하는 일 |
|---|---|
| `/secscan-setup` | 스캐너·런타임 설치 상태를 `doctor` 로 점검하고, 빠진 것을 하나씩 승인받아 설치 |
| `/security-check <경로 \| git URL>` | 스택 감지 → 프로파일 결정 → 스캔 → 보고서 해석 → 억제 후보 제안 |
| `/clear-clone [슬러그 \| all]` | git URL 로 받아 둔 클론 정리 (보고서는 남김) |

처음이라면 `/secscan-setup` 부터 — venv 생성까지 여기서 안내한다.

### git URL 점검

`/security-check https://github.com/owner/repo.git` 처럼 원격 저장소를 바로 넘길 수 있다.
내부적으로 `secscan fetch` 가 `--depth 1` 로 `.secscan/repos/<host>__<owner>__<repo>/` 에 받는다.

- `.secscan/` 은 `.gitignore` 되어 있고 `exclude.py` 기본 제외 목록에도 있어, secscan 자신을
  점검해도 클론한 코드가 findings 에 섞이지 않는다
- 이미 받아 둔 클론이 있으면 **지우고 다시 받는다** — 보고서가 항상 현재 기본 브랜치 기준
- 보고서는 `out/<슬러그>/` 로 분리돼 여러 프로젝트 결과가 서로 덮어쓰지 않는다

클론/삭제는 결정적 코드(`secscan/fetch.py`)가 처리한다 — 삭제는 `.secscan/repos/` 밖으로
나갈 수 없고 심볼릭 링크 탈출도 막는다. Claude 가 `rm -rf` 경로를 계산하지 않는다(원칙 2).

```bash
secscan fetch <git URL>          # 얕은 클론 + 커밋 SHA 출력
secscan clean --list             # 클론 목록 + 용량
secscan clean [--slug <슬러그>]   # 정리 (미지정 시 전체)
```

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
