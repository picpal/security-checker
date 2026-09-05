# 검증 캠페인(V) 플랜 1 — 측정 (V0~V3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** message-gate 정답지 2종(GT-A 소스 점검, GT-B 보안팀 SCA 46건)에 대해 secscan 현행 바이너리의 탐지·도달성 결과를 재현 가능한 증거와 수치로 남기고, 갭을 백로그 후보로 뽑는다.

**Architecture:** 정답지는 JSON 매니페스트(`docs/verification/ground-truth/`), 대조·분류는 순수 함수(`secscan/measure.py`), 파이프라인 단계별 건수는 `run_scan` 에 주입하는 `TraceSink`(기본 None, 동작 무변경)로 기록한다. 실스캔은 패키지 밖 개발 도구 `tools/verify/` 가 격리된 스냅샷(clone --local, 별도 GRADLE_USER_HOME, 크리덴셜 제거, `--network-off`)에서 돌리고 증거를 `docs/verification/evidence/` 에 동결한다. 측정 결과는 markdown 표로 렌더한다.

**Tech Stack:** Python 3.11+ stdlib only (core deps 0), pytest, 실스캔 시 trivy/cdxgen/semgrep/gitleaks/depscan(설치됨), git, gradle wrapper(message-gate 동봉).

**Spec:** `docs/superpowers/specs/2026-09-04-verification-campaign-design.md` (§2~§6, §9 V0~V3). 플랜 2(V4~V7: 모델 확장·판정 단계 H·xlsx·변이 픽스처·최종 문서)는 이 플랜의 증거 동결(Task 6) 완료 후 별도 작성한다(spec §4.4 "V1 전 V4 시작 금지").

## Global Constraints

- Python `>=3.11`, `dependencies = []` 유지. dev 의존성은 `pytest>=8` 뿐. 새 런타임 의존성 금지.
- 결정적 계층(정규화·병합·대조·추적)은 순수 함수 + 골든 테스트. 실스캔은 테스트가 아니라 **문서화된 명령**이다.
- 자동 억제 금지. 이 플랜은 억제를 생성하지 않는다.
- 스캔 대상 message-gate 경로: `/Users/picpal/Desktop/workspace/message-gate` (하네스는 `--repo` 인자로 받는다, 하드코딩 금지).
- 격리 실행: 스냅샷마다 새 디렉토리(`<scratch>/<sha>/repo`), `GRADLE_USER_HOME=<scratch>/<sha>/gradle-home`, 환경변수 중 `TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API_KEY|AWS_|GITHUB_|GH_` 매칭 키 제거, secret 검증은 항상 `never`(`--network-off`). "read-only" 라는 표현 금지.
- 증거에 비밀값 저장 금지: gitleaks 원시 출력은 `Secret`·`Match` 필드를 `<redacted>` 로 치환한 뒤 저장.
- 스냅샷 SHA: GT-B `a483b3b1` / GT-A 취약 `29bfb5ba`(259·489) `d4a1ded0`(760) `1052b80d`(#305·497·676) / GT-A 수정 `72e49a1b`(259) `55e58bc6`(760) `8428e646`(#305) `5895c9f4`(489) `81f4f31b`(497·676).
- 게이트 수치는 spec §5 그대로: SCA CVE 단위 recall ≥ 44/46, HIGH/Important 미탐 ≤ 1, mssql 3단계 전부 ✓, 초과분 미분류 0, false-unreachable = 0, GT-A 범주 내 출현·소멸 100%. **게이트 미통과 = 측정 문서에 기록 + 백로그 P1**, 캠페인은 계속 진행.
- 커밋: 작게 자주, 메시지 마지막 줄 `다음: <할 일>`. 한국어 주석·문서.
- 테스트 실행: `.venv/bin/pytest` (현재 234 green). 새 태스크는 기존 green 을 깨지 않는다.
- **측정 사실성(spec §4.5)**: 실행자(서브에이전트)는 수치를 손으로 쓰지 않고, 초과분 분류를 override 하지 않고, 게이트 ✓/✗ 를 임의로 정하지 않는다. 결과 문서의 모든 수치는 `facts.json` 의 값을 `<!-- fact:<id> -->` 마커와 함께 인용한다. 판단이 필요한 항목은 `needs_human` 으로만 보고한다.

---

## File Structure

| 파일 | 책임 |
|---|---|
| `docs/verification/ground-truth/gt-b-sca.json` | GT-B 매니페스트(47 항목 = present 46 + absent 1, 패키지 분리 시 항목 수 증가) |
| `docs/verification/ground-truth/gt-a-source.json` | GT-A 매니페스트(스냅샷·수정 커밋·파일·기대 룰·기대 tier·분류) |
| `docs/verification/ground-truth/golden/security-team-schema.json` | 보안팀 xlsx 시트·헤더 골든(사진 기준 재구성) |
| `secscan/measure.py` (수정) | `GtEntry`/`GtManifest`/`load_gt_manifest`/`match_ground_truth`/`classify_extras` — 순수 |
| `secscan/scan.py` (수정) | `TraceSink` + `run_scan(..., trace=None)` |
| `secscan/normalize/__init__.py` (수정) | `normalize_each(raws) -> dict[tool, list[Finding]]` (to_findings 가 사용) |
| `secscan/output/json_io.py` (신규) | `to_json(findings)` / `from_json(text)` — typed Finding lossless 직렬화 |
| `tools/__init__.py`, `tools/verify/__init__.py` | 패키지 마커 |
| `tools/verify/snapshot.py` | `prepare_snapshot`, `isolated_env` |
| `tools/verify/evidence.py` | `redact_gitleaks`, `tool_versions`, `write_evidence` |
| `tools/verify/run_snapshot.py` | CLI: 스냅샷 1개 실스캔 + 증거 동결 |
| `tools/verify/report.py` | attrition·대조·사람 판정 비교표 렌더 + CLI |
| `tools/verify/profile_contract.py` | 원 spec §8 vs `profiles.PROFILES` 드리프트 + 실제 status |
| `tools/verify/known_fp.py` | mssql 3단계 검사 |
| `tools/verify/jar_surface.py` | jar 입력면 실험(빌드 → trivy fs → 인벤토리 비교) |
| `tools/verify/differential.py` | GT-A 취약/수정 커밋 differential |
| `fixtures/reach-app/` + `tests/golden/atom-usages-reach-app.json` | 도달성 쌍 픽스처(취약 API / 안전 API / 프레임워크 활성화) |
| `tests/test_measure.py`, `tests/test_scan.py`, `tests/test_json_io.py`, `tests/test_verify_tools.py`, `tests/test_reach_app.py` | 테스트 |
| `docs/measurements/2026-09-XX-message-gate-verification.md` | 측정 문서(플랜 1 은 중간본, 플랜 2 V7 에서 최종) |

---

### Task 1: GT 매니페스트 3종 + 로더/검증기

**Files:**
- Create: `docs/verification/ground-truth/gt-b-sca.json`
- Create: `docs/verification/ground-truth/gt-a-source.json`
- Create: `docs/verification/ground-truth/golden/security-team-schema.json`
- Modify: `secscan/measure.py` (파일 끝에 추가)
- Test: `tests/test_measure.py` (파일 끝에 추가)

**Interfaces:**
- Produces: `GtEntry`(frozen dataclass), `GtManifest`, `load_gt_manifest(path) -> GtManifest`, `GtManifest.present()`, `.absent()`, `.packages()`, `.cves()`.

- [ ] **Step 1: GT-B 매니페스트 작성**

`docs/verification/ground-truth/gt-b-sca.json`. 출처: message-gate `docs/security/05_취약점조치내역_MessageGate.xlsx` 시트 `조치결과_35건`·`추가조치_12건`, `03_취약점조치결과_MessageGate.md` §3·§5. 보안팀 행이 두 패키지를 한 셀에 담은 jackson 행은 항목 2개로 분리(`row` 동일). `human_verdict` 는 03 문서에 분석이 있는 행만 채운다.

```json
{
  "@context": "secscan-ground-truth/v1",
  "kind": "sca",
  "snapshot": "a483b3b1",
  "scan_date": "2026-08-31",
  "source": "message-gate docs/security/05_취약점조치내역_MessageGate.xlsx (보안팀 Deduped_CVEs 35행 전사) + 03_취약점조치결과_MessageGate.md §3·§5 (개발자 추가 12건·도달성 분석)",
  "note": "보안팀 원본 xlsx·trivy JSON 은 확보 불가. 설치 버전은 보안팀 표기 그대로(mssql 은 실제 해석 버전 13.2.1.jre11 로 기재).",
  "entries": [
    {"row": 1, "advisory": "GHSA-r7wm-3cxj-wff9", "package": "com.fasterxml.jackson.core:jackson-core", "installed": "2.21.2", "fixed": ["2.18.8", "2.21.4"], "severity_team": "HIGH", "cvss_max": 8.7, "cvss_source": "ghsa", "origin": "team", "expected": "present", "human_verdict": "unreachable", "reason_class": "api-unused", "reason": "async 논블로킹 파서(NonBlockingUtf8JsonParserBase) 미사용, 서블릿 블로킹 스택"},
    {"row": 1, "advisory": "GHSA-r7wm-3cxj-wff9", "package": "tools.jackson.core:jackson-core", "installed": "3.1.2", "fixed": ["3.1.4"], "severity_team": "HIGH", "cvss_max": 8.7, "cvss_source": "ghsa", "origin": "team", "expected": "present", "human_verdict": "unreachable", "reason_class": "api-unused", "reason": "async 논블로킹 파서 미사용"},
    {"row": 2, "advisory": "CVE-2025-59250", "package": "com.microsoft.sqlserver:mssql-jdbc", "installed": "13.2.1.jre11", "fixed": ["13.2.1.jre11"], "severity_team": "HIGH", "cvss_max": 8.1, "cvss_source": "nvd", "origin": "team", "expected": "absent", "note": "known-FP: 스캐너가 설치 버전을 13.2.1 로 표기(bare 13.2.1 은 Maven Central 에 없음). 실제 13.2.1.jre11 은 수정 목록에 포함."},
    {"row": 3, "advisory": "CVE-2026-54512", "package": "com.fasterxml.jackson.core:jackson-databind", "installed": "2.21.2", "fixed": ["2.18.8", "2.21.4"], "severity_team": "HIGH", "cvss_max": 8.1, "cvss_source": "redhat", "origin": "team", "expected": "present", "human_verdict": "unreachable", "reason_class": "config-gated", "reason": "@JsonTypeInfo/@JsonSubTypes/activateDefaultTyping/PolymorphicTypeValidator src 전체 0건"},
    {"row": 3, "advisory": "CVE-2026-54512", "package": "tools.jackson.core:jackson-databind", "installed": "3.1.2", "fixed": ["3.1.4"], "severity_team": "HIGH", "cvss_max": 8.1, "cvss_source": "redhat", "origin": "team", "expected": "present", "human_verdict": "unreachable", "reason_class": "config-gated", "reason": "polymorphic typing 미활성"},
    {"row": 4, "advisory": "CVE-2026-54513", "package": "com.fasterxml.jackson.core:jackson-databind", "installed": "2.21.2", "fixed": ["2.18.8", "2.21.4"], "severity_team": "HIGH", "cvss_max": 8.1, "cvss_source": "redhat", "origin": "team", "expected": "present", "human_verdict": "unreachable", "reason_class": "config-gated", "reason": "polymorphic typing 미활성"},
    {"row": 4, "advisory": "CVE-2026-54513", "package": "tools.jackson.core:jackson-databind", "installed": "3.1.2", "fixed": ["3.1.4"], "severity_team": "HIGH", "cvss_max": 8.1, "cvss_source": "redhat", "origin": "team", "expected": "present", "human_verdict": "unreachable", "reason_class": "config-gated", "reason": "polymorphic typing 미활성"},
    {"row": 5, "advisory": "CVE-2026-40983", "package": "io.micrometer:micrometer-core", "installed": "1.16.5", "fixed": ["1.16.6", "1.15.12"], "severity_team": "HIGH", "cvss_max": 7.5, "cvss_source": "redhat", "origin": "team", "expected": "present"},
    {"row": 6, "advisory": "CVE-2026-40984", "package": "io.micrometer:micrometer-core", "installed": "1.16.5", "fixed": ["1.16.6", "1.15.12"], "severity_team": "HIGH", "cvss_max": 7.5, "cvss_source": "redhat", "origin": "team", "expected": "present"},
    {"row": 7, "advisory": "CVE-2026-41695", "package": "org.springframework.data:spring-data-commons", "installed": "4.0.5", "fixed": ["4.0.6", "3.5.12"], "severity_team": "HIGH", "cvss_max": 7.5, "cvss_source": "redhat", "origin": "team", "expected": "present"},
    {"row": 8, "advisory": "CVE-2026-41716", "package": "org.springframework.data:spring-data-commons", "installed": "4.0.5", "fixed": ["4.0.6", "3.5.12"], "severity_team": "HIGH", "cvss_max": 7.5, "cvss_source": "redhat", "origin": "team", "expected": "present"},
    {"row": 9, "advisory": "CVE-2026-41845", "package": "org.springframework:spring-webmvc", "installed": "7.0.7", "fixed": ["7.0.8", "6.2.19"], "severity_team": "HIGH", "cvss_max": 6.1, "cvss_source": "nvd", "origin": "team", "expected": "present"},
    {"row": 10, "advisory": "CVE-2026-41842", "package": "org.springframework:spring-webmvc", "installed": "7.0.7", "fixed": ["7.0.8", "6.2.19"], "severity_team": "HIGH", "cvss_max": 5.9, "cvss_source": "redhat", "origin": "team", "expected": "present"},
    {"row": 11, "advisory": "CVE-2026-41850", "package": "org.springframework:spring-expression", "installed": "7.0.7", "fixed": ["7.0.8", "6.2.19"], "severity_team": "HIGH", "cvss_max": 5.9, "cvss_source": "redhat", "origin": "team", "expected": "present"},
    {"row": 12, "advisory": "CVE-2026-41851", "package": "org.springframework:spring-expression", "installed": "7.0.7", "fixed": ["7.0.8", "6.2.19"], "severity_team": "MEDIUM", "cvss_max": 7.5, "cvss_source": "nvd", "origin": "team", "expected": "present"},
    {"row": 13, "advisory": "CVE-2026-41854", "package": "org.springframework:spring-web", "installed": "7.0.7", "fixed": ["7.0.8", "6.2.19"], "severity_team": "MEDIUM", "cvss_max": 6.5, "cvss_source": "nvd", "origin": "team", "expected": "present"},
    {"row": 14, "advisory": "CVE-2026-54518", "package": "com.fasterxml.jackson.core:jackson-databind", "installed": "2.21.2", "fixed": ["2.21.4"], "severity_team": "MEDIUM", "cvss_max": 6.5, "cvss_source": "redhat", "origin": "team", "expected": "present", "human_verdict": "unreachable", "reason_class": "api-unused", "reason": "@JsonView·@JsonUnwrapped·@JsonAlias·@JsonIgnoreProperties·PropertyNamingStrategy 전부 0건 (도달 경로 미확인)"},
    {"row": 14, "advisory": "CVE-2026-54518", "package": "tools.jackson.core:jackson-databind", "installed": "3.1.2", "fixed": ["3.1.4"], "severity_team": "MEDIUM", "cvss_max": 6.5, "cvss_source": "redhat", "origin": "team", "expected": "present", "human_verdict": "unreachable", "reason_class": "api-unused", "reason": "view/alias 계열 어노테이션 0건"},
    {"row": 15, "advisory": "CVE-2026-59888", "package": "com.fasterxml.jackson.core:jackson-databind", "installed": "2.21.2", "fixed": ["2.18.8", "2.21.4"], "severity_team": "MEDIUM", "cvss_max": 6.5, "cvss_source": "redhat", "origin": "team", "expected": "present", "human_verdict": "unreachable", "reason_class": "api-unused", "reason": "HTTP 직렬화 record 18개/15파일 전부 @JsonIgnore 0건"},
    {"row": 15, "advisory": "CVE-2026-59888", "package": "tools.jackson.core:jackson-databind", "installed": "3.1.2", "fixed": ["3.1.4"], "severity_team": "MEDIUM", "cvss_max": 6.5, "cvss_source": "redhat", "origin": "team", "expected": "present", "human_verdict": "unreachable", "reason_class": "api-unused", "reason": "record 에 @JsonIgnore 0건"},
    {"row": 16, "advisory": "CVE-2026-59889", "package": "com.fasterxml.jackson.core:jackson-databind", "installed": "2.21.2", "fixed": ["2.21.5", "2.18.9"], "severity_team": "MEDIUM", "cvss_max": 6.5, "cvss_source": "ghsa", "origin": "team", "expected": "present", "human_verdict": "unreachable", "reason_class": "api-unused", "reason": "@JsonView·@JsonUnwrapped 0건 (도달 경로 미확인)"},
    {"row": 16, "advisory": "CVE-2026-59889", "package": "tools.jackson.core:jackson-databind", "installed": "3.1.2", "fixed": ["3.1.5"], "severity_team": "MEDIUM", "cvss_max": 6.5, "cvss_source": "ghsa", "origin": "team", "expected": "present", "human_verdict": "unreachable", "reason_class": "api-unused", "reason": "@JsonView·@JsonUnwrapped 0건"},
    {"row": 17, "advisory": "GHSA-mhm7-754m-9p8w", "package": "com.fasterxml.jackson.core:jackson-databind", "installed": "2.21.2", "fixed": ["2.18.9", "2.21.5"], "severity_team": "MEDIUM", "cvss_max": 6.5, "cvss_source": "ghsa", "origin": "team", "expected": "present", "human_verdict": "unreachable", "reason_class": "api-unused", "reason": "@JsonView·@JsonTypeInfo(EXTERNAL_PROPERTY) 0건"},
    {"row": 18, "advisory": "CVE-2026-41706", "package": "org.springframework.security:spring-security-web", "installed": "7.0.5", "fixed": ["7.0.6", "6.5.11"], "severity_team": "MEDIUM", "cvss_max": 6.1, "cvss_source": "ghsa", "origin": "team", "expected": "present"},
    {"row": 19, "advisory": "CVE-2026-41844", "package": "org.springframework:spring-webmvc", "installed": "7.0.7", "fixed": ["7.0.8", "6.2.19"], "severity_team": "MEDIUM", "cvss_max": 6.1, "cvss_source": "nvd", "origin": "team", "expected": "present"},
    {"row": 20, "advisory": "CVE-2026-41846", "package": "org.springframework:spring-webmvc", "installed": "7.0.7", "fixed": ["7.0.8", "6.2.19"], "severity_team": "MEDIUM", "cvss_max": 6.1, "cvss_source": "nvd", "origin": "team", "expected": "present"},
    {"row": 21, "advisory": "CVE-2026-41711", "package": "org.springframework.data:spring-data-commons", "installed": "4.0.5", "fixed": ["4.0.6", "3.5.12"], "severity_team": "MEDIUM", "cvss_max": 5.9, "cvss_source": "redhat", "origin": "team", "expected": "present"},
    {"row": 22, "advisory": "CVE-2026-41721", "package": "org.springframework.data:spring-data-commons", "installed": "4.0.5", "fixed": ["4.0.6", "3.5.12"], "severity_team": "MEDIUM", "cvss_max": 5.9, "cvss_source": "redhat", "origin": "team", "expected": "present"},
    {"row": 23, "advisory": "CVE-2026-41841", "package": "org.springframework:spring-webmvc", "installed": "7.0.7", "fixed": ["7.0.8", "6.2.19"], "severity_team": "MEDIUM", "cvss_max": 5.9, "cvss_source": "ghsa", "origin": "team", "expected": "present"},
    {"row": 24, "advisory": "CVE-2026-41843", "package": "org.springframework:spring-webmvc", "installed": "7.0.7", "fixed": ["7.0.8", "6.2.19"], "severity_team": "MEDIUM", "cvss_max": 5.9, "cvss_source": "redhat", "origin": "team", "expected": "present"},
    {"row": 25, "advisory": "CVE-2026-49844", "package": "org.apache.logging.log4j:log4j-api", "installed": "2.25.4", "fixed": ["2.25.5", "2.26.1"], "severity_team": "MEDIUM", "cvss_max": 5.9, "cvss_source": "nvd", "origin": "team", "expected": "present", "human_verdict": "unreachable", "reason_class": "impl-absent", "reason": "log4j-core 부재(로깅 구현체 logback), 브리지 log4j-to-slf4j 는 JSON 포맷터를 타지 않음"},
    {"row": 26, "advisory": "CVE-2026-41001", "package": "org.springframework.boot:spring-boot-autoconfigure", "installed": "4.0.6", "fixed": ["4.0.7", "3.5.15"], "severity_team": "MEDIUM", "cvss_max": 5.3, "cvss_source": "redhat", "origin": "team", "expected": "present"},
    {"row": 27, "advisory": "CVE-2026-41853", "package": "org.springframework:spring-webmvc", "installed": "7.0.7", "fixed": ["7.0.8", "6.2.19"], "severity_team": "MEDIUM", "cvss_max": 5.3, "cvss_source": "redhat", "origin": "team", "expected": "present"},
    {"row": 28, "advisory": "CVE-2026-54514", "package": "com.fasterxml.jackson.core:jackson-databind", "installed": "2.21.2", "fixed": ["2.18.8", "2.21.4"], "severity_team": "MEDIUM", "cvss_max": 5.3, "cvss_source": "redhat", "origin": "team", "expected": "present", "human_verdict": "unreachable", "reason_class": "api-unused", "reason": "InetSocketAddress 역직렬화 0건 (도달 경로 미확인)"},
    {"row": 28, "advisory": "CVE-2026-54514", "package": "tools.jackson.core:jackson-databind", "installed": "3.1.2", "fixed": ["3.1.4"], "severity_team": "MEDIUM", "cvss_max": 5.3, "cvss_source": "redhat", "origin": "team", "expected": "present", "human_verdict": "unreachable", "reason_class": "api-unused", "reason": "InetSocketAddress 역직렬화 0건"},
    {"row": 29, "advisory": "CVE-2026-54515", "package": "com.fasterxml.jackson.core:jackson-databind", "installed": "2.21.2", "fixed": ["2.18.9", "2.21.5"], "severity_team": "MEDIUM", "cvss_max": 5.3, "cvss_source": "redhat", "origin": "team", "expected": "present", "human_verdict": "unreachable", "reason_class": "api-unused", "reason": "@JsonIgnoreProperties 0건 (도달 경로 미확인)"},
    {"row": 29, "advisory": "CVE-2026-54515", "package": "tools.jackson.core:jackson-databind", "installed": "3.1.2", "fixed": ["3.1.4"], "severity_team": "MEDIUM", "cvss_max": 5.3, "cvss_source": "redhat", "origin": "team", "expected": "present", "human_verdict": "unreachable", "reason_class": "api-unused", "reason": "@JsonIgnoreProperties 0건"},
    {"row": 30, "advisory": "CVE-2026-54516", "package": "com.fasterxml.jackson.core:jackson-databind", "installed": "2.21.2", "fixed": ["2.21.4"], "severity_team": "MEDIUM", "cvss_max": 5.3, "cvss_source": "redhat", "origin": "team", "expected": "present", "human_verdict": "unreachable", "reason_class": "api-unused", "reason": "PropertyNamingStrategy·renamed properties 0건 (도달 경로 미확인)"},
    {"row": 30, "advisory": "CVE-2026-54516", "package": "tools.jackson.core:jackson-databind", "installed": "3.1.2", "fixed": ["3.1.4"], "severity_team": "MEDIUM", "cvss_max": 5.3, "cvss_source": "redhat", "origin": "team", "expected": "present", "human_verdict": "unreachable", "reason_class": "api-unused", "reason": "PropertyNamingStrategy 0건"},
    {"row": 31, "advisory": "CVE-2026-54517", "package": "com.fasterxml.jackson.core:jackson-databind", "installed": "2.21.2", "fixed": ["2.21.4"], "severity_team": "MEDIUM", "cvss_max": 5.3, "cvss_source": "redhat", "origin": "team", "expected": "present", "human_verdict": "unreachable", "reason_class": "api-unused", "reason": "@JsonView 필터 0건 (도달 경로 미확인)"},
    {"row": 31, "advisory": "CVE-2026-54517", "package": "tools.jackson.core:jackson-databind", "installed": "3.1.2", "fixed": ["3.1.4"], "severity_team": "MEDIUM", "cvss_max": 5.3, "cvss_source": "redhat", "origin": "team", "expected": "present", "human_verdict": "unreachable", "reason_class": "api-unused", "reason": "@JsonView 0건"},
    {"row": 32, "advisory": "CVE-2026-41848", "package": "org.springframework:spring-core", "installed": "7.0.7", "fixed": ["7.0.8", "6.2.19"], "severity_team": "LOW", "cvss_max": 7.5, "cvss_source": "nvd", "origin": "team", "expected": "present"},
    {"row": 33, "advisory": "CVE-2026-41852", "package": "org.springframework:spring-expression", "installed": "7.0.7", "fixed": ["7.0.8", "6.2.19"], "severity_team": "LOW", "cvss_max": 5.3, "cvss_source": "nvd", "origin": "team", "expected": "present"},
    {"row": 34, "advisory": "CVE-2026-10532", "package": "ch.qos.logback:logback-core", "installed": "1.5.32", "fixed": ["1.5.34"], "severity_team": "LOW", "cvss_max": 2.9, "cvss_source": "ghsa", "origin": "team", "expected": "present"},
    {"row": 35, "advisory": "CVE-2026-9828", "package": "ch.qos.logback:logback-core", "installed": "1.5.32", "fixed": ["1.5.33"], "severity_team": "LOW", "cvss_max": 1.2, "cvss_source": "ghsa", "origin": "team", "expected": "present"},
    {"row": null, "advisory": "CVE-2026-68763", "package": "org.apache.tomcat.embed:tomcat-embed-core", "installed": "11.0.22", "fixed": ["11.0.25"], "severity_team": "Important", "published": "2026-08-25", "origin": "dev-found", "expected": "present", "human_verdict": "unreachable", "reason_class": "config-gated", "reason": "HTTP/2 비활성(설정 0건, Spring Boot 기본 false)"},
    {"row": null, "advisory": "CVE-2026-68569", "package": "org.apache.tomcat.embed:tomcat-embed-core", "installed": "11.0.22", "fixed": ["11.0.25"], "severity_team": "Important", "published": "2026-08-25", "origin": "dev-found", "expected": "present", "human_verdict": "unreachable", "reason_class": "config-gated", "reason": "Tomcat Realm 미사용(자체 HTTP Basic 필터)"},
    {"row": null, "advisory": "CVE-2026-65927", "package": "org.apache.tomcat.embed:tomcat-embed-core", "installed": "11.0.22", "fixed": ["11.0.25"], "severity_team": "Important", "published": "2026-08-25", "origin": "dev-found", "expected": "present", "human_verdict": "unreachable", "reason_class": "config-gated", "reason": "RewriteValve 미설정"},
    {"row": null, "advisory": "CVE-2026-65182", "package": "org.apache.tomcat.embed:tomcat-embed-core", "installed": "11.0.22", "fixed": ["11.0.25"], "severity_team": "Important", "published": "2026-08-25", "origin": "dev-found", "expected": "present", "human_verdict": "unreachable", "reason_class": "config-gated", "reason": "web.xml security-constraint 미사용"},
    {"row": null, "advisory": "CVE-2026-65637", "package": "org.apache.tomcat.embed:tomcat-embed-core", "installed": "11.0.22", "fixed": ["11.0.25"], "severity_team": "Moderate", "published": "2026-08-25", "origin": "dev-found", "expected": "present", "human_verdict": "unreachable", "reason_class": "config-gated", "reason": "HTTP/2 비활성"},
    {"row": null, "advisory": "CVE-2026-73180", "package": "org.apache.tomcat.embed:tomcat-embed-core", "installed": "11.0.22", "fixed": ["11.0.25"], "severity_team": "Low", "published": "2026-08-25", "origin": "dev-found", "expected": "present", "human_verdict": "unreachable", "reason_class": "config-gated", "reason": "WebSocket 미사용"},
    {"row": null, "advisory": "CVE-2026-68525", "package": "org.apache.tomcat.embed:tomcat-embed-core", "installed": "11.0.22", "fixed": ["11.0.25"], "severity_team": "Low", "published": "2026-08-25", "origin": "dev-found", "expected": "present", "human_verdict": "unreachable", "reason_class": "config-gated", "reason": "formLogin 명시적 disable"},
    {"row": null, "advisory": "CVE-2026-66422", "package": "org.apache.tomcat.embed:tomcat-embed-core", "installed": "11.0.22", "fixed": ["11.0.25"], "severity_team": "Low", "published": "2026-08-25", "origin": "dev-found", "expected": "present", "human_verdict": "unreachable", "reason_class": "config-gated", "reason": "security-role-ref·isUserInRole 0건"},
    {"row": null, "advisory": "CVE-2026-66299", "package": "org.apache.tomcat.embed:tomcat-embed-core", "installed": "11.0.22", "fixed": ["11.0.25"], "severity_team": "Low", "published": "2026-07-28", "origin": "dev-found", "expected": "present", "human_verdict": "unreachable", "reason_class": "config-gated", "reason": "WebSocket chat 예제 앱 미배포", "note": "공개 34일 후 스캔에도 보안팀 목록에 없음 — 보안팀 필터 정책 확인 요청 대상"},
    {"row": null, "advisory": "CVE-2026-65905", "package": "org.apache.tomcat.embed:tomcat-embed-core", "installed": "11.0.22", "fixed": ["11.0.25"], "severity_team": "Low", "published": "2026-08-25", "origin": "dev-found", "expected": "present", "human_verdict": "unreachable", "reason_class": "config-gated", "reason": "DIGEST 인증 미사용"},
    {"row": null, "advisory": "CVE-2026-65183", "package": "org.apache.tomcat.embed:tomcat-embed-core", "installed": "11.0.22", "fixed": ["11.0.25"], "severity_team": "Low", "published": "2026-08-25", "origin": "dev-found", "expected": "present", "human_verdict": "unreachable", "reason_class": "config-gated", "reason": "Unix Domain Socket 커넥터 미구성(TCP 7700/9090)"},
    {"row": null, "advisory": "CVE-2026-19880", "package": "ch.qos.logback:logback-core", "installed": "1.5.32", "fixed": ["1.6.3"], "severity_team": null, "published": null, "origin": "dev-found", "expected": "present", "human_verdict": "unreachable", "reason_class": "config-gated", "reason": "SiftingAppender 미사용(appender 는 콘솔·롤링 파일 2종)"}
  ]
}
```

- [ ] **Step 2: GT-A 매니페스트 작성**

`docs/verification/ground-truth/gt-a-source.json`. `expected_rule_suffix` 는 semgrep 이 로컬 룰 디렉토리 룰 id 에 경로 접두를 붙이므로 `rule_id.endswith()` 로 비교한다(`tests/test_custom_rules.py` 관례).

```json
{
  "@context": "secscan-ground-truth/v1",
  "kind": "source",
  "repo_note": "message-gate. vulnerable = 수정 커밋의 부모. 파일 경로는 저장소 루트 기준 접미(endswith 매칭).",
  "entries": [
    {"cwe": "CWE-259", "issue": "#264", "vulnerable": "29bfb5ba", "fixed": "72e49a1b",
     "file_suffix": "LoadtestSeederConfig.java", "expected_rule_suffix": "hardcoded-credential",
     "category": "sast", "expected_tier": "review", "tier_reason": "loadtest 경로 강등(is_test_path)", "class": "in-category"},
    {"cwe": "CWE-760", "issue": "#266", "vulnerable": "d4a1ded0", "fixed": "55e58bc6",
     "file_suffix": "LoadtestSeederConfig.java", "expected_rule_suffix": "zero-salt",
     "category": "sast", "expected_tier": "review", "tier_reason": "loadtest 경로 강등", "class": "in-category"},
    {"cwe": "CWE-89", "issue": "#305", "vulnerable": "1052b80d", "fixed": "8428e646",
     "file_suffix": "LgCarrierMapper.xml", "expected_rule_suffix": "mybatis-sqli-identifier",
     "category": "sast", "expected_tier": "review", "tier_reason": "테이블명(식별자) 위치 ${} → identifier 룰 = review", "class": "in-category"},
    {"cwe": "CWE-89", "issue": "#305", "vulnerable": "1052b80d", "fixed": "8428e646",
     "file_suffix": "OldLgCarrierMapper.xml", "expected_rule_suffix": "mybatis-sqli-identifier",
     "category": "sast", "expected_tier": "review", "tier_reason": "테이블명(식별자) 위치", "class": "in-category"},
    {"cwe": "CWE-489", "issue": "#263", "vulnerable": "29bfb5ba", "fixed": "5895c9f4",
     "file_suffix": "application.yml", "expected_rule_suffix": null,
     "category": null, "expected_tier": null, "tier_reason": null, "class": "measure-then-classify",
     "note": "management 포트 인증 강화. 기존 semgrep 팩이 무엇이라도 잡는지 기록만"},
    {"cwe": "CWE-497", "issue": "#303", "vulnerable": "1052b80d", "fixed": "81f4f31b",
     "file_suffix": "TestDbReset.java", "expected_rule_suffix": null,
     "category": null, "expected_tier": null, "tier_reason": null, "class": "measure-then-classify",
     "note": "자격증명 마스킹(로그 노출). 기존 팩 탐지 여부 기록만"},
    {"cwe": "CWE-676", "issue": "#303", "vulnerable": "1052b80d", "fixed": "81f4f31b",
     "file_suffix": "TestDbReset.java", "expected_rule_suffix": null,
     "category": null, "expected_tier": null, "tier_reason": null, "class": "out-of-category", "note": "리소스 정리 — 코드 스멜"},
    {"cwe": "CWE-754", "issue": "#268", "vulnerable": null, "fixed": null, "file_suffix": null, "expected_rule_suffix": null,
     "category": null, "expected_tier": null, "tier_reason": null, "class": "out-of-category", "note": "broad catch — IDE 인스펙션 영역(갭 지도)"},
    {"cwe": "CWE-476", "issue": "#312", "vulnerable": "00c7e34b", "fixed": "b742368e", "file_suffix": null, "expected_rule_suffix": null,
     "category": null, "expected_tier": null, "tier_reason": null, "class": "out-of-category", "note": "null 가드 — 코드 스멜"},
    {"cwe": "CWE-397", "issue": "#307", "vulnerable": null, "fixed": null, "file_suffix": null, "expected_rule_suffix": null,
     "category": null, "expected_tier": null, "tier_reason": null, "class": "out-of-category", "note": "generic throws"},
    {"cwe": "CWE-398", "issue": "#308", "vulnerable": null, "fixed": null, "file_suffix": null, "expected_rule_suffix": null,
     "category": null, "expected_tier": null, "tier_reason": null, "class": "out-of-category", "note": "빈 블록"}
  ]
}
```

- [ ] **Step 3: 보안팀 스키마 골든 작성**

`docs/verification/ground-truth/golden/security-team-schema.json`:

```json
{
  "@context": "secscan-golden/security-team-xlsx/v1",
  "source": "보안팀 'MessageGate 라이브러리 취약점 점검 결과보고서_20260831.xlsx' — 원본 미확보, 시트 사진 2장 기준 재구성 (2026-09-04)",
  "sheets": ["Summary", "Findings", "Deduped_CVEs", "Targets"],
  "deduped_cves_header": ["No.", "Vulnerability ID", "Severity", "Max CVSS Score", "CVSS Source",
    "Affected Packages", "Installed Versions", "Fixed Versions", "Targets", "Finding Count", "Title", "URL"],
  "observations": {
    "severity": "trivy 벤더 등급(redhat 우선) — CVSS 순서와 불일치(HIGH 5.9 / MEDIUM 7.5 존재)",
    "targets": "Java (trivy fs jar 분석기가 모든 jar 를 Target=Java 로 묶음 → 배포 jar 스캔)",
    "affected_packages": "복수 패키지를 한 셀에 ', ' 로 결합 (jackson 2.x/3.x)",
    "finding_count": "Findings 시트 원본 행(패키지×타깃) 수를 CVE 별 합산",
    "installed_versions_anomaly": "mssql-jdbc 13.2.1 (실제 13.2.1.jre11) — jar 버전 파싱 추정"
  }
}
```

- [ ] **Step 4: 실패하는 테스트 작성 (`tests/test_measure.py` 끝에 추가)**

```python
# --- V0: GT 매니페스트 로더 ---
from pathlib import Path

from secscan.measure import GtEntry, GtManifest, load_gt_manifest

GT_DIR = Path(__file__).parent.parent / "docs" / "verification" / "ground-truth"


def test_gt_b_manifest_loads_and_counts():
    m = load_gt_manifest(GT_DIR / "gt-b-sca.json")
    assert m.kind == "sca"
    assert m.snapshot == "a483b3b1"
    assert len(m.absent()) == 1
    assert m.absent()[0].advisory == "CVE-2025-59250"
    # CVE 단위 분모 46 = 보안팀 34 + 개발자 12 (absent 제외)
    assert len(m.cves()) == 46
    assert sum(1 for e in m.present() if e.origin == "dev-found") == 12
    assert "org.apache.tomcat.embed:tomcat-embed-core" in m.packages()


def test_gt_manifest_rejects_duplicate_keys(tmp_path):
    p = tmp_path / "gt.json"
    p.write_text('{"kind":"sca","snapshot":"x","scan_date":"2026-01-01","entries":['
                 '{"advisory":"CVE-1","package":"a:b","installed":"1"},'
                 '{"advisory":"CVE-1","package":"a:b","installed":"1"}]}')
    import pytest
    with pytest.raises(ValueError, match="중복"):
        load_gt_manifest(p)


def test_gt_manifest_rejects_bad_expected(tmp_path):
    p = tmp_path / "gt.json"
    p.write_text('{"kind":"sca","snapshot":"x","scan_date":"2026-01-01","entries":['
                 '{"advisory":"CVE-1","package":"a:b","installed":"1","expected":"maybe"}]}')
    import pytest
    with pytest.raises(ValueError, match="expected"):
        load_gt_manifest(p)


def test_gt_a_manifest_classes_are_fixed():
    m = load_gt_manifest(GT_DIR / "gt-a-source.json")
    assert m.kind == "source"
    classes = {e.get("class") for e in m.raw_entries}
    assert classes == {"in-category", "measure-then-classify", "out-of-category"}
    in_cat = [e for e in m.raw_entries if e["class"] == "in-category"]
    assert {e["cwe"] for e in in_cat} == {"CWE-259", "CWE-760", "CWE-89"}
    assert all(e["expected_rule_suffix"] for e in in_cat)
```

- [ ] **Step 5: 실패 확인**

Run: `.venv/bin/pytest tests/test_measure.py -q`
Expected: FAIL — `ImportError: cannot import name 'GtEntry'`

- [ ] **Step 6: 구현 (`secscan/measure.py` 끝에 추가)**

```python
# --- V0: 정답지 매니페스트 (spec §3.4) ---
import json
from pathlib import Path

_EXPECTED = frozenset({"present", "absent"})


@dataclass(frozen=True)
class GtEntry:
    """SCA 정답지 항목 = advisory × 패키지 × 설치버전."""
    advisory: str
    package: str  # "group:artifact"
    installed: str
    expected: str = "present"  # present | absent
    origin: str = "team"  # team | dev-found
    row: int | None = None
    aliases: tuple[str, ...] = ()
    fixed: tuple[str, ...] = ()
    severity_team: str | None = None
    cvss_max: float | None = None
    cvss_source: str | None = None
    published: str | None = None  # ISO 날짜, 초과분 분류용
    human_verdict: str | None = None  # reachable | unreachable | None
    reason_class: str | None = None  # config-gated | impl-absent | api-unused
    reason: str | None = None
    note: str | None = None

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.advisory, self.package, self.installed)


@dataclass
class GtManifest:
    kind: str  # sca | source
    snapshot: str | None
    scan_date: str | None
    entries: tuple[GtEntry, ...]  # kind == "sca" 일 때만 채움
    raw_entries: list[dict]  # 원본(소스 정답지는 이걸 그대로 사용)

    def present(self) -> list[GtEntry]:
        return [e for e in self.entries if e.expected == "present"]

    def absent(self) -> list[GtEntry]:
        return [e for e in self.entries if e.expected == "absent"]

    def packages(self) -> set[str]:
        return {e.package for e in self.entries}

    def cves(self) -> set[str]:
        return {e.advisory for e in self.present()}


def _entry_from_dict(d: dict) -> GtEntry:
    exp = d.get("expected", "present")
    if exp not in _EXPECTED:
        raise ValueError(f"expected 는 present|absent — {d.get('advisory')}: {exp}")
    return GtEntry(
        advisory=d["advisory"], package=d["package"], installed=d["installed"],
        expected=exp, origin=d.get("origin", "team"), row=d.get("row"),
        aliases=tuple(d.get("aliases") or ()), fixed=tuple(d.get("fixed") or ()),
        severity_team=d.get("severity_team"), cvss_max=d.get("cvss_max"),
        cvss_source=d.get("cvss_source"), published=d.get("published"),
        human_verdict=d.get("human_verdict"), reason_class=d.get("reason_class"),
        reason=d.get("reason"), note=d.get("note"),
    )


def load_gt_manifest(path) -> GtManifest:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    kind = data.get("kind", "sca")
    raw = list(data.get("entries", []))
    entries: tuple[GtEntry, ...] = ()
    if kind == "sca":
        parsed = [_entry_from_dict(d) for d in raw]
        seen: set[tuple[str, str, str]] = set()
        for e in parsed:
            if e.key in seen:
                raise ValueError(f"중복 항목: {e.key}")
            seen.add(e.key)
        entries = tuple(parsed)
    return GtManifest(kind=kind, snapshot=data.get("snapshot"),
                      scan_date=data.get("scan_date"), entries=entries, raw_entries=raw)
```

`measure.py` 상단 import 에 `from dataclasses import dataclass, field` 가 이미 있다. `json`/`Path` import 는 모듈 상단으로 옮겨도 된다.

- [ ] **Step 7: 통과 확인**

Run: `.venv/bin/pytest tests/test_measure.py -q`
Expected: PASS (기존 테스트 포함)

- [ ] **Step 8: 커밋**

```bash
git add docs/verification/ground-truth secscan/measure.py tests/test_measure.py
git commit -m "feat(V0): 정답지 매니페스트 3종(GT-B 46+FP1 · GT-A · 보안팀 시트 골든) + 로더/검증기

다음: match_ground_truth 대조기"
```

---

### Task 2: 대조기 `match_ground_truth` + 초과분 분류 `classify_extras`

**Files:**
- Modify: `secscan/measure.py`
- Test: `tests/test_measure.py`

**Interfaces:**
- Consumes: `GtEntry`, `GtManifest` (Task 1), `Finding`(models).
- Produces: `Match(entry, kind, finding_key, got_version)`, `MatchReport(matches, extras)` with `by_kind()`, `recall_cve() -> (matched, total)`, `recall_entry(strict: bool) -> (matched, total)`, `false_positives()`, `missed()`; `match_ground_truth(findings, manifest) -> MatchReport`; `classify_extras(extras, manifest, published: dict[str, str]) -> dict[str, str]` (dedup_key → `team-missed | db-drift | inventory-diff | unknown-date`).

- [ ] **Step 1: 실패하는 테스트 작성 (`tests/test_measure.py` 끝에 추가)**

```python
# --- V0: 대조기 ---
from secscan.measure import classify_extras, match_ground_truth


def _sca(pkg, ver, cve, aliases=()):
    return Finding(
        category="sca", severity="high", tool="trivy", rule_id=cve,
        component=Component("maven", pkg, ver),
        advisory=Advisory(cve, aliases=(cve, *aliases)),
        reachability=Reachability(UNKNOWN),
    )


def _manifest(entries):
    return GtManifest(kind="sca", snapshot="s", scan_date="2026-08-31",
                      entries=tuple(entries), raw_entries=[])


def test_match_kinds_exact_version_mismatch_alias_missed():
    m = _manifest([
        GtEntry("CVE-1", "g:a", "1.0"),
        GtEntry("CVE-2", "g:b", "2.0"),
        GtEntry("CVE-3", "g:c", "3.0", aliases=("GHSA-x",)),
        GtEntry("CVE-4", "g:d", "4.0"),
    ])
    findings = [
        _sca("g:a", "1.0", "CVE-1"),          # exact
        _sca("g:b", "2.0.jre11", "CVE-2"),    # version-mismatch
        _sca("g:c", "3.0", "GHSA-x"),         # alias
        _sca("g:z", "9.9", "CVE-9"),          # extra
    ]
    r = match_ground_truth(findings, m)
    assert r.by_kind() == {"exact": 1, "version-mismatch": 1, "alias": 1, "missed": 1}
    assert r.recall_cve() == (3, 4)
    assert r.recall_entry(strict=True) == (2, 4)     # exact+alias
    assert r.recall_entry(strict=False) == (3, 4)    # + version-mismatch
    assert [x.entry.advisory for x in r.missed()] == ["CVE-4"]
    assert [f.advisory.id for f in r.extras] == ["CVE-9"]
    vm = next(x for x in r.matches if x.kind == "version-mismatch")
    assert vm.got_version == "2.0.jre11"


def test_match_absent_entry_reported_as_false_positive():
    m = _manifest([GtEntry("CVE-FP", "g:m", "1.0.jre11", expected="absent"),
                   GtEntry("CVE-OK", "g:n", "1.0", expected="absent")])
    r = match_ground_truth([_sca("g:m", "1.0", "CVE-FP")], m)
    kinds = {x.entry.advisory: x.kind for x in r.matches}
    assert kinds == {"CVE-FP": "false-positive", "CVE-OK": "absent-ok"}
    assert [x.entry.advisory for x in r.false_positives()] == ["CVE-FP"]
    assert r.extras == []  # FP 매칭에 쓰인 finding 은 초과분이 아니다


def test_match_same_cve_two_packages_counts_entries_separately():
    m = _manifest([GtEntry("CVE-J", "com.fasterxml.jackson.core:jackson-databind", "2.21.2"),
                   GtEntry("CVE-J", "tools.jackson.core:jackson-databind", "3.1.2")])
    r = match_ground_truth([_sca("com.fasterxml.jackson.core:jackson-databind", "2.21.2", "CVE-J")], m)
    assert r.recall_cve() == (1, 1)
    assert r.recall_entry(strict=True) == (1, 2)


def test_classify_extras_by_published_date_and_inventory():
    m = _manifest([GtEntry("CVE-1", "g:a", "1.0")])
    extras = [_sca("g:a", "1.0", "CVE-OLD"), _sca("g:a", "1.0", "CVE-NEW"),
              _sca("g:q", "1.0", "CVE-Q"), _sca("g:a", "1.0", "CVE-NODATE")]
    published = {"CVE-OLD": "2026-08-01", "CVE-NEW": "2026-09-02", "CVE-Q": "2026-08-01"}
    c = classify_extras(extras, m, published)
    assert c[extras[0].dedup_key] == "team-missed"
    assert c[extras[1].dedup_key] == "db-drift"
    assert c[extras[2].dedup_key] == "inventory-diff"
    assert c[extras[3].dedup_key] == "unknown-date"
```

- [ ] **Step 2: 실패 확인**

Run: `.venv/bin/pytest tests/test_measure.py -q`
Expected: FAIL — `ImportError: cannot import name 'classify_extras'`

- [ ] **Step 3: 구현 (`secscan/measure.py` 끝에 추가)**

```python
# --- V0: 대조기 (spec §4.3) ---

@dataclass
class Match:
    entry: GtEntry
    kind: str  # exact | version-mismatch | alias | missed | false-positive | absent-ok
    finding_key: str | None = None
    got_version: str | None = None


@dataclass
class MatchReport:
    matches: list[Match]
    extras: list[Finding]

    def by_kind(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for m in self.matches:
            if m.kind in ("absent-ok",):
                continue
            out[m.kind] = out.get(m.kind, 0) + 1
        return out

    def _present(self) -> list[Match]:
        return [m for m in self.matches if m.entry.expected == "present"]

    def recall_cve(self) -> tuple[int, int]:
        total = {m.entry.advisory for m in self._present()}
        hit = {m.entry.advisory for m in self._present()
               if m.kind in ("exact", "alias", "version-mismatch")}
        return (len(hit), len(total))

    def recall_entry(self, *, strict: bool = True) -> tuple[int, int]:
        ok = ("exact", "alias") if strict else ("exact", "alias", "version-mismatch")
        pres = self._present()
        return (sum(1 for m in pres if m.kind in ok), len(pres))

    def missed(self) -> list[Match]:
        return [m for m in self.matches if m.kind == "missed"]

    def false_positives(self) -> list[Match]:
        return [m for m in self.matches if m.kind == "false-positive"]


def _ids(f: Finding) -> set[str]:
    if not f.advisory:
        return set()
    return {f.advisory.id, *f.advisory.aliases}


def match_ground_truth(findings: list[Finding], manifest: GtManifest) -> MatchReport:
    sca = [f for f in findings if f.category == "sca" and f.component and f.advisory]
    used: set[str] = set()
    matches: list[Match] = []
    for e in manifest.entries:
        cands = [f for f in sca if f.component.package == e.package
                 and (e.advisory in _ids(f) or any(a in _ids(f) for a in e.aliases))]
        if e.expected == "absent":
            if cands:
                used.update(f.dedup_key for f in cands)
                matches.append(Match(e, "false-positive", cands[0].dedup_key, cands[0].component.version))
            else:
                matches.append(Match(e, "absent-ok"))
            continue
        if not cands:
            matches.append(Match(e, "missed"))
            continue
        exact = [f for f in cands if f.component.version == e.installed]
        f = exact[0] if exact else cands[0]
        used.add(f.dedup_key)
        if f.component.version != e.installed:
            kind = "version-mismatch"
        elif e.advisory in _ids(f):
            kind = "exact"
        else:
            kind = "alias"
        matches.append(Match(e, kind, f.dedup_key, f.component.version))
    extras = [f for f in sca if f.dedup_key not in used]
    return MatchReport(matches, extras)


def classify_extras(extras: list[Finding], manifest: GtManifest,
                    published: dict[str, str]) -> dict[str, str]:
    """초과 탐지 자동 분류. our-fp 는 자동 판정 불가 — 사람이 triage 파일로 덮어쓴다."""
    inv = manifest.packages()
    scan_date = manifest.scan_date or ""
    out: dict[str, str] = {}
    for f in extras:
        date = next((published[i] for i in _ids(f) if i in published), None)
        if f.component.package not in inv:
            out[f.dedup_key] = "inventory-diff"
        elif date is None:
            out[f.dedup_key] = "unknown-date"
        elif date[:10] > scan_date:
            out[f.dedup_key] = "db-drift"
        else:
            out[f.dedup_key] = "team-missed"
    return out
```

- [ ] **Step 4: 통과 확인**

Run: `.venv/bin/pytest tests/test_measure.py -q`
Expected: PASS

- [ ] **Step 5: 커밋**

```bash
git add secscan/measure.py tests/test_measure.py
git commit -m "feat(V0): match_ground_truth(exact/version-mismatch/alias/missed/FP) + classify_extras

다음: run_scan TraceSink 단계 추적기"
```

---

### Task 3: `TraceSink` 단계 추적기 (제품 변경, 기본 무동작)

**Files:**
- Modify: `secscan/normalize/__init__.py`
- Modify: `secscan/scan.py`
- Test: `tests/test_scan.py`

**Interfaces:**
- Produces: `normalize_each(raws) -> dict[str, list[Finding]]` (normalize), `TraceSink` with `.raw: list[dict]`, `.stages: list[dict]`, `.record_raw(tool, status, nbytes)`, `.record(stage, findings)`, `.to_dict()`; `run_scan(..., trace: TraceSink | None = None)`.
- 단계 이름(spec §4.2 순서): `normalize:<tool>` → `merge` → `exclude` → `compliance` → `reachability` → `secret_verify` → `baseline` → `suppress` → `final`. 조건부 단계는 실행되지 않으면 기록하지 않는다.

- [ ] **Step 1: 실패하는 테스트 작성 (`tests/test_scan.py` 끝에 추가)**

```python
# --- V0: TraceSink ---
from secscan.scan import TraceSink


def test_trace_sink_records_stage_order_and_counts():
    sink = TraceSink()
    run_scan(
        "/proj", get_profile("accurate-sca"),
        adapters=[FakeAdapter("trivy", TRIVY), FakeAdapter("osv-scanner", OSV),
                  FakeAdapter("gitleaks", "", status=FAILED)],
        reachability_provider=_depscan_provider,
        env_ok=lambda: True, count_loc=lambda t: 10,
        trace=sink,
    )
    raw_tools = {(r["tool"], r["status"]) for r in sink.raw}
    assert ("gitleaks", FAILED) in raw_tools and ("trivy", OK) in raw_tools
    names = [s["stage"] for s in sink.stages]
    assert names[:2] == sorted(names[:2]) and all(n.startswith("normalize:") for n in names[:2])
    assert names[2:] == ["merge", "exclude", "compliance", "reachability", "final"]
    merge = next(s for s in sink.stages if s["stage"] == "merge")
    assert merge["count"] == len(merge["keys"]) > 0
    d = sink.to_dict()
    assert set(d) == {"raw", "stages"}


def test_run_scan_without_trace_is_unchanged():
    a = run_scan("/proj", get_profile("accurate-sca"),
                 adapters=[FakeAdapter("trivy", TRIVY)], reachability_provider=None)
    b = run_scan("/proj", get_profile("accurate-sca"),
                 adapters=[FakeAdapter("trivy", TRIVY)], reachability_provider=None, trace=TraceSink())
    assert [f.dedup_key for f in a.findings] == [f.dedup_key for f in b.findings]
```

- [ ] **Step 2: 실패 확인**

Run: `.venv/bin/pytest tests/test_scan.py -q`
Expected: FAIL — `ImportError: cannot import name 'TraceSink'`

- [ ] **Step 3: `normalize_each` 추가 (`secscan/normalize/__init__.py`)**

```python
def normalize_each(raw_results: list[RawResult]) -> dict[str, list]:
    """도구별 정규화(병합 전). 성공한 RawResult 만. 추적기·골든 비교용."""
    out: dict[str, list] = {}
    for r in raw_results:
        if r.status != OK:
            continue
        parser = _PARSERS.get(r.tool)
        if parser:
            out.setdefault(r.tool, []).extend(parser(r.payload, tool_version=r.version))
    return out


def to_findings(raw_results: list[RawResult]):
    """성공한 RawResult 만 정규화·병합. 실패/타임아웃은 건너뛴다(부분 실패는 별도 보고)."""
    findings = []
    for fs in normalize_each(raw_results).values():
        findings.extend(fs)
    return merge_consensus(findings)
```

기존 `to_findings` 본문을 위 구현으로 교체한다(동작 동일: 도구 순서는 raw 리스트 순서 유지 — `dict` 삽입 순서).

- [ ] **Step 4: `TraceSink` + `run_scan(trace=)` (`secscan/scan.py`)**

파일 상단 import 에 `from .normalize import normalize_each, to_findings` 와 `from .normalize.merge import merge_consensus` 를 추가하고, 클래스와 파라미터를 추가한다.

```python
@dataclass
class TraceSink:
    """단계별 attrition 기록(spec §4.2). run_scan 에 주입하지 않으면 아무 비용도 없다."""
    raw: list[dict] = field(default_factory=list)
    stages: list[dict] = field(default_factory=list)

    def record_raw(self, tool: str, status: str, nbytes: int) -> None:
        self.raw.append({"tool": tool, "status": status, "bytes": nbytes})

    def record(self, stage: str, findings) -> None:
        keys = sorted(f.dedup_key for f in findings)
        self.stages.append({"stage": stage, "count": len(keys), "keys": keys})

    def to_dict(self) -> dict:
        return {"raw": list(self.raw), "stages": list(self.stages)}
```

`run_scan` 시그니처 끝에 `trace: TraceSink | None = None,` 을 추가하고 본문을 다음처럼 바꾼다(기존 로직 유지, 기록만 삽입):

```python
    raws = orchestrate(adapters, target, max_workers=max_workers)
    if trace is not None:
        for r in raws:
            trace.record_raw(r.tool, r.status, len(r.payload or ""))
        per_tool = normalize_each(raws)
        for tool in sorted(per_tool):
            trace.record(f"normalize:{tool}", per_tool[tool])
        findings = merge_consensus([f for fs in per_tool.values() for f in fs])
        trace.record("merge", findings)
    else:
        findings = to_findings(raws)
```

이후 각 단계 뒤에 한 줄씩:

```python
    # (제외 블록 끝, excluded_count 계산 직후)
    if trace is not None:
        trace.record("exclude", findings)
    enrich_compliance(findings)
    if trace is not None:
        trace.record("compliance", findings)
    # (도달성 블록 안, findings, ran, reason = ... 직후)
        if trace is not None:
            trace.record("reachability", findings)
    # (시크릿 검증 블록 안, findings, verified_count = ... 직후)
        if trace is not None:
            trace.record("secret_verify", findings)
    # (baseline 적용 직후)
        if trace is not None:
            trace.record("baseline", findings)
    # (apply_suppressions 직후)
        if trace is not None:
            trace.record("suppress", findings)
    # (return 직전)
    if trace is not None:
        trace.record("final", findings)
```

- [ ] **Step 5: 통과 확인 + 전체 회귀**

Run: `.venv/bin/pytest -q`
Expected: 전부 PASS (234 + 신규)

- [ ] **Step 6: 커밋**

```bash
git add secscan/normalize/__init__.py secscan/scan.py tests/test_scan.py
git commit -m "feat(V1): run_scan TraceSink — normalize/merge/exclude/compliance/reachability/secret/baseline/suppress/final attrition (기본 None, 무변경)

다음: findings.json lossless 직렬화"
```

---

### Task 4: `findings.json` lossless 직렬화 (`secscan/output/json_io.py`)

**Files:**
- Create: `secscan/output/json_io.py`
- Test: `tests/test_json_io.py`

**Interfaces:**
- Produces: `to_json(findings: list[Finding], *, meta: dict | None = None) -> str`, `from_json(text: str) -> list[Finding]`, `finding_to_dict(f) -> dict`, `finding_from_dict(d) -> Finding`. 스키마 `{"@context": "secscan-findings/v1", "meta": {...}, "findings": [...]}`. tuple→list, dataclass→dict, `None` 유지. 플랜 2 에서 필드가 늘어도 `dataclasses.fields` 기반이라 자동 반영.

- [ ] **Step 1: 실패하는 테스트 작성 (`tests/test_json_io.py`)**

```python
"""findings.json — typed Finding 의 lossless 직렬화(spec §7.2). SARIF 가 아니다."""

import json

from secscan.models import (
    UNREACHABLE, Advisory, Component, Compliance, Consensus, Finding, KisaWeakness,
    Location, Reachability, Suppression,
)
from secscan.output.json_io import finding_from_dict, finding_to_dict, from_json, to_json


def _sca():
    return Finding(
        category="sca", severity="critical", title="Text4Shell", rule_id="CVE-2022-42889",
        tool="trivy+osv-scanner", cwe=("CWE-94",), owasp=("A03",), confidence="unknown",
        component=Component("maven", "org.apache.commons:commons-text", "1.9"),
        advisory=Advisory("CVE-2022-42889", aliases=("CVE-2022-42889", "GHSA-599f-7c49-w659"),
                          fixed_versions=("1.10.0",)),
        source="pom.xml",
        reachability=Reachability(UNREACHABLE, evidence="미호출", source="dep-scan"),
        consensus=Consensus(("trivy", "osv-scanner"), 2),
        references=("https://nvd.nist.gov/x",),
        suppression=Suppression("suppressed", "도달 불가", "alice 2026-09-01", "콜패스 없음",
                                "2026-12-31", "sca|maven|org.apache.commons:commons-text|1.9|CVE-2022-42889",
                                basis="unreachable"),
        compliance=Compliance(kisa=(KisaWeakness("IV-01", "입력데이터 검증 및 표현", "SQL 삽입"),),
                              pci=("PCI-DSS 6.2.4 — injection",)),
    )


def _sast():
    return Finding(category="sast", severity="high", title="SQLi", rule_id="java.sqli",
                   tool="semgrep", cwe=("CWE-89",), confidence="high",
                   location=Location("src/A.java", 10, 12, None), verified=None)


def test_round_trip_is_lossless():
    fs = [_sca(), _sast()]
    back = from_json(to_json(fs))
    assert back == fs
    assert [f.dedup_key for f in back] == [f.dedup_key for f in fs]


def test_json_shape_and_meta():
    d = json.loads(to_json([_sast()], meta={"profile": "standard"}))
    assert d["@context"] == "secscan-findings/v1"
    assert d["meta"] == {"profile": "standard"}
    f = d["findings"][0]
    assert f["id"] == _sast().id and f["dedup_key"] == _sast().dedup_key
    assert f["location"] == {"file": "src/A.java", "start_line": 10, "end_line": 12, "snippet_ref": None}
    assert f["cwe"] == ["CWE-89"]


def test_finding_from_dict_ignores_derived_fields():
    d = finding_to_dict(_sast())
    d["id"] = "zzz"; d["dedup_key"] = "zzz"; d["unknown_future_field"] = 1
    assert finding_from_dict(d) == _sast()
```

- [ ] **Step 2: 실패 확인**

Run: `.venv/bin/pytest tests/test_json_io.py -q`
Expected: FAIL — `ModuleNotFoundError: secscan.output.json_io`

- [ ] **Step 3: 구현 (`secscan/output/json_io.py`)**

```python
"""findings.json — typed Finding 의 lossless canonical 직렬화 (spec §7.2).

SARIF/markdown/xlsx 는 projection(손실 있음)이고, 이 파일만 내부 모델을 그대로 담는다.
dataclasses.fields 기반이라 모델에 필드가 추가되면 자동으로 따라온다(단, 중첩 타입은
_NESTED 표에 등록해야 복원된다).
"""

from __future__ import annotations

import json
from dataclasses import fields, is_dataclass

from ..models import (
    Advisory, Compliance, Component, Consensus, Finding, KisaWeakness, Location,
    Reachability, Suppression,
)

CONTEXT = "secscan-findings/v1"

# Finding 필드명 → 중첩 dataclass. tuple[dataclass] 은 (cls, "seq") 로 표기.
_NESTED: dict[str, object] = {
    "component": Component, "advisory": Advisory, "location": Location,
    "reachability": Reachability, "consensus": Consensus, "suppression": Suppression,
    "compliance": Compliance,
}
_COMPLIANCE_SEQ = {"kisa": KisaWeakness}


def _plain(obj):
    if is_dataclass(obj):
        return {f.name: _plain(getattr(obj, f.name)) for f in fields(obj)}
    if isinstance(obj, (list, tuple)):
        return [_plain(x) for x in obj]
    return obj


def _build(cls, data):
    if data is None:
        return None
    kwargs = {}
    for f in fields(cls):
        if f.name not in data:
            continue
        v = data[f.name]
        if cls is Compliance and f.name in _COMPLIANCE_SEQ:
            v = tuple(_build(_COMPLIANCE_SEQ[f.name], x) for x in (v or []))
        elif isinstance(v, list):
            v = tuple(v)
        kwargs[f.name] = v
    return cls(**kwargs)


def finding_to_dict(f: Finding) -> dict:
    d = _plain(f)
    d["id"] = f.id
    d["dedup_key"] = f.dedup_key
    return d


def finding_from_dict(d: dict) -> Finding:
    known = {f.name for f in fields(Finding)}
    kwargs = {}
    for name, v in d.items():
        if name not in known:
            continue  # id/dedup_key(파생)·미래 필드 무시
        if name in _NESTED:
            v = _build(_NESTED[name], v)
        elif isinstance(v, list):
            v = tuple(v)
        kwargs[name] = v
    return Finding(**kwargs)


def to_json(findings: list[Finding], *, meta: dict | None = None) -> str:
    doc = {"@context": CONTEXT, "meta": meta or {},
           "findings": [finding_to_dict(f) for f in findings]}
    return json.dumps(doc, indent=2, ensure_ascii=False, sort_keys=False)


def from_json(text: str) -> list[Finding]:
    doc = json.loads(text)
    if doc.get("@context") != CONTEXT:
        raise ValueError(f"findings.json 컨텍스트 불일치: {doc.get('@context')}")
    return [finding_from_dict(d) for d in doc.get("findings", [])]
```

- [ ] **Step 4: 통과 확인**

Run: `.venv/bin/pytest tests/test_json_io.py -q`
Expected: PASS

- [ ] **Step 5: 커밋**

```bash
git add secscan/output/json_io.py tests/test_json_io.py
git commit -m "feat(V1): findings.json lossless 직렬화(to_json/from_json) — 증거 동결·대조기 입력

다음: tools/verify 스냅샷 격리 + 증거 작성기"
```

---

### Task 5: `tools/verify` — 스냅샷 격리 + 증거 작성기 + 실행 CLI

**Files:**
- Create: `tools/__init__.py`, `tools/verify/__init__.py`
- Create: `tools/verify/snapshot.py`, `tools/verify/evidence.py`, `tools/verify/run_snapshot.py`
- Modify: `pyproject.toml` (`[tool.pytest.ini_options]` 에 `pythonpath = ["."]`)
- Test: `tests/test_verify_tools.py`

**Interfaces:**
- `snapshot.prepare_snapshot(repo, sha, scratch_root, *, run=subprocess.run) -> Path` — `<scratch_root>/<sha>/repo` 가 있으면 재사용, 없으면 `git clone --local --no-checkout <repo> <dest>` + `git -C <dest> checkout --detach <sha>`.
- `snapshot.isolated_env(scratch_root, sha, base: dict | None = None) -> dict` — 크리덴셜 키 제거 + `GRADLE_USER_HOME`.
- `evidence.redact_gitleaks(payload: str) -> str` — `Secret`·`Match` → `"<redacted>"`.
- `evidence.tool_versions(*, run=subprocess.run) -> dict[str, str]`.
- `evidence.write_evidence(out_dir, *, result: ScanResult, trace: TraceSink | None, meta: dict) -> list[Path]` — `raw/<tool>.json|sarif`, `findings.json`, `findings.sarif`, `report.md`, `trace.json`, `meta.json`.
- `run_snapshot.main(argv) -> int` — CLI.

- [ ] **Step 1: pytest 가 `tools` 를 import 하도록 설정**

`pyproject.toml` 의 `[tool.pytest.ini_options]` 를 다음으로 교체:

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-q"
pythonpath = ["."]
```

빈 `tools/__init__.py`, `tools/verify/__init__.py` 생성.

- [ ] **Step 2: 실패하는 테스트 작성 (`tests/test_verify_tools.py`)**

```python
"""tools/verify — 스냅샷 격리·증거 작성기(부수효과는 runner 주입으로 결정적 검증)."""

import json
from pathlib import Path

from secscan.adapters.base import FAILED, OK, RawResult
from secscan.scan import ScanResult, TraceSink
from tools.verify.evidence import redact_gitleaks, tool_versions, write_evidence
from tools.verify.snapshot import isolated_env, prepare_snapshot

GOLDEN = Path(__file__).parent / "golden"


def test_prepare_snapshot_clones_local_and_checks_out(tmp_path):
    calls = []

    def fake_run(argv, **kw):
        calls.append(argv)
        if argv[:2] == ["git", "clone"]:
            Path(argv[-1]).mkdir(parents=True)
        class R: returncode = 0
        return R()

    dest = prepare_snapshot(Path("/repo"), "abc123", tmp_path, run=fake_run)
    assert dest == tmp_path / "abc123" / "repo"
    assert calls[0] == ["git", "clone", "--local", "--no-checkout", "/repo", str(dest)]
    assert calls[1] == ["git", "-C", str(dest), "checkout", "--detach", "abc123"]
    # 두 번째 호출은 재사용(clone 없음)
    calls.clear()
    prepare_snapshot(Path("/repo"), "abc123", tmp_path, run=fake_run)
    assert calls == []


def test_isolated_env_strips_credentials_and_sets_gradle_home(tmp_path):
    base = {"PATH": "/bin", "GITHUB_TOKEN": "x", "AWS_SECRET_ACCESS_KEY": "y",
            "DB_PASSWORD": "z", "MY_API_KEY": "k", "HOME": "/h", "JAVA_HOME": "/j"}
    env = isolated_env(tmp_path, "abc123", base)
    assert "GITHUB_TOKEN" not in env and "AWS_SECRET_ACCESS_KEY" not in env
    assert "DB_PASSWORD" not in env and "MY_API_KEY" not in env
    assert env["PATH"] == "/bin" and env["JAVA_HOME"] == "/j"
    assert env["GRADLE_USER_HOME"] == str(tmp_path / "abc123" / "gradle-home")
    assert env["SECSCAN_VERIFY_ISOLATED"] == "1"


def test_redact_gitleaks_blanks_secret_and_match():
    payload = (GOLDEN / "gitleaks-secret-app.json").read_text()
    out = json.loads(redact_gitleaks(payload))
    assert out and all(x["Secret"] == "<redacted>" and x["Match"] == "<redacted>" for x in out)
    assert all(x["File"] and x["RuleID"] for x in out)  # 위치·룰은 보존
    for x in json.loads(payload):
        assert x["Secret"] not in redact_gitleaks(payload)


def test_tool_versions_uses_runner():
    def fake_run(argv, **kw):
        class R:
            returncode = 0
            stdout = f"{argv[0]} 9.9.9\n"
            stderr = ""
        return R()
    v = tool_versions(run=fake_run)
    assert v["trivy"] == "trivy 9.9.9" and "java" in v and "semgrep" in v


def test_write_evidence_layout_and_redaction(tmp_path):
    trivy = (GOLDEN / "trivy-vuln-maven-app.json").read_text()
    gitleaks = (GOLDEN / "gitleaks-secret-app.json").read_text()
    from secscan.normalize import to_findings
    raws = [RawResult("trivy", OK, payload=trivy), RawResult("gitleaks", OK, payload=gitleaks),
            RawResult("semgrep", FAILED, error="exit 2")]
    findings = to_findings(raws)
    result = ScanResult(findings, raws, partial_failures=[raws[2]])
    sink = TraceSink(); sink.record("final", findings)
    written = write_evidence(tmp_path, result=result, trace=sink,
                             meta={"snapshot": "abc", "profile": "standard"})
    names = {p.relative_to(tmp_path).as_posix() for p in written}
    assert {"raw/trivy.json", "raw/gitleaks.json", "findings.json", "findings.sarif",
            "report.md", "trace.json", "meta.json"} <= names
    assert "raw/semgrep.json" not in names  # 실패 도구는 payload 없음 → 미저장
    secret_values = {x["Secret"] for x in json.loads(gitleaks)}
    for p in written:
        text = p.read_text()
        assert not any(s in text for s in secret_values), p
    meta = json.loads((tmp_path / "meta.json").read_text())
    assert meta["snapshot"] == "abc"
    assert meta["scanner_status"] == [{"tool": "trivy", "status": "ok"},
                                      {"tool": "gitleaks", "status": "ok"},
                                      {"tool": "semgrep", "status": "failed", "error": "exit 2"}]
```

- [ ] **Step 3: 실패 확인**

Run: `.venv/bin/pytest tests/test_verify_tools.py -q`
Expected: FAIL — `ModuleNotFoundError: tools.verify.evidence`

- [ ] **Step 4: `tools/verify/snapshot.py`**

```python
"""스냅샷 격리 — message-gate 커밋을 새 디렉토리에 꺼내고 크리덴셜 없는 환경을 만든다(spec §4.1).

빌드(cdxgen/gradle/spotbugs)는 임의 코드 실행이므로 "read-only" 가 아니라 "격리 실행"이다.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

_CRED_RE = re.compile(r"(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API_KEY|^AWS_|^GITHUB_|^GH_)", re.IGNORECASE)


def prepare_snapshot(repo: Path, sha: str, scratch_root: Path, *, run=subprocess.run) -> Path:
    dest = Path(scratch_root) / sha / "repo"
    if dest.exists():
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    r = run(["git", "clone", "--local", "--no-checkout", str(repo), str(dest)],
            capture_output=True, text=True)
    if getattr(r, "returncode", 1) != 0:
        raise RuntimeError(f"git clone 실패: {getattr(r, 'stderr', '')}")
    r = run(["git", "-C", str(dest), "checkout", "--detach", sha], capture_output=True, text=True)
    if getattr(r, "returncode", 1) != 0:
        raise RuntimeError(f"git checkout {sha} 실패: {getattr(r, 'stderr', '')}")
    return dest


def isolated_env(scratch_root: Path, sha: str, base: dict | None = None) -> dict:
    src = dict(os.environ if base is None else base)
    env = {k: v for k, v in src.items() if not _CRED_RE.search(k)}
    env["GRADLE_USER_HOME"] = str(Path(scratch_root) / sha / "gradle-home")
    env["GRADLE_OPTS"] = "-Dorg.gradle.daemon=false"
    env["SECSCAN_VERIFY_ISOLATED"] = "1"
    return env
```

- [ ] **Step 5: `tools/verify/evidence.py`**

```python
"""증거 동결 — raw 출력(비밀값 제거)·findings.json·SARIF·md·trace·meta 를 한 디렉토리에(spec §4.4)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from secscan.output.json_io import to_json
from secscan.output.markdown import to_markdown
from secscan.output.sarif import to_sarif

_VERSION_CMDS = {
    "trivy": ["trivy", "--version"],
    "cdxgen": ["cdxgen", "--version"],
    "semgrep": ["semgrep", "--version"],
    "gitleaks": ["gitleaks", "version"],
    "depscan": ["depscan", "--version"],
    "spotbugs": ["spotbugs", "-version"],
    "java": ["java", "-version"],
    "gradle": ["gradle", "--version"],
}


def redact_gitleaks(payload: str) -> str:
    try:
        data = json.loads(payload or "[]")
    except json.JSONDecodeError:
        return "[]"
    for x in data or []:
        for k in ("Secret", "Match"):
            if k in x:
                x[k] = "<redacted>"
    return json.dumps(data, indent=2, ensure_ascii=False)


def tool_versions(*, run=subprocess.run) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, argv in _VERSION_CMDS.items():
        try:
            r = run(argv, capture_output=True, text=True, timeout=30)
            text = (r.stdout or "") + (r.stderr or "")
            out[name] = " ".join(text.split())[:200] or f"exit {r.returncode}"
        except Exception as e:  # 미설치 등
            out[name] = f"unavailable: {type(e).__name__}"
    return out


def write_evidence(out_dir, *, result, trace, meta: dict) -> list[Path]:
    out = Path(out_dir)
    (out / "raw").mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for r in result.raw_results:
        if not r.payload:
            continue
        ext = "sarif" if r.format == "sarif" else "json"
        p = out / "raw" / f"{r.tool}.{ext}"
        text = redact_gitleaks(r.payload) if r.tool == "gitleaks" else r.payload
        p.write_text(text, encoding="utf-8"); written.append(p)
    p = out / "findings.json"
    p.write_text(to_json(result.findings, meta=meta), encoding="utf-8"); written.append(p)
    p = out / "findings.sarif"
    p.write_text(json.dumps(to_sarif(result.findings), indent=2, ensure_ascii=False), encoding="utf-8")
    written.append(p)
    p = out / "report.md"
    p.write_text(to_markdown(result.findings, target=meta.get("snapshot"),
                             meta={"scanners": [r.tool for r in result.raw_results]}), encoding="utf-8")
    written.append(p)
    p = out / "trace.json"
    p.write_text(json.dumps(trace.to_dict() if trace else {}, indent=2, ensure_ascii=False), encoding="utf-8")
    written.append(p)
    full_meta = dict(meta)
    full_meta["scanner_status"] = [
        {"tool": r.tool, "status": r.status, **({"error": r.error} if r.error else {})}
        for r in result.raw_results
    ]
    full_meta["reachability"] = {"ran": result.reachability_ran, "reason": result.reachability_reason}
    full_meta["secret_policy"] = result.secret_policy
    full_meta["excluded_count"] = result.excluded_count
    p = out / "meta.json"
    p.write_text(json.dumps(full_meta, indent=2, ensure_ascii=False), encoding="utf-8"); written.append(p)
    return written
```

- [ ] **Step 6: `tools/verify/run_snapshot.py` (CLI, 테스트는 인자 파서만)**

```python
"""스냅샷 1개 실스캔 + 증거 동결.

사용: python -m tools.verify.run_snapshot --repo <message-gate> --sha a483b3b1 \
        --profile standard --scratch /tmp/secscan-verify --out docs/verification/evidence/2026-09-05/a483b3b1
네트워크: 의존성 다운로드(cdxgen/gradle)만. 시크릿 검증은 항상 never.
"""

from __future__ import annotations

import argparse
import json
import os
import resource
import time
from datetime import date
from pathlib import Path

from secscan.cli import count_source_loc, reachability_env_ok, source_hash
from secscan.profiles import build_adapters, get_profile
from secscan.reachability.depscan import DepscanUsageProvider
from secscan.reachability.engine import Budget
from secscan.scan import TraceSink, run_scan

from .evidence import tool_versions, write_evidence
from .snapshot import isolated_env, prepare_snapshot


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tools.verify.run_snapshot")
    p.add_argument("--repo", required=True)
    p.add_argument("--sha", required=True)
    p.add_argument("--profile", default="standard")
    p.add_argument("--scratch", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--no-reachability", action="store_true")
    p.add_argument("--allow-large", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    scratch = Path(args.scratch)
    os.environ.update(isolated_env(scratch, args.sha))  # 이후 subprocess 전부 상속
    repo_dir = prepare_snapshot(Path(args.repo), args.sha, scratch)

    profile = get_profile(args.profile)
    adapters = build_adapters(profile)
    provider, env_ok = None, (lambda: True)
    if profile.reachability and not args.no_reachability:
        provider = DepscanUsageProvider(scratch / args.sha / "reach" / source_hash(repo_dir))
        env_ok = reachability_env_ok

    sink = TraceSink()
    t0 = time.perf_counter()
    result = run_scan(
        repo_dir, profile, adapters=adapters, reachability_provider=provider, env_ok=env_ok,
        count_loc=count_source_loc, budget=Budget(allow_large=args.allow_large),
        secret_policy="never", secret_runner=None,
        today=date.today().isoformat(), trace=sink,
    )
    elapsed = time.perf_counter() - t0
    rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    meta = {
        "snapshot": args.sha, "repo": str(args.repo), "profile": args.profile,
        "run_date": date.today().isoformat(), "elapsed_s": round(elapsed, 1),
        "children_max_rss_bytes": rss, "tool_versions": tool_versions(),
        "isolated": {"gradle_user_home": os.environ["GRADLE_USER_HOME"], "secret_policy": "never"},
    }
    written = write_evidence(args.out, result=result, trace=sink, meta=meta)
    print(json.dumps({"written": [str(p) for p in written], "findings": len(result.findings),
                      "partial": [r.tool for r in result.partial_failures], "elapsed_s": meta["elapsed_s"]},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

`tests/test_verify_tools.py` 끝에 파서 테스트 추가:

```python
def test_run_snapshot_parser_defaults():
    from tools.verify.run_snapshot import build_parser
    a = build_parser().parse_args(["--repo", "/r", "--sha", "abc", "--scratch", "/s", "--out", "/o"])
    assert a.profile == "standard" and a.no_reachability is False
```

- [ ] **Step 7: 통과 확인 + 전체 회귀**

Run: `.venv/bin/pytest -q`
Expected: 전부 PASS

- [ ] **Step 8: 커밋**

```bash
git add pyproject.toml tools tests/test_verify_tools.py
git commit -m "feat(V1): tools/verify — 스냅샷 격리(clone --local·크리덴셜 제거·GRADLE_USER_HOME) + 증거 동결(gitleaks 비밀값 제거) + run_snapshot CLI

다음: V1 증거 동결 실행(a483b3b1 standard/deep, GT-A 스냅샷)"
```

---

### Task 6: V1 증거 동결 실행 (실스캔, 네트워크·빌드 필요)

**Files:**
- Create: `docs/verification/evidence/<YYYY-MM-DD>/<sha>/...` (Task 5 산출물)
- Create: `docs/verification/evidence/<YYYY-MM-DD>/README.md`

이 태스크는 테스트가 아니라 **실행 기록**이다. 실패한 스캐너는 `meta.json` 의 `scanner_status` 에 남기고 계속 진행한다(부분 실패 정상). 각 실행은 Bash `dangerouslyDisableSandbox=true` 가 필요하다(네트워크·빌드).

- [ ] **Step 1: 사전 점검**

```bash
.venv/bin/secscan doctor
ls /Users/picpal/Desktop/workspace/message-gate/gradlew
git -C /Users/picpal/Desktop/workspace/message-gate rev-parse a483b3b1 29bfb5ba d4a1ded0 1052b80d 72e49a1b 55e58bc6 8428e646 5895c9f4 81f4f31b
```
Expected: doctor 정상, 9개 SHA 전부 해석.

- [ ] **Step 2: 스크래치·증거 디렉토리 정의**

```bash
export VDATE=$(date +%F)
export SCRATCH=/private/tmp/secscan-verify   # 스냅샷별 하위 디렉토리가 자동 생성됨
export EVD=docs/verification/evidence/$VDATE
mkdir -p $EVD
```

- [ ] **Step 3: GT-B 스냅샷 standard (bom-sca + semgrep + gitleaks + 도달성)**

```bash
.venv/bin/python -m tools.verify.run_snapshot --repo /Users/picpal/Desktop/workspace/message-gate \
  --sha a483b3b1 --profile standard --scratch $SCRATCH --out $EVD/a483b3b1-standard --allow-large
```
Expected: `findings.json` 생성, trivy(bom) status ok, findings 수십 건. 도달성이 `size`/`timeout` 으로 스킵되면 `meta.json` 에 사유가 남는다 — 그대로 기록.

- [ ] **Step 4: GT-B 스냅샷 deep (spotbugs 추가, 빌드)**

```bash
.venv/bin/python -m tools.verify.run_snapshot --repo /Users/picpal/Desktop/workspace/message-gate \
  --sha a483b3b1 --profile deep --scratch $SCRATCH --out $EVD/a483b3b1-deep --allow-large --no-reachability
```
Expected: spotbugs status ok 또는 skipped(빌드 실패). 실패 시 `meta.json` 의 error 확인만 하고 진행.

- [ ] **Step 5: GT-A 취약/수정 스냅샷 (standard, 도달성 생략 — SAST/secret 목적)**

```bash
for sha in 29bfb5ba d4a1ded0 1052b80d 72e49a1b 55e58bc6 8428e646 5895c9f4 81f4f31b; do
  .venv/bin/python -m tools.verify.run_snapshot --repo /Users/picpal/Desktop/workspace/message-gate \
    --sha $sha --profile standard --scratch $SCRATCH --out $EVD/$sha-standard --no-reachability
done
```
Expected: 8개 디렉토리. bom-sca 는 스냅샷마다 cdxgen 을 다시 돌리므로 시간이 걸린다(스냅샷별 새 경로 → 캐시 미공유가 의도).

- [ ] **Step 6: 비밀값 누출 검사**

```bash
grep -rl '"Secret": "<redacted>"' $EVD | wc -l
grep -rn -i 'BEGIN .*PRIVATE KEY' $EVD || echo "no private key material"
```
Expected: gitleaks raw 파일 수만큼 redacted, private key 본문 없음. 있으면 해당 파일에서 값을 제거하고 `evidence.py` 의 redaction 을 보강한 뒤 재실행.

- [ ] **Step 7: README + 커밋**

`$EVD/README.md`:

```markdown
# 증거 동결 <YYYY-MM-DD> — 현행 바이너리(커밋 <git rev-parse --short HEAD>)

| 디렉토리 | 스냅샷 | 프로파일 | 스캐너 status | findings | 비고 |
|---|---|---|---|---|---|
| a483b3b1-standard | GT-B 취약 | standard | (meta.json 에서 전사) | N | 도달성 사유: … |
| a483b3b1-deep | GT-B 취약 | deep | … | N | spotbugs … |
| 29bfb5ba-standard | GT-A CWE-259·489 취약 | standard | … | N | |
| … | | | | | |

- 도구 버전: meta.json `tool_versions` 참조. trivy DB 시점: `trivy --version` 출력의 UpdatedAt.
- 격리: 스냅샷별 `<scratch>/<sha>/`, GRADLE_USER_HOME 분리, 크리덴셜 환경변수 제거, secret 검증 never.
- 이 증거는 V4(모델 변경) 이후 회귀 입력으로 재사용한다(spec §4.4).
```

```bash
git add docs/verification/evidence
git commit -m "docs(V1): 증거 동결 — a483b3b1 standard/deep + GT-A 스냅샷 8종 (현행 바이너리, 비밀값 제거)

다음: V2 SCA 측정(대조·mssql·초과분·입력면)"
```

---

### Task 7: 측정 리포트 렌더 + 프로파일 계약 + mssql 3단계

**Files:**
- Create: `tools/verify/report.py`, `tools/verify/profile_contract.py`, `tools/verify/known_fp.py`
- Test: `tests/test_verify_tools.py` (추가)

**Interfaces:**
- `report.render_attrition(trace: dict) -> str` (markdown 표)
- `report.render_match(report: MatchReport, classes: dict[str, str]) -> str`
- `report.render_human_verdicts(manifest: GtManifest, findings: list[Finding]) -> str`
- `report.published_dates(trivy_payload: str) -> dict[str, str]` (raw trivy JSON 의 `PublishedDate`)
- `report.main(argv)` CLI: `--evidence <dir> --gt <gt-b-sca.json> --out <md> [--facts <json>]` — `--facts` 는 `collect_facts(...)` 결과를 JSON 으로 저장.
- `report.collect_facts(report: MatchReport, classes: dict, findings, trace: dict, meta: dict) -> dict[str, str|int]` — 정본 수치(id → 값): `sca.recall_cve`("m/t"), `sca.recall_entry_strict`, `sca.recall_entry_loose`, `sca.missed`, `sca.missed_high_important`(severity_team 이 HIGH 또는 Important 인 미탐 수 — spec §5 축 2 게이트 "HIGH/Important 미탐 ≤ 1"; 보안팀 trivy 벤더 심각도와 개발자 추가분의 Tomcat 척도 Important/Moderate/Low 가 섞여 있음), `sca.false_positive`, `sca.extras`, `sca.extras.<class>`(4분류별), **`sca.extras.unclassified`**(항상 출력, 미분류 건수 — 0 이어도 인용 가능해야 함), `findings.total`, `findings.<category>`, `attrition.<stage>`, `scanner.<tool>`(status), `reach.<status>`(SCA 도달성 status 별 건수; 없음=`none`), **`sca.recall_cve.<origin>`**(origin 별 CVE 단위 recall "m/t" — `team`/`dev-found`; spec §5 축 2 도구 상관 편향 분리).
- `known_fp.render(result: dict) -> str` — `# known-FP CVE-2025-59250 (mssql-jdbc) 3단계` 제목 + `| 단계 | 결과 |` 표 전체 문서.
- `profile_contract.render_doc(statuses: dict[str, str]) -> str` — `# 프로파일 계약 (spec §8 vs 구현 vs 실제)` 제목 + `render(compare_profiles(), statuses)` 전체 문서.
- `profile_contract.SPEC_PROFILES: dict[str, frozenset[str]]`, `compare_profiles() -> list[dict]`, `render(rows, statuses: dict[str, str]) -> str`
- `known_fp.check_known_fp(bom_json: str, trivy_json: str, *, package, advisory, expected_version) -> dict` with keys `component_present`, `version_preserved`, `not_reported`, `found_version`.

- [ ] **Step 1: 실패하는 테스트 작성 (`tests/test_verify_tools.py` 끝에 추가)**

```python
# --- V2: 리포트·프로파일 계약·known-FP ---
from secscan.measure import GtEntry, GtManifest, match_ground_truth
from secscan.models import UNKNOWN, UNREACHABLE, Advisory, Component, Finding, Reachability
from tools.verify.known_fp import check_known_fp
from tools.verify.profile_contract import SPEC_PROFILES, compare_profiles, render as render_profiles
from tools.verify.report import published_dates, render_attrition, render_human_verdicts, render_match


def _sca(pkg, ver, cve, reach=UNKNOWN, evidence=None):
    return Finding(category="sca", severity="high", tool="trivy", rule_id=cve,
                   component=Component("maven", pkg, ver), advisory=Advisory(cve, aliases=(cve,)),
                   reachability=Reachability(reach, evidence=evidence))


def test_render_attrition_table_shows_stage_deltas():
    trace = {"raw": [{"tool": "trivy", "status": "ok", "bytes": 10}],
             "stages": [{"stage": "merge", "count": 5, "keys": []},
                        {"stage": "exclude", "count": 3, "keys": []},
                        {"stage": "final", "count": 3, "keys": []}]}
    md = render_attrition(trace)
    assert "| merge | 5 |" in md and "| exclude | 3 | -2 |" in md


def test_render_match_lists_recall_and_extra_classes():
    m = GtManifest("sca", "s", "2026-08-31", (GtEntry("CVE-1", "g:a", "1.0"), GtEntry("CVE-2", "g:b", "1.0")), [])
    r = match_ground_truth([_sca("g:a", "1.0", "CVE-1"), _sca("g:z", "1.0", "CVE-9")], m)
    md = render_match(r, {r.extras[0].dedup_key: "inventory-diff"})
    assert "CVE 단위 recall: 1/2" in md and "CVE-2" in md and "inventory-diff" in md


def test_render_human_verdicts_compares_reason_classes():
    m = GtManifest("sca", "s", "2026-08-31",
                   (GtEntry("CVE-T", "org.apache.tomcat.embed:tomcat-embed-core", "11.0.22",
                            human_verdict="unreachable", reason_class="config-gated", reason="HTTP/2 off"),), [])
    md = render_human_verdicts(m, [_sca("org.apache.tomcat.embed:tomcat-embed-core", "11.0.22", "CVE-T", UNREACHABLE)])
    assert "config-gated" in md and "unreachable" in md and "패키지 prefix" in md


def test_published_dates_from_trivy_json():
    payload = (GOLDEN / "trivy-vuln-maven-app.json").read_text()
    d = published_dates(payload)
    assert d["CVE-2022-42889"].startswith("2022-10")


def test_profile_contract_detects_bom_sca_vs_trivy_osv_drift():
    rows = compare_profiles()
    acc = next(r for r in rows if r["profile"] == "accurate-sca")
    assert acc["spec"] == sorted(SPEC_PROFILES["accurate-sca"])
    assert "osv-scanner" in acc["missing"]
    md = render_profiles(rows, {"trivy": "ok", "gitleaks": "ok"})
    assert "accurate-sca" in md and "osv-scanner" in md


def test_check_known_fp_three_stages():
    bom = json.dumps({"components": [{"purl": "pkg:maven/com.microsoft.sqlserver/mssql-jdbc@13.2.1.jre11",
                                      "group": "com.microsoft.sqlserver", "name": "mssql-jdbc", "version": "13.2.1.jre11"}]})
    trivy_clean = json.dumps({"Results": [{"Target": "bom.json", "Vulnerabilities": []}]})
    r = check_known_fp(bom, trivy_clean, package="com.microsoft.sqlserver:mssql-jdbc",
                       advisory="CVE-2025-59250", expected_version="13.2.1.jre11")
    assert r == {"component_present": True, "version_preserved": True, "not_reported": True,
                 "found_version": "13.2.1.jre11"}
    trivy_fp = json.dumps({"Results": [{"Target": "bom.json", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2025-59250", "PkgName": "com.microsoft.sqlserver:mssql-jdbc", "InstalledVersion": "13.2.1"}]}]})
    assert check_known_fp(bom, trivy_fp, package="com.microsoft.sqlserver:mssql-jdbc",
                          advisory="CVE-2025-59250", expected_version="13.2.1.jre11")["not_reported"] is False
```

- [ ] **Step 2: 실패 확인**

Run: `.venv/bin/pytest tests/test_verify_tools.py -q`
Expected: FAIL — `ModuleNotFoundError: tools.verify.known_fp`

- [ ] **Step 3: `tools/verify/known_fp.py`**

```python
"""known-FP 3단계 검사(spec §5 축 3): 컴포넌트 존재 → 버전 보존 → 비해당 판정."""

from __future__ import annotations

import json


def check_known_fp(bom_json: str, trivy_json: str, *, package: str, advisory: str,
                   expected_version: str) -> dict:
    group, _, name = package.partition(":")
    found = None
    for c in json.loads(bom_json or "{}").get("components", []) or []:
        purl = c.get("purl", "")
        if (c.get("group") == group and c.get("name") == name) or purl.startswith(f"pkg:maven/{group}/{name}@"):
            found = c.get("version") or purl.split("@", 1)[-1]
            break
    reported = False
    for res in json.loads(trivy_json or "{}").get("Results", []) or []:
        for v in res.get("Vulnerabilities") or []:
            if v.get("VulnerabilityID") == advisory and (v.get("PkgName") in (package, name)):
                reported = True
    return {
        "component_present": found is not None,
        "version_preserved": found == expected_version,
        "not_reported": not reported,
        "found_version": found,
    }
```

- [ ] **Step 4: `tools/verify/profile_contract.py`**

```python
"""프로파일 계약(spec §5 축 1): 원 spec §8 기대 어댑터 vs 구현 PROFILES + 실제 status."""

from __future__ import annotations

from secscan.profiles import PROFILES

# 원 spec 2026-06-26 §8. bom-sca 는 "trivy(BOM)" 로 간주해 trivy 로 정규화한다.
SPEC_PROFILES: dict[str, frozenset[str]] = {
    "quick": frozenset({"trivy", "gitleaks"}),
    "accurate-sca": frozenset({"trivy", "osv-scanner"}),
    "standard": frozenset({"semgrep", "trivy", "osv-scanner", "gitleaks"}),
    "deep": frozenset({"semgrep", "trivy", "osv-scanner", "gitleaks", "spotbugs"}),
}
_ALIAS = {"bom-sca": "trivy"}


def compare_profiles() -> list[dict]:
    rows = []
    for name, spec in SPEC_PROFILES.items():
        impl = {_ALIAS.get(a, a) for a in PROFILES[name].adapter_names} if name in PROFILES else set()
        rows.append({"profile": name, "spec": sorted(spec), "impl": sorted(impl),
                     "missing": sorted(spec - impl), "extra": sorted(impl - spec),
                     "reachability": PROFILES[name].reachability if name in PROFILES else None})
    return rows


def render(rows: list[dict], statuses: dict[str, str]) -> str:
    L = ["| 프로파일 | spec §8 | 구현 | 누락 | 초과 | 실제 status |", "|---|---|---|---|---|---|"]
    for r in rows:
        st = ", ".join(f"{a}={statuses.get(a, '-')}" for a in r["impl"])
        L.append(f"| {r['profile']} | {', '.join(r['spec'])} | {', '.join(r['impl'])} | "
                 f"{', '.join(r['missing']) or '-'} | {', '.join(r['extra']) or '-'} | {st} |")
    return "\n".join(L)
```

- [ ] **Step 5: `tools/verify/report.py`**

```python
"""측정 리포트 렌더 — attrition·정답지 대조·사람 도달성 판정 비교(spec §4.2·§4.3·§5 축 6a)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from secscan.measure import GtManifest, MatchReport, classify_extras, load_gt_manifest, match_ground_truth
from secscan.models import Finding
from secscan.output.json_io import from_json

OUR_METHOD = "패키지 prefix 존재(atom usage 슬라이스에 해당 타입 호출 유무)"


def render_attrition(trace: dict) -> str:
    L = ["| 단계 | 건수 | 증감 |", "|---|---|---|"]
    prev = None
    for s in trace.get("stages", []):
        delta = "" if prev is None else f"{s['count'] - prev:+d}"
        L.append(f"| {s['stage']} | {s['count']} | {delta} |")
        prev = s["count"]
    raw = ", ".join(f"{r['tool']}={r['status']}({r['bytes']}B)" for r in trace.get("raw", []))
    return f"raw: {raw}\n\n" + "\n".join(L)


def render_match(report: MatchReport, classes: dict[str, str]) -> str:
    c_hit, c_tot = report.recall_cve()
    e_hit, e_tot = report.recall_entry(strict=True)
    e_len, _ = report.recall_entry(strict=False)
    by_o = " · ".join(f"{o} {h}/{t}" for o, (h, t) in sorted(recall_by_origin(report).items()))
    L = [f"- CVE 단위 recall(GT-B 합산): {c_hit}/{c_tot}",
         f"- origin 별 CVE recall: {by_o} (team = 보안팀 trivy 결과 재현율 성격, dev-found = 독립 증거 — spec §5 축 2)",
         f"- 항목 단위 recall: strict {e_hit}/{e_tot} · version-mismatch 포함 {e_len}/{e_tot}",
         f"- 종류별: {report.by_kind()}", ""]
    if report.missed():
        L += ["### 미탐", "| advisory | 패키지 | 설치 | 심각도(보안팀) | origin |", "|---|---|---|---|---|"]
        for m in report.missed():
            e = m.entry
            L.append(f"| {e.advisory} | {e.package} | {e.installed} | {e.severity_team or '-'} | {e.origin} |")
        L.append("")
    if report.false_positives():
        L += ["### known-FP 재현(치명)", *(f"- {m.entry.advisory} {m.entry.package} → 보고됨(버전 {m.got_version})"
                                          for m in report.false_positives()), ""]
    vm = [m for m in report.matches if m.kind == "version-mismatch"]
    if vm:
        L += ["### 버전 표기 불일치", *(f"- {m.entry.advisory} {m.entry.package}: 기대 {m.entry.installed} / 실제 {m.got_version}" for m in vm), ""]
    if report.extras:
        L += ["### 초과 탐지", "| advisory | 패키지 | 설치 | 분류 |", "|---|---|---|---|"]
        for f in sorted(report.extras, key=lambda x: x.dedup_key):
            L.append(f"| {f.advisory.id} | {f.component.package} | {f.component.version} | {classes.get(f.dedup_key, '미분류')} |")
    return "\n".join(L)


def render_human_verdicts(manifest: GtManifest, findings: list[Finding]) -> str:
    by = {}
    for f in findings:
        if f.component and f.advisory:
            for i in (f.advisory.id, *f.advisory.aliases):
                by[(i, f.component.package)] = f
    L = ["| advisory | 패키지 | 사람 판정 | 사람 근거 분류 | 우리 판정 | 우리 근거 | 판정 방법 차이 |",
         "|---|---|---|---|---|---|---|"]
    for e in manifest.entries:
        if not e.human_verdict:
            continue
        f = by.get((e.advisory, e.package))
        ours = f.reachability.status if f else "미탐"
        ev = (f.reachability.evidence or "-") if f else "-"
        L.append(f"| {e.advisory} | {e.package} | {e.human_verdict} | {e.reason_class} ({e.reason}) | {ours} | {ev} | 사람=CVE 전제조건 / 우리={OUR_METHOD} |")
    return "\n".join(L)


def published_dates(trivy_payload: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for res in json.loads(trivy_payload or "{}").get("Results", []) or []:
        for v in res.get("Vulnerabilities") or []:
            if v.get("VulnerabilityID") and v.get("PublishedDate"):
                out[v["VulnerabilityID"]] = v["PublishedDate"][:10]
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="tools.verify.report")
    p.add_argument("--evidence", required=True)
    p.add_argument("--gt", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--facts", default=None, help="정본 수치 JSON 출력 경로(spec §4.5)")
    a = p.parse_args(argv)
    ev = Path(a.evidence)
    findings = from_json((ev / "findings.json").read_text(encoding="utf-8"))
    trace = json.loads((ev / "trace.json").read_text(encoding="utf-8"))
    meta = json.loads((ev / "meta.json").read_text(encoding="utf-8")) if (ev / "meta.json").exists() else {}
    manifest = load_gt_manifest(a.gt)
    report = match_ground_truth(findings, manifest)
    raw_trivy = ev / "raw" / "trivy.json"
    dates = published_dates(raw_trivy.read_text(encoding="utf-8")) if raw_trivy.exists() else {}
    classes = classify_extras(report.extras, manifest, dates)
    md = "\n\n".join([
        f"# 대조 — {ev.name} vs {Path(a.gt).name}",
        "## 단계별 attrition", render_attrition(trace),
        "## 정답지 대조", render_match(report, classes),
        "## 사람 도달성 판정 비교(일치율 산출 안 함 — 방법이 다름)", render_human_verdicts(manifest, findings),
    ])
    Path(a.out).write_text(md, encoding="utf-8")
    if a.facts:
        Path(a.facts).write_text(json.dumps(collect_facts(report, classes, findings, trace, meta),
                                            ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(a.out)
    return 0


def recall_by_origin(report: MatchReport) -> dict[str, tuple[int, int]]:
    """origin(team/dev-found) 별 CVE 단위 recall — team 은 보안팀 trivy 재현율 성격(spec §5 축 2)."""
    hit_kinds = {"exact", "alias", "version-mismatch"}
    acc: dict[str, tuple[set, set]] = {}
    for m in report.matches:
        if m.entry.expected != "present":
            continue
        tot, hit = acc.setdefault(m.entry.origin, (set(), set()))
        tot.add(m.entry.advisory)
        if m.kind in hit_kinds:
            hit.add(m.entry.advisory)
    return {o: (len(h), len(t)) for o, (t, h) in acc.items()}


def collect_facts(report: MatchReport, classes: dict[str, str], findings: list[Finding],
                  trace: dict, meta: dict) -> dict:
    """정본 수치(spec §4.5). 문서는 이 값을 `<!-- fact:id -->` 마커와 함께 인용만 한다."""
    from collections import Counter
    c_hit, c_tot = report.recall_cve()
    s_hit, e_tot = report.recall_entry(strict=True)
    l_hit, _ = report.recall_entry(strict=False)
    facts: dict = {
        "sca.recall_cve": f"{c_hit}/{c_tot}",
        "sca.recall_entry_strict": f"{s_hit}/{e_tot}",
        "sca.recall_entry_loose": f"{l_hit}/{e_tot}",
        "sca.missed": len(report.missed()),
        "sca.missed_high_important": sum(1 for m in report.missed()
                                          if (m.entry.severity_team or "").upper() in ("HIGH", "IMPORTANT")),
        "sca.false_positive": len(report.false_positives()),
        "sca.extras": len(report.extras),
        "findings.total": len(findings),
    }
    for cls, n in sorted(Counter(classes.get(f.dedup_key, "미분류") for f in report.extras).items()):
        facts[f"sca.extras.{cls}"] = n
    facts["sca.extras.unclassified"] = sum(1 for f in report.extras if f.dedup_key not in classes)
    for origin, (hit, tot) in sorted(recall_by_origin(report).items()):
        facts[f"sca.recall_cve.{origin}"] = f"{hit}/{tot}"
    for cat, n in sorted(Counter(f.category for f in findings).items()):
        facts[f"findings.{cat}"] = n
    for s in trace.get("stages", []):
        facts[f"attrition.{s['stage']}"] = s["count"]
    for s in meta.get("scanner_status", []):
        facts[f"scanner.{s['tool']}"] = s["status"]
    for st, n in sorted(Counter((f.reachability.status if f.reachability else "none")
                                for f in findings if f.category == "sca").items()):
        facts[f"reach.{st}"] = n
    return facts


if __name__ == "__main__":
    raise SystemExit(main())
```

`tools/verify/known_fp.py` 끝에 추가:

```python
def render(result: dict) -> str:
    """known-FP 3단계 문서(생성기 — reconcile 이 같은 함수로 재생성해 비교한다)."""
    rows = "\n".join(f"| {k} | {v} |" for k, v in result.items())
    return "# known-FP CVE-2025-59250 (mssql-jdbc) 3단계\n\n| 단계 | 결과 |\n|---|---|\n" + rows + "\n"
```

`tools/verify/profile_contract.py` 끝에 추가:

```python
def render_doc(statuses: dict[str, str]) -> str:
    """프로파일 계약 문서(생성기 — reconcile 재생성 비교 대상)."""
    return "# 프로파일 계약 (spec §8 vs 구현 vs 실제)\n\n" + render(compare_profiles(), statuses) + "\n"
```

`tests/test_verify_tools.py` 에 추가:

```python
def test_collect_facts_ids_and_values():
    from tools.verify.report import collect_facts
    m = GtManifest("gt-b-sca", "a483b3b1", "2026-08-31", entries=(
        GtEntry("CVE-1", "g:a", "1.0", "present", "team", 1, severity_team="HIGH"),
        GtEntry("CVE-2", "g:b", "1.0", "present", "team", 2),), raw_entries=())
    fs = [_sca("g:a", "1.0", "CVE-1"), _sca("g:z", "9.9", "CVE-9")]
    rep = match_ground_truth(fs, m)
    facts = collect_facts(rep, {fs[1].dedup_key: "inventory-diff"}, fs,
                          {"stages": [{"stage": "merge", "count": 2}, {"stage": "final", "count": 2}]},
                          {"scanner_status": [{"tool": "trivy", "status": "ok"}]})
    assert facts["sca.recall_cve"] == "1/2" and facts["sca.missed"] == 1 and facts["sca.missed_high_important"] == 0
    assert facts["sca.extras"] == 1 and facts["sca.extras.inventory-diff"] == 1 and facts["sca.extras.unclassified"] == 0
    assert facts["attrition.final"] == 2 and facts["scanner.trivy"] == "ok" and facts["findings.sca"] == 2
    assert facts["sca.recall_cve.team"] == "1/2" and "sca.recall_cve.dev-found" not in facts


def test_known_fp_render_and_profile_render_doc_are_full_docs():
    from tools.verify.known_fp import render as render_fp
    from tools.verify.profile_contract import render_doc
    fp = render_fp({"component_present": True, "version_preserved": True, "not_reported": True, "found_version": "13.2.1.jre11"})
    assert fp.startswith("# known-FP CVE-2025-59250") and "| not_reported | True |" in fp
    doc = render_doc({"trivy": "ok"})
    assert doc.startswith("# 프로파일 계약") and "standard" in doc
```

- [ ] **Step 6: 통과 확인**

Run: `.venv/bin/pytest tests/test_verify_tools.py -q`
Expected: PASS

- [ ] **Step 7: 커밋**

```bash
git add tools/verify/report.py tools/verify/profile_contract.py tools/verify/known_fp.py tests/test_verify_tools.py
git commit -m "feat(V2): 측정 리포트(attrition·대조·사람판정 비교) + 프로파일 계약 검사 + known-FP 3단계

다음: V2 실측 — GT-B 대조·mssql·초과분 분류"
```

---

### Task 8: V2 실측 — SCA 대조·mssql·초과분 (증거 기반, 결정적)

**Files:**
- Create: `docs/verification/results/<YYYY-MM-DD>/gt-b-match.md`, `known-fp.md`, `profile-contract.md`, `extras-triage.json`

- [ ] **Step 0: BOM 을 증거에 보존 (known-FP 재현성 — 캐시는 tmp 라 사라진다)**

```bash
export VDATE=<Task 6 의 날짜>; export EVD=docs/verification/evidence/$VDATE; export RES=docs/verification/results/$VDATE; mkdir -p $RES
export SCRATCH=/private/tmp/secscan-verify
cp "$(.venv/bin/python -c 'from pathlib import Path; from secscan.sbom import bom_cache_path; print(bom_cache_path(Path("/private/tmp/secscan-verify/a483b3b1/repo")))')" $EVD/a483b3b1-standard/raw/bom.cdx.json
.venv/bin/python -c "import json,sys; d=json.load(open('$EVD/a483b3b1-standard/raw/bom.cdx.json')); print('components', len(d['components']))"
git add $EVD/a483b3b1-standard/raw/bom.cdx.json
git commit -m "docs(V1): 증거에 cdxgen BOM 보존(a483b3b1) — known-FP 3단계·입력면 재생성용

다음: V2 대조 리포트"
```
Expected: components 196.

- [ ] **Step 1: 대조 리포트 + 정본 수치 생성**

```bash
.venv/bin/python -m tools.verify.report --evidence $EVD/a483b3b1-standard \
  --gt docs/verification/ground-truth/gt-b-sca.json --out $RES/gt-b-match.md --facts $RES/facts.json
```
Expected: `gt-b-match.md` 에 CVE 단위 recall `N/46`, 미탐 표, 초과분 표. `facts.json` 에 `sca.recall_cve` 등 정본 수치. **이 두 파일은 손으로 고치지 않는다.**

- [ ] **Step 2: known-FP 3단계 (생성기 함수만 사용)**

```bash
.venv/bin/python - <<'EOF'
import os
from pathlib import Path
from tools.verify.known_fp import check_known_fp, render
evd = Path(os.environ["EVD"]) / "a483b3b1-standard"
r = check_known_fp((evd / "raw" / "bom.cdx.json").read_text(), (evd / "raw" / "trivy.json").read_text(),
                   package="com.microsoft.sqlserver:mssql-jdbc", advisory="CVE-2025-59250",
                   expected_version="13.2.1.jre11")
Path(os.environ["RES"], "known-fp.md").write_text(render(r), encoding="utf-8")
print(r)
EOF
```
Expected: 세 값 모두 True 가 게이트. False 가 있으면 어느 단계인지 그대로 기록(예: cdxgen 이 `.jre11` 을 잃으면 `version_preserved=False`). 결과를 해석하거나 고치지 않는다.

- [ ] **Step 3: 프로파일 계약 (생성기 함수만 사용)**

```bash
.venv/bin/python - <<'EOF'
import json, os
from pathlib import Path
from tools.verify.profile_contract import render_doc
meta = json.loads((Path(os.environ["EVD"]) / "a483b3b1-deep" / "meta.json").read_text())
statuses = {s["tool"]: s["status"] for s in meta["scanner_status"]}
Path(os.environ["RES"], "profile-contract.md").write_text(render_doc(statuses), encoding="utf-8")
EOF
```

- [ ] **Step 4: 초과분 triage — 실행자는 판단하지 않는다 (spec §4.5)**

`$RES/extras-triage.json` 을 아래 형식으로 만든다. **`overrides` 는 항상 `[]`** — 자동 분류(`team-missed`/`db-drift`/`inventory-diff`/`unknown-date`)를 실행자가 덮어쓰는 것은 금지다(오탐 추론 금지). 자동 분류가 의심스러운 항목(예: 설치 버전이 advisory 영향 범위 밖으로 보이는 경우)은 `needs_human` 에 **질문 형태**로만 적는다. 사람이 확정하면 `overrides` 에 `provenance: "human:<이름>"` 과 함께 추가한다(이 플랜 범위 밖).

```json
{"@context": "secscan-extras-triage/v1", "evidence": "<EVD>/a483b3b1-standard",
 "overrides": [],
 "needs_human": [
   {"dedup_key": "sca|maven|<pkg>|<ver>|<CVE>", "auto_class": "team-missed",
    "question": "trivy 는 <ver> 를 영향 범위로 보는데 advisory 본문의 영향 범위와 일치하는지 확인 필요"}
 ]}
```
의심 항목이 없으면 `"needs_human": []`.

- [ ] **Step 5: 게이트 판정 기록(정본 인용만) + 커밋**

`$RES/gate-v2.md` 의 **모든 수치는 `facts.json` 의 값을 그대로 옮기고 옆에 `<!-- fact:<id> -->` 마커**를 단다. ✓/✗ 는 spec §5 게이트 기준을 수치에 기계적으로 적용한 결과이며(기준을 문장으로 함께 적음), 실행자의 해석을 덧붙이지 않는다. 예:

```markdown
# 게이트 V2 (정본: facts.json)

| 축 | 기준 | 측정값 | 판정 |
|---|---|---|---|
| 1 프로파일 계약 | 드리프트 전건 문서화 | profile-contract.md 행 수 N <!-- fact:profile.rows --> · 드리프트 M <!-- fact:profile.drift --> | ✓ (문서화됨) |
| 2 SCA recall | CVE 단위 GT-B 합산 ≥ 44/46, HIGH/Important 미탐 ≤ 1 (origin 별 병기 필수) | 합산 38/46 <!-- fact:sca.recall_cve --> · team 34/34 <!-- fact:sca.recall_cve.team --> · dev-found 4/12 <!-- fact:sca.recall_cve.dev-found --> · HIGH/Important 미탐 3 <!-- fact:sca.missed_high_important --> | ✗ → 백로그 P1 후보 |
| 3 known-FP | 3단계 모두 True | known-fp.md 참조 (component_present/version_preserved/not_reported) | ✓/✗ |
| 4 초과분 | 미분류 0 | 초과 7 <!-- fact:sca.extras --> · 미분류 0 <!-- fact:sca.extras.unclassified --> | ✓ |
```
(위 숫자는 형식 예시다 — 실제 값은 `facts.json` 에서 옮긴다. `profile.rows`/`profile.drift` 는 `profile-contract.md` 표에서 세어 `facts.json` 에 `facts-profile.json` 으로 별도 저장: `{"profile.rows": N, "profile.drift": M}` — 세는 스크립트 한 줄을 문서에 남긴다.)

```bash
git add docs/verification/results
git commit -m "docs(V2): GT-B 대조 실측 — CVE recall N/46, known-FP 3단계, 프로파일 계약, 초과분 triage

다음: V2 입력면 교차(jar vs BOM)"
```

---

### Task 9: 입력면 교차 실험 (jar `trivy rootfs` vs cdxgen BOM)

**Files:**
- Create: `tools/verify/jar_surface.py`
- Test: `tests/test_verify_tools.py` (추가)
- Create: `docs/verification/results/<date>/input-surface.md`

**Interfaces:**
- `inventory_from_bom(bom_json: str) -> dict[str, str]` (`group:artifact` → version)
- `inventory_from_trivy(trivy_json: str) -> dict[str, str]` (`Results[].Packages[]` 또는 `Vulnerabilities[]` 의 PkgName/InstalledVersion)
- `diff_inventories(a, b) -> dict` with `only_a`, `only_b`, `version_differs: dict[pkg, (va, vb)]`
- `compare_installed(inv: dict, manifest: GtManifest) -> list[dict]` — 정답지 설치버전 vs 인벤토리
- `render(diff, cmp_bom, cmp_jar) -> str`
- `render_doc(ok: bool, bom_json: str, jar_json: str, manifest: GtManifest) -> str` — 문서 전체(제목 포함). `main` 은 이 함수로만 md 를 만들고, `input-surface.status.json`(`{"jar_build_scan_ok": bool}`)을 함께 저장한다 — reconcile(Task 13)이 저장된 `input-surface.trivy-fs.json`·증거 `raw/bom.cdx.json`·status 로 같은 문서를 재생성해 비교한다.

- [ ] **Step 1: 실패하는 테스트 작성**

```python
# --- V2: 입력면 교차 ---
from tools.verify.jar_surface import compare_installed, diff_inventories, inventory_from_bom, inventory_from_trivy


def test_inventories_and_diff():
    bom = json.dumps({"components": [
        {"group": "g", "name": "a", "version": "1.0", "purl": "pkg:maven/g/a@1.0"},
        {"group": "g", "name": "b", "version": "2.0", "purl": "pkg:maven/g/b@2.0"}]})
    trivy = json.dumps({"Results": [{"Target": "Java", "Packages": [
        {"Name": "g:a", "Version": "1.0"}, {"Name": "g:c", "Version": "3.0"}],
        "Vulnerabilities": [{"PkgName": "g:b", "InstalledVersion": "2.0.jre11", "VulnerabilityID": "CVE-1"}]}]})
    ia, ib = inventory_from_bom(bom), inventory_from_trivy(trivy)
    assert ia == {"g:a": "1.0", "g:b": "2.0"}
    assert ib == {"g:a": "1.0", "g:c": "3.0", "g:b": "2.0.jre11"}
    d = diff_inventories(ia, ib)
    assert d["only_a"] == [] and d["only_b"] == ["g:c"]
    assert d["version_differs"] == {"g:b": ("2.0", "2.0.jre11")}


def test_compare_installed_against_manifest():
    m = GtManifest("sca", "s", "2026-08-31", (GtEntry("CVE-1", "g:a", "1.0"), GtEntry("CVE-2", "g:x", "9")), [])
    rows = compare_installed({"g:a": "1.0"}, m)
    assert rows == [{"package": "g:a", "manifest": "1.0", "inventory": "1.0", "match": True},
                    {"package": "g:x", "manifest": "9", "inventory": None, "match": False}]
```

- [ ] **Step 2: 실패 확인**

Run: `.venv/bin/pytest tests/test_verify_tools.py -q`
Expected: FAIL — `ModuleNotFoundError: tools.verify.jar_surface`

- [ ] **Step 3: 구현 (`tools/verify/jar_surface.py`)**

```python
"""입력면 교차(spec §5 축 5): 배포 jar(trivy rootfs) vs cdxgen BOM 인벤토리·버전 비교.

주의: Trivy 언어 지원표상 jar/war/ear 는 image·rootfs 모드에서만 분석된다 — `trivy fs` 는 소스 매니페스트(pom/gradle) 전용이라
빌드 산출물 디렉토리에 돌리면 "language-specific files num=0" 으로 조용히 0건이 된다(2026-09-05 실측). 보안팀 결과(Target=Java, Type=jar)와
같은 표면은 rootfs 다.

빌드·스캔은 CLI 로 실행하고(격리 env 상속), 비교는 순수 함수다.
사용: python -m tools.verify.jar_surface --repo-dir <scratch>/<sha>/repo --bom <bom.json> \
        --gt docs/verification/ground-truth/gt-b-sca.json --out <md>
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from secscan.measure import GtManifest, load_gt_manifest


def inventory_from_bom(bom_json: str) -> dict[str, str]:
    inv: dict[str, str] = {}
    for c in json.loads(bom_json or "{}").get("components", []) or []:
        g, n, v = c.get("group"), c.get("name"), c.get("version")
        if not (g and n):
            purl = c.get("purl", "")
            if purl.startswith("pkg:maven/"):
                body = purl[len("pkg:maven/"):]
                gn, _, ver = body.partition("@")
                g, _, n = gn.partition("/")
                v = v or ver.split("?", 1)[0]
        if g and n and v:
            inv[f"{g}:{n}"] = v
    return inv


def inventory_from_trivy(trivy_json: str) -> dict[str, str]:
    inv: dict[str, str] = {}
    for res in json.loads(trivy_json or "{}").get("Results", []) or []:
        for p in res.get("Packages") or []:
            if p.get("Name") and p.get("Version"):
                inv[p["Name"]] = p["Version"]
        for v in res.get("Vulnerabilities") or []:
            if v.get("PkgName") and v.get("InstalledVersion"):
                inv.setdefault(v["PkgName"], v["InstalledVersion"])
    return inv


def diff_inventories(a: dict[str, str], b: dict[str, str]) -> dict:
    return {
        "only_a": sorted(set(a) - set(b)),
        "only_b": sorted(set(b) - set(a)),
        "version_differs": {k: (a[k], b[k]) for k in sorted(set(a) & set(b)) if a[k] != b[k]},
    }


def compare_installed(inv: dict[str, str], manifest: GtManifest) -> list[dict]:
    rows, seen = [], set()
    for e in manifest.entries:
        if e.package in seen:
            continue
        seen.add(e.package)
        got = inv.get(e.package)
        rows.append({"package": e.package, "manifest": e.installed, "inventory": got, "match": got == e.installed})
    return rows


def render(diff: dict, cmp_bom: list[dict], cmp_jar: list[dict]) -> str:
    L = ["## 인벤토리 차이 (BOM=a, jar=b)",
         f"- BOM 에만: {len(diff['only_a'])} — {', '.join(diff['only_a'][:30])}",
         f"- jar 에만: {len(diff['only_b'])} — {', '.join(diff['only_b'][:30])}",
         "- 버전 차이:", *(f"  - {k}: BOM {a} / jar {b}" for k, (a, b) in diff["version_differs"].items()),
         "", "## 정답지 설치버전 대조", "| 패키지 | 보안팀 | BOM | jar |", "|---|---|---|---|"]
    jar_by = {r["package"]: r for r in cmp_jar}
    for r in cmp_bom:
        j = jar_by.get(r["package"], {})
        L.append(f"| {r['package']} | {r['manifest']} | {r['inventory'] or '-'} | {j.get('inventory') or '-'} |")
    return "\n".join(L)


def build_and_scan_jar(repo_dir: Path, out_json: Path, *, run=subprocess.run) -> bool:
    """./gradlew bootJar → trivy rootfs build/libs (fat jar 의 BOOT-INF/lib 중첩 jar 포함). 실패 시 False (부분 실패 정상)."""
    r = run(["./gradlew", "bootJar", "-x", "test", "--no-daemon", "-q"], cwd=str(repo_dir),
            capture_output=True, text=True, timeout=1800)
    if r.returncode != 0:
        out_json.with_suffix(".build-error.txt").write_text((r.stderr or "")[-4000:], encoding="utf-8")
        return False
    r = run(["trivy", "rootfs", "--scanners", "vuln", "--list-all-pkgs", "--format", "json", "--quiet",
             str(repo_dir / "build" / "libs")], capture_output=True, text=True, timeout=900)
    out_json.write_text(r.stdout or "{}", encoding="utf-8")
    return r.returncode == 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="tools.verify.jar_surface")
    p.add_argument("--repo-dir", required=True)
    p.add_argument("--bom", required=True)
    p.add_argument("--gt", required=True)
    p.add_argument("--out", required=True)
    a = p.parse_args(argv)
    out = Path(a.out)
    jar_json = out.with_suffix(".trivy-fs.json")
    ok = build_and_scan_jar(Path(a.repo_dir), jar_json)
    jar_text = jar_json.read_text(encoding="utf-8") if jar_json.exists() else "{}"
    if not jar_json.exists():
        jar_json.write_text("{}", encoding="utf-8")  # reconcile 재생성용 — 실패도 파일로 남긴다
    out.with_name("input-surface.status.json").write_text(json.dumps({"jar_build_scan_ok": ok}) + "\n", encoding="utf-8")
    out.write_text(render_doc(ok, Path(a.bom).read_text(encoding="utf-8"), jar_text, load_gt_manifest(a.gt)), encoding="utf-8")
    print(out)
    return 0


def render_doc(ok: bool, bom_json: str, jar_json: str, manifest: GtManifest) -> str:
    """입력면 교차 문서 전체(생성기 — reconcile 이 같은 입력으로 재생성해 비교한다)."""
    inv_bom = inventory_from_bom(bom_json)
    inv_jar = inventory_from_trivy(jar_json) if jar_json.strip() not in ("", "{}") else {}
    return f"# 입력면 교차 — jar 빌드/스캔 {'성공' if ok else '실패(부분)'}\n\n" + render(
        diff_inventories(inv_bom, inv_jar), compare_installed(inv_bom, manifest), compare_installed(inv_jar, manifest))


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: 통과 확인 + 커밋(코드)**

Run: `.venv/bin/pytest -q` → PASS

```bash
git add tools/verify/jar_surface.py tests/test_verify_tools.py
git commit -m "feat(V2): 입력면 교차 도구 — jar(trivy rootfs) vs BOM 인벤토리·버전 비교

다음: 입력면 교차 실측"
```

- [ ] **Step 5: 실측 (격리 env, 네트워크·빌드)**

```bash
export SCRATCH=/private/tmp/secscan-verify; export VDATE=<Task 6 날짜>; export RES=docs/verification/results/$VDATE
eval "$(.venv/bin/python -c 'from pathlib import Path; from tools.verify.snapshot import isolated_env; import shlex; print("\n".join(f"export {k}={shlex.quote(v)}" for k,v in isolated_env(Path("/private/tmp/secscan-verify"),"a483b3b1").items() if k in ("GRADLE_USER_HOME","GRADLE_OPTS","SECSCAN_VERIFY_ISOLATED")))')"
BOM=$(.venv/bin/python -c "from secscan.sbom import bom_cache_path; print(bom_cache_path('$SCRATCH/a483b3b1/repo'))")
.venv/bin/python -m tools.verify.jar_surface --repo-dir $SCRATCH/a483b3b1/repo --bom $BOM \
  --gt docs/verification/ground-truth/gt-b-sca.json --out $RES/input-surface.md
```
Expected: `input-surface.md` 에 인벤토리 차·정답지 설치버전 3열 대조. mssql 행에서 jar 열이 `13.2.1` 로 나오면 보안팀 오탐 원인(jar 버전 파싱) 재현이다 — 그대로 기록.

- [ ] **Step 6: 커밋**

```bash
git add docs/verification/results
git commit -m "docs(V2): 입력면 교차 실측 — jar vs BOM 인벤토리·해석 버전 대조

다음: V3 도달성 쌍 픽스처 reach-app"
```

---

### Task 10: `fixtures/reach-app` 도달성 쌍 픽스처 + false-unreachable 게이트 테스트

**Files:**
- Create: `fixtures/reach-app/pom.xml`, `fixtures/reach-app/src/main/java/demo/App.java`, `fixtures/reach-app/expected.json`
- Create: `tests/golden/atom-usages-reach-app.json`
- Test: `tests/test_reach_app.py`

**Interfaces:**
- Consumes: `decide_reachability(findings, invoked)`, `parse_invoked_symbols(json)` (depscan), `Finding`.
- 케이스 3: (a) 취약 API 사용 → reachable, (b) 같은 라이브러리 안전 API 만(jackson `ObjectMapper.readValue`) → 앱이 **실제로 사용**하므로 unreachable 이면 false-unreachable. 사전 확인 결과 현 엔진의 `package_prefixes("com.fasterxml.jackson.core:jackson-databind")` 는 `com.fasterxml.jackson.core.jackson.databind` 만 내놓아 실제 패키지 `com.fasterxml.jackson.databind` 와 불일치 → **unreachable 을 낸다**(Maven 좌표→Java 패키지 추정 실패). (c) 프레임워크 활성화 라이브러리(앱 코드 미참조) → unreachable 금지. (b)(c) 둘 다 현 엔진이 unreachable 을 내므로 `xfail(strict=True)` 로 갭을 고정하고, 현 동작을 별도 테스트로 명시한다.

- [ ] **Step 1: 픽스처 작성**

`fixtures/reach-app/pom.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>demo</groupId><artifactId>reach-app</artifactId><version>0.1</version>
  <properties><maven.compiler.source>17</maven.compiler.source><maven.compiler.target>17</maven.compiler.target></properties>
  <dependencies>
    <!-- (a) 취약 API 직접 호출: StringSubstitutor.createInterpolator (CVE-2022-42889) -->
    <dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId><version>1.9</version></dependency>
    <!-- (b) 같은 라이브러리의 안전 API 만: ObjectMapper.readValue 단순 POJO (polymorphic typing 없음) -->
    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>2.13.0</version></dependency>
    <!-- (c) 프레임워크 활성화: 앱 코드가 tomcat 타입을 참조하지 않지만 런타임에 항상 기동 -->
    <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId><version>2.5.0</version></dependency>
  </dependencies>
</project>
```

`fixtures/reach-app/src/main/java/demo/App.java`:

```java
package demo;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.text.StringSubstitutor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class App {
    public static void main(String[] args) { SpringApplication.run(App.class, args); }

    // (a) 취약 API: 사용자 입력이 interpolator 로
    public String interpolate(String userInput) {
        return StringSubstitutor.createInterpolator().replace(userInput);
    }

    // (b) 안전 API 만: 단순 POJO 역직렬화 (default typing 없음)
    public Config parse(String json) throws Exception {
        return new ObjectMapper().readValue(json, Config.class);
    }

    public static class Config { public String name; }
}
```

`fixtures/reach-app/expected.json`:

```json
{
  "description": "도달성 쌍 픽스처(spec §6). must_not_be_unreachable = 안전상 unreachable 로 판정하면 안 되는 케이스(false-unreachable 게이트).",
  "reachable": [
    {"package": "commons-text", "version": "1.9", "cve": "CVE-2022-42889", "reason": "App.interpolate → StringSubstitutor.createInterpolator().replace"}
  ],
  "must_not_be_unreachable": [
    {"package": "jackson-databind", "version": "2.13.0", "cve": "CVE-2022-42003", "reason": "App.parse 가 ObjectMapper.readValue 를 직접 호출(실사용). 현 엔진은 Maven 좌표→패키지 prefix 추정(com.fasterxml.jackson.core.jackson.databind)이 실제 패키지(com.fasterxml.jackson.databind)와 어긋나 unreachable = false-unreachable(원인: prefix 휴리스틱)"},
    {"package": "tomcat-embed-core", "version": "9.0.46", "cve": "CVE-2021-41079", "reason": "spring-boot-starter-web 이 런타임에 항상 기동. 앱 코드 미참조 → 현 엔진 unreachable = false-unreachable(원인: 프레임워크 활성화 미인지)"}
  ]
}
```

`tests/golden/atom-usages-reach-app.json` (atom usage 슬라이스 최소형 — `parse_invoked_symbols` 가 읽는 키만):

```json
{
  "objectSlices": [
    {"code": "interpolate", "fullName": "demo.App.interpolate", "signature": "", "fileName": "App.java", "lineNumber": 13, "columnNumber": 0,
     "usages": [{"targetObj": {"name": "userInput", "typeFullName": "java.lang.String", "lineNumber": 13, "columnNumber": 0, "label": "PARAM"},
                 "definedBy": {"name": "<empty>", "typeFullName": "ANY", "lineNumber": null, "columnNumber": null, "label": "UNKNOWN"},
                 "invokedCalls": [{"callName": "createInterpolator", "resolvedMethod": "org.apache.commons.text.StringSubstitutor.createInterpolator:org.apache.commons.text.StringSubstitutor()", "paramTypes": [], "returnType": "org.apache.commons.text.StringSubstitutor", "isExternal": true, "lineNumber": 14, "columnNumber": 0}],
                 "argToCalls": []}]},
    {"code": "parse", "fullName": "demo.App.parse", "signature": "", "fileName": "App.java", "lineNumber": 18, "columnNumber": 0,
     "usages": [{"targetObj": {"name": "json", "typeFullName": "java.lang.String", "lineNumber": 18, "columnNumber": 0, "label": "PARAM"},
                 "definedBy": {"name": "<empty>", "typeFullName": "ANY", "lineNumber": null, "columnNumber": null, "label": "UNKNOWN"},
                 "invokedCalls": [{"callName": "readValue", "resolvedMethod": "com.fasterxml.jackson.databind.ObjectMapper.readValue:java.lang.Object(java.lang.String,java.lang.Class)", "paramTypes": ["java.lang.String", "java.lang.Class"], "returnType": "java.lang.Object", "isExternal": true, "lineNumber": 19, "columnNumber": 0}],
                 "argToCalls": []}]},
    {"code": "main", "fullName": "demo.App.main", "signature": "", "fileName": "App.java", "lineNumber": 10, "columnNumber": 0,
     "usages": [{"targetObj": {"name": "args", "typeFullName": "java.lang.String[]", "lineNumber": 10, "columnNumber": 0, "label": "PARAM"},
                 "definedBy": {"name": "<empty>", "typeFullName": "ANY", "lineNumber": null, "columnNumber": null, "label": "UNKNOWN"},
                 "invokedCalls": [{"callName": "run", "resolvedMethod": "org.springframework.boot.SpringApplication.run:org.springframework.context.ConfigurableApplicationContext(java.lang.Class,java.lang.String[])", "paramTypes": [], "returnType": "", "isExternal": true, "lineNumber": 10, "columnNumber": 0}],
                 "argToCalls": []}]}
  ],
  "userDefinedTypes": []
}
```

- [ ] **Step 2: 실패하는 테스트 작성 (`tests/test_reach_app.py`)**

```python
"""V3 도달성 쌍 픽스처(spec §5 축 6·§6) — false-unreachable 게이트.

골든 usage 슬라이스로 결정적 검증. (c) 프레임워크 활성화 케이스는 현 엔진(패키지 prefix 존재)이
unreachable 을 내는 것이 알려진 갭이라 xfail(strict) 로 고정한다: 엔진이 고쳐지면 이 xfail 이
XPASS 로 실패해 제거를 강제한다.
"""

import json
from pathlib import Path

import pytest

from secscan.models import REACHABLE, UNREACHABLE, Advisory, Component, Finding, Reachability
from secscan.reachability.depscan import decide_reachability, parse_invoked_symbols

ROOT = Path(__file__).parent.parent
SLICE = (ROOT / "tests" / "golden" / "atom-usages-reach-app.json").read_text()
EXPECTED = json.loads((ROOT / "fixtures" / "reach-app" / "expected.json").read_text())


def _f(pkg, ver, cve):
    return Finding(category="sca", severity="high", tool="trivy", rule_id=cve,
                   component=Component("maven", pkg, ver), advisory=Advisory(cve, aliases=(cve,)))


FINDINGS = [
    _f("org.apache.commons:commons-text", "1.9", "CVE-2022-42889"),
    _f("com.fasterxml.jackson.core:jackson-databind", "2.13.0", "CVE-2022-42003"),
    _f("org.apache.tomcat.embed:tomcat-embed-core", "9.0.46", "CVE-2021-41079"),
]


def _verdicts():
    return decide_reachability(FINDINGS, parse_invoked_symbols(SLICE)).verdicts


def test_vulnerable_api_use_is_reachable():
    assert _verdicts()["org.apache.commons:commons-text@1.9"] == REACHABLE


@pytest.mark.xfail(strict=True, reason="백로그 P1: Maven 좌표→Java 패키지 prefix 추정 실패(jackson-databind 실사용인데 unreachable) — false-unreachable")
def test_used_library_with_mismatched_prefix_must_not_be_unreachable():
    assert _verdicts()["com.fasterxml.jackson.core:jackson-databind@2.13.0"] != UNREACHABLE


@pytest.mark.xfail(strict=True, reason="백로그 P1: 프레임워크 활성화 라이브러리(앱 미참조)를 unreachable 로 판정 — false-unreachable")
def test_framework_activated_library_must_not_be_unreachable():
    assert _verdicts()["org.apache.tomcat.embed:tomcat-embed-core@9.0.46"] != UNREACHABLE


def test_current_engine_false_unreachable_modes_documented():
    # 위 두 xfail 의 반대 진술 — 갭이 실재함을 명시적으로 고정(엔진이 고쳐지면 셋 다 갱신).
    v = _verdicts()
    assert v["com.fasterxml.jackson.core:jackson-databind@2.13.0"] == UNREACHABLE
    assert v["org.apache.tomcat.embed:tomcat-embed-core@9.0.46"] == UNREACHABLE
    assert EXPECTED["must_not_be_unreachable"][0]["package"] == "jackson-databind"
    assert EXPECTED["must_not_be_unreachable"][1]["package"] == "tomcat-embed-core"
```

- [ ] **Step 3: 실행 확인**

Run: `.venv/bin/pytest tests/test_reach_app.py -v`
Expected: 2 PASS + 2 XFAIL (strict). `test_vulnerable_api_use_is_reachable` 이 실패하면 골든 슬라이스의 `resolvedMethod` 접두가 `package_prefixes("org.apache.commons:commons-text")` 결과(`org.apache.commons.text`)와 일치하는지 확인.

- [ ] **Step 4: 커밋**

```bash
git add fixtures/reach-app tests/golden/atom-usages-reach-app.json tests/test_reach_app.py
git commit -m "test(V3): reach-app 도달성 쌍 픽스처 — 취약 API reachable / prefix 불일치·프레임워크 활성화 false-unreachable xfail(strict) 2종

다음: GT-A differential 도구"
```

---

### Task 11: GT-A differential (취약 커밋 출현 ∧ 수정 커밋 소멸)

**Files:**
- Create: `tools/verify/differential.py`
- Test: `tests/test_verify_tools.py` (추가)
- Create: `docs/verification/results/<date>/gt-a-differential.md`

**Interfaces:**
- `find_expected(findings, entry: dict) -> list[Finding]` — `rule_id.endswith(expected_rule_suffix)` ∧ `location.file.endswith(file_suffix)`.
- `evaluate_pair(entry: dict, vuln_findings, fixed_findings) -> dict` with `present_in_vulnerable`, `absent_in_fixed`, `tier_vulnerable`, `passed`(in-category 만 판정), `observed`(measure-then-classify: 취약 스냅샷에서 해당 파일에 걸린 rule_id 목록).
- `render(rows) -> str`
- CLI `main`: `--evidence-root <EVD> --gt gt-a-source.json --out <md> [--facts <json>]` — `<EVD>/<sha>-standard/findings.json` 을 읽는다(Task 6 산출물). `--facts` 는 `collect_facts(rows)` 를 저장(`gta.in_category_pass`="m/t", 행별 `gta.row<i>.<cwe>.passed`, measure-then-classify 는 `gta.row<i>.<cwe>.observed`).
- `collect_facts(rows: list[dict]) -> dict`

- [ ] **Step 1: 실패하는 테스트 작성**

```python
# --- V3: GT-A differential ---
from secscan.models import Location, sast_tier
from tools.verify.differential import evaluate_pair, find_expected


def _sast(rule, file, conf="high", sev="high"):
    return Finding(category="sast", severity=sev, tool="semgrep", rule_id=rule, confidence=conf,
                   location=Location(file, 5))


def test_evaluate_pair_in_category_present_then_absent():
    entry = {"cwe": "CWE-760", "file_suffix": "LoadtestSeederConfig.java", "expected_rule_suffix": "zero-salt",
             "expected_tier": "review", "class": "in-category"}
    vuln = [_sast("secscan.rules.zero-salt", "src/main/java/x/loadtest/LoadtestSeederConfig.java")]
    r = evaluate_pair(entry, vuln, [])
    assert r["present_in_vulnerable"] and r["absent_in_fixed"] and r["passed"]
    assert r["tier_vulnerable"] == "review" and r["tier_ok"]


def test_evaluate_pair_fails_when_still_present_in_fixed():
    entry = {"cwe": "CWE-89", "file_suffix": "LgCarrierMapper.xml", "expected_rule_suffix": "mybatis-sqli-identifier",
             "expected_tier": "review", "class": "in-category"}
    f = _sast("secscan.rules.mybatis-sqli-identifier", "src/main/resources/mybatis/mapper/lg/LgCarrierMapper.xml", conf="low")
    r = evaluate_pair(entry, [f], [f])
    assert r["present_in_vulnerable"] and not r["absent_in_fixed"] and not r["passed"]


def test_evaluate_pair_measure_then_classify_records_observed_rules():
    entry = {"cwe": "CWE-497", "file_suffix": "TestDbReset.java", "expected_rule_suffix": None,
             "expected_tier": None, "class": "measure-then-classify"}
    vuln = [_sast("java.lang.security.audit.x", "src/main/java/t/TestDbReset.java"),
            _sast("other.rule", "src/main/java/t/Other.java")]
    r = evaluate_pair(entry, vuln, [])
    assert r["passed"] is None and r["observed"] == ["java.lang.security.audit.x"]
```

- [ ] **Step 2: 실패 확인**

Run: `.venv/bin/pytest tests/test_verify_tools.py -q`
Expected: FAIL — `ModuleNotFoundError: tools.verify.differential`

- [ ] **Step 3: 구현 (`tools/verify/differential.py`)**

```python
"""GT-A differential(spec §5 축 7): 취약 스냅샷에서 기대 룰 출현 ∧ 수정 커밋에서 소멸.

탐지 recall(출현)과 actionable recall(tier)을 분리해 기록한다. 증거 디렉토리의 findings.json 을 읽는다.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from secscan.measure import load_gt_manifest
from secscan.models import Finding, sast_tier
from secscan.output.json_io import from_json


def find_expected(findings: list[Finding], entry: dict) -> list[Finding]:
    suf, fsuf = entry.get("expected_rule_suffix"), entry.get("file_suffix")
    return [f for f in findings if f.category == "sast" and f.location
            and (suf is None or f.rule_id.endswith(suf))
            and (fsuf is None or f.location.file.endswith(fsuf))]


def evaluate_pair(entry: dict, vuln_findings: list[Finding], fixed_findings: list[Finding]) -> dict:
    cls = entry.get("class")
    row = {"cwe": entry.get("cwe"), "class": cls, "file": entry.get("file_suffix"),
           "rule": entry.get("expected_rule_suffix")}
    if cls == "measure-then-classify":
        hits = find_expected(vuln_findings, entry)
        row.update({"observed": sorted({f.rule_id for f in hits}), "passed": None})
        return row
    if cls != "in-category":
        row.update({"passed": None, "observed": []})
        return row
    v, x = find_expected(vuln_findings, entry), find_expected(fixed_findings, entry)
    tier = sast_tier(v[0]) if v else None
    row.update({
        "present_in_vulnerable": bool(v), "absent_in_fixed": not x,
        "tier_vulnerable": tier, "tier_ok": (tier == entry.get("expected_tier")) if v else False,
        "passed": bool(v) and not x,
    })
    return row


def render(rows: list[dict]) -> str:
    L = ["| CWE | 분류 | 파일 | 룰 | 취약에서 출현 | 수정에서 소멸 | tier(기대) | 판정 |", "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        if r["class"] == "in-category":
            L.append(f"| {r['cwe']} | {r['class']} | {r['file']} | {r['rule']} | {r['present_in_vulnerable']} | {r['absent_in_fixed']} | "
                     f"{r['tier_vulnerable']} ({'ok' if r['tier_ok'] else 'mismatch'}) | {'PASS' if r['passed'] else 'FAIL'} |")
        else:
            L.append(f"| {r['cwe']} | {r['class']} | {r['file'] or '-'} | - | 관측: {', '.join(r.get('observed', [])) or '없음'} | - | - | 기록 |")
    return "\n".join(L)


def _load(evidence_root: Path, sha: str) -> list[Finding]:
    p = evidence_root / f"{sha}-standard" / "findings.json"
    return from_json(p.read_text(encoding="utf-8")) if p.exists() else []


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="tools.verify.differential")
    p.add_argument("--evidence-root", required=True)
    p.add_argument("--gt", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--facts", default=None, help="정본 수치 JSON(spec §4.5)")
    a = p.parse_args(argv)
    root = Path(a.evidence_root)
    rows = []
    for e in load_gt_manifest(a.gt).raw_entries:
        if not e.get("vulnerable"):
            rows.append({"cwe": e.get("cwe"), "class": e.get("class"), "file": None, "rule": None, "passed": None, "observed": []})
            continue
        rows.append(evaluate_pair(e, _load(root, e["vulnerable"]), _load(root, e["fixed"]) if e.get("fixed") else []))
    in_cat = [r for r in rows if r["class"] == "in-category"]
    md = (f"# GT-A differential — 범주 내 {sum(1 for r in in_cat if r['passed'])}/{len(in_cat)} PASS\n\n" + render(rows))
    Path(a.out).write_text(md, encoding="utf-8")
    if a.facts:
        Path(a.facts).write_text(json.dumps(collect_facts(rows), ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(a.out)
    return 0


def collect_facts(rows: list[dict]) -> dict:
    """정본 수치(spec §4.5). 판정은 evaluate_pair 의 기계적 결과를 그대로 옮긴다."""
    in_cat = [r for r in rows if r["class"] == "in-category"]
    facts: dict = {"gta.in_category_pass": f"{sum(1 for r in in_cat if r['passed'])}/{len(in_cat)}"}
    for i, r in enumerate(rows):
        if r["class"] == "in-category":
            facts[f"gta.row{i}.{r['cwe']}.passed"] = str(r["passed"])
        elif r["class"] == "measure-then-classify":
            facts[f"gta.row{i}.{r['cwe']}.observed"] = ", ".join(r.get("observed", [])) or "없음"
    return facts


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: 통과 확인 + 코드 커밋**

Run: `.venv/bin/pytest -q` → PASS

```bash
git add tools/verify/differential.py tests/test_verify_tools.py
git commit -m "feat(V3): GT-A differential — 취약 출현·수정 소멸·tier 분리 판정

다음: V3 실측(differential + 사람 판정 비교)"
```

- [ ] **Step 5: 실측 (증거 기반, 결정적)**

```bash
export VDATE=<Task 6 날짜>; export EVD=docs/verification/evidence/$VDATE; export RES=docs/verification/results/$VDATE
.venv/bin/python -m tools.verify.differential --evidence-root $EVD \
  --gt docs/verification/ground-truth/gt-a-source.json --out $RES/gt-a-differential.md --facts $RES/facts-gta.json
```
Expected: 범주 내 4행(259·760·#305 ×2) PASS 여부 + measure-then-classify 2행의 관측 룰. FAIL 이면 해당 증거 디렉토리의 `raw/semgrep.json` 에서 룰 id·파일을 확인해 원인(룰 미로드 / 경로 제외 / 파일명 불일치)을 `gate-v3.md` 에 적는다.

- [ ] **Step 6: 게이트 기록 + 커밋**

`$RES/gate-v3.md`(모든 수치에 `<!-- fact:<id> -->` 마커 — `facts-gta.json`·`facts.json` 값만 인용; reach-app xfail 수는 pytest 출력 줄을 코드블록으로 인용): 축 6 — (a) 사람 판정 비교표는 `gt-b-match.md` 하단, (b) false-unreachable: `tests/test_reach_app.py` xfail 1건 = **게이트 미통과, 백로그 P1**(프레임워크 활성화 라이브러리), (c) 증거 `findings.json` 의 unknown 비율. 축 7 — differential PASS 수, tier 기대 일치, measure-then-classify 관측 결과와 사후 분류.

```bash
git add docs/verification/results
git commit -m "docs(V3): GT-A differential 실측 + 도달성 축 게이트 기록(false-unreachable 갭 P1)

다음: 측정 문서 중간본 + PROGRESS 갱신"
```

---

### Task 12: 측정 문서 중간본 + PROGRESS/CLAUDE 갱신

**Files:**
- Create: `docs/measurements/<YYYY-MM-DD>-message-gate-verification.md`
- Modify: `PROGRESS.md`, `CLAUDE.md`(상태 절 1~2줄)

- [ ] **Step 1: 측정 문서 작성**

`docs/verification/results/<date>/` 의 md 들을 절로 묶는다. 구성(spec §5 순서): 요약(축별 게이트 ✓/✗ 표) → 환경·격리·도구 버전(meta.json) → 축 1 프로파일 계약 → 축 2~4 SCA(recall 표·미탐·known-FP 3단계·초과분 분류) → 축 5 입력면 → 축 6 도달성(사람 판정 비교표 + reach-app 결과) → 축 7 GT-A differential → 부수 측정(시간·메모리) → **백로그 후보(우선순위)**: 게이트 미통과 항목을 P1 로, 관측된 갭을 P2 로. 마지막에 "플랜 2(V4~V7)에서 확정" 표기. 수치는 `facts*.json` 의 값을 그대로 옮기고 **요약 표는 `| 축 | 기준 | 측정값 | 판정 |` 형식으로 쓰고 측정값 열의 모든 수치에 `<!-- fact:<id> -->` 마커**를 단다(Task 13 정본 검증기가 측정값/값 열을 대조; 기준 열은 spec 상수). 추정치·해석 수치 금지. 생성 문서(`gt-b-match.md` 등)는 내용을 바꾸지 말고 인용(파일 경로 + 핵심 표 복사)한다.

- [ ] **Step 2: PROGRESS.md 에 V 절 추가**

```markdown
## V — 검증 캠페인 (spec 2026-09-04) — 플랜 1(V0~V3) ✅
- [x] V0 정답지 매니페스트 3종 + 대조기(match_ground_truth/classify_extras)
- [x] V1 TraceSink 단계 추적 + findings.json + tools/verify 격리 하네스 + 증거 동결(docs/verification/evidence/<date>)
- [x] V2 SCA 실측: CVE recall N/46 · known-FP 3단계 · 프로파일 계약 · 초과분 triage · 입력면 교차
- [x] V3 도달성 쌍 픽스처(reach-app, false-unreachable xfail) + GT-A differential + 정본 검증(reconcile ✓)
- [ ] V4~V7 → 플랜 2 (판정 단계 H · 모델 확장 · xlsx · 변이 픽스처 · 최종 문서)
```

`CLAUDE.md` 상태 줄에 `V 플랜1 완료(측정 문서 docs/measurements/<date>-message-gate-verification.md)` 를 추가한다.

- [ ] **Step 3: 전체 테스트 + 커밋**

```bash
.venv/bin/pytest -q
git add docs/measurements PROGRESS.md CLAUDE.md
git commit -m "docs(V3): message-gate 검증 측정 문서 중간본 + PROGRESS/CLAUDE 갱신

다음: 플랜 2(V4~V7) 작성 — 판정 단계 H·모델 확장·xlsx"
```

---

### Task 13: 정본 검증기 `tools/verify/reconcile.py` (spec §4.5 · 축 9 — 측정 사실성)

**Files:**
- Create: `tools/verify/reconcile.py`
- Test: `tests/test_verify_tools.py` (추가)
- Create: `docs/verification/results/<date>/reconcile-report.md`

**Interfaces:**
- Consumes: `report.main/collect_facts`(Task 7), `known_fp.check_known_fp/render`(Task 7), `profile_contract.render_doc`(Task 7), `jar_surface.render_doc`(Task 9), `differential.main`(Task 11), `secscan.output.json_io.from_json`, `secscan.measure.load_gt_manifest`.
- Produces: `parse_markers(md) -> list[tuple[str, str]]`(fact_id, 문서값), `check_markers(md, facts) -> list[dict]`, `unmarked_numbers(md, section: str | None) -> list[str]`, `check_provenance(triage: dict) -> list[dict]`, `raw_vs_typed(trivy_json, findings) -> dict`, `regenerate(results_dir, evidence_root, gt_b, gt_a) -> list[dict]`, `load_facts(results_dir) -> dict`, `render_report(...) -> str`, `main(argv) -> int` (`--results --evidence-root --gt-b --gt-a [--measurement <md>] [--out <md>]`, exit 0=통과 / 1=위반).

- [ ] **Step 1: 실패하는 테스트 작성 (`tests/test_verify_tools.py` 끝에 추가)**

```python
# --- V3: 정본 검증기 (spec §4.5) ---
from tools.verify.reconcile import (check_markers, check_provenance, parse_markers, raw_vs_typed,
                                    regenerate, unmarked_numbers)


def test_parse_and_check_markers():
    md = "| recall | 38/46 <!-- fact:sca.recall_cve --> | 미탐 3 <!-- fact:sca.missed --> |"
    assert parse_markers(md) == [("sca.recall_cve", "38/46"), ("sca.missed", "3")]
    rows = check_markers(md, {"sca.recall_cve": "38/46", "sca.missed": 4})
    assert [r["ok"] for r in rows] == [True, False] and rows[1]["fact"] == "4"
    assert check_markers("7 <!-- fact:nope -->", {})[0]["ok"] is False


def test_unmarked_numbers_only_in_section_tables_and_value_columns():
    md = ("## 요약\n| 축 | 기준 | 측정값 | 판정 |\n|---|---|---|---|\n"
          "| 1 a | ≥ 44/46 | 38/46 <!-- fact:x --> | ✓ |\n| 2 b | ≤ 1 | 7 | ✗ |\n| 3 c | - | 2026-09-05 | ✓ |\n"
          "## 기타\n| 축 | 값 |\n|---|---|\n| z | 99 |\n| w | 5 |\n")
    assert unmarked_numbers(md, "요약") == ["7"]          # 행 라벨 1·2·3 과 기준 열 44/46·1 은 대상 아님
    assert unmarked_numbers(md, None) == ["7", "99", "5"]  # "값" 열도 검사 대상


def test_unmarked_numbers_catches_attached_tokens_and_skips_ids():
    md = ("| 축 | 측정값 |\n|---|---|\n"
          "| 2 a | 미탐 9건 · 미분류 0(키 없음) · 기준 44/46 |\n"
          "| 4 b | 3 <!-- fact:m -->건 · a483b3b1 · CVE-2026-40992 · 13.2.1.jre11 · spec §5 · 2026-09-05 |\n"
          "| 표 없는 헤더 | 77 |\n")
    assert unmarked_numbers(md, None) == ["9", "0", "44/46", "77"]
    assert unmarked_numbers("| a | b |\n|---|---|\n| 1 | 2 |\n", None) == []  # 측정값/값 열이 없는 표는 검사 안 함


def test_check_provenance_requires_human():
    t = {"overrides": [{"dedup_key": "k1", "provenance": "human:picpal"}, {"dedup_key": "k2", "provenance": "ai:claude"},
                       {"dedup_key": "k3"}]}
    assert [r["ok"] for r in check_provenance(t)] == [True, False, False]
    assert check_provenance({"overrides": []}) == []


def test_raw_vs_typed_cardinality():
    trivy = json.dumps({"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-1"}, {"VulnerabilityID": "CVE-2"}]}]})
    r = raw_vs_typed(trivy, [_sca("g:a", "1.0", "CVE-1")])
    assert (r["raw_count"], r["typed_count"], r["only_raw"], r["only_typed"]) == (2, 1, ["CVE-2"], [])


def _fake_results(tmp_path):
    """가짜 증거 + 그 증거로 생성한 결과 문서 — 재생성 비교의 양성 케이스."""
    from tools.verify import differential, report
    from tools.verify.jar_surface import render_doc as render_surface
    from tools.verify.known_fp import check_known_fp, render as render_fp
    from tools.verify.profile_contract import render_doc as render_profiles
    from secscan.output.json_io import to_json
    ev = tmp_path / "evidence"; std = ev / "a483b3b1-standard"; (std / "raw").mkdir(parents=True)
    fs = [_sca("org.apache.tomcat.embed:tomcat-embed-core", "11.0.22", "CVE-2026-1"),
          _sca("com.microsoft.sqlserver:mssql-jdbc", "13.2.1.jre11", "CVE-2020-9")]
    (std / "findings.json").write_text(to_json(fs), encoding="utf-8")
    (std / "trace.json").write_text(json.dumps({"raw": [{"tool": "trivy", "status": "ok", "bytes": 1}],
                                                "stages": [{"stage": "merge", "count": 2}, {"stage": "final", "count": 2}]}), encoding="utf-8")
    (std / "meta.json").write_text(json.dumps({"scanner_status": [{"tool": "trivy", "status": "ok"}]}), encoding="utf-8")
    (std / "raw" / "trivy.json").write_text(json.dumps({"Results": [{"Target": "Java", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2026-1", "PkgName": "org.apache.tomcat.embed:tomcat-embed-core", "InstalledVersion": "11.0.22", "PublishedDate": "2026-08-25T00:00:00Z"}]}]}), encoding="utf-8")
    (std / "raw" / "bom.cdx.json").write_text(json.dumps({"components": [
        {"group": "com.microsoft.sqlserver", "name": "mssql-jdbc", "version": "13.2.1.jre11", "purl": "pkg:maven/com.microsoft.sqlserver/mssql-jdbc@13.2.1.jre11?type=jar"}]}), encoding="utf-8")
    deep = ev / "a483b3b1-deep"; deep.mkdir()
    (deep / "meta.json").write_text(json.dumps({"scanner_status": [{"tool": "trivy", "status": "ok"}, {"tool": "spotbugs", "status": "ok"}]}), encoding="utf-8")
    res = tmp_path / "results"; res.mkdir()
    gt_b = "docs/verification/ground-truth/gt-b-sca.json"; gt_a = "docs/verification/ground-truth/gt-a-source.json"
    report.main(["--evidence", str(std), "--gt", gt_b, "--out", str(res / "gt-b-match.md"), "--facts", str(res / "facts.json")])
    differential.main(["--evidence-root", str(ev), "--gt", gt_a, "--out", str(res / "gt-a-differential.md"), "--facts", str(res / "facts-gta.json")])
    r = check_known_fp((std / "raw" / "bom.cdx.json").read_text(), (std / "raw" / "trivy.json").read_text(),
                       package="com.microsoft.sqlserver:mssql-jdbc", advisory="CVE-2025-59250", expected_version="13.2.1.jre11")
    (res / "known-fp.md").write_text(render_fp(r), encoding="utf-8")
    (res / "profile-contract.md").write_text(render_profiles({"trivy": "ok", "spotbugs": "ok"}), encoding="utf-8")
    (res / "input-surface.trivy-fs.json").write_text("{}", encoding="utf-8")
    (res / "input-surface.status.json").write_text(json.dumps({"jar_build_scan_ok": False}), encoding="utf-8")
    from secscan.measure import load_gt_manifest
    (res / "input-surface.md").write_text(render_surface(False, (std / "raw" / "bom.cdx.json").read_text(), "{}", load_gt_manifest(gt_b)), encoding="utf-8")
    return res, ev, gt_b, gt_a


def test_regenerate_passes_then_detects_tampering(tmp_path):
    res, ev, gt_b, gt_a = _fake_results(tmp_path)
    rows = regenerate(res, ev, gt_b, gt_a)
    assert rows and all(r["ok"] for r in rows), rows
    p = res / "gt-b-match.md"; p.write_text(p.read_text(encoding="utf-8") + "\n손으로 고친 줄", encoding="utf-8")
    rows = regenerate(res, ev, gt_b, gt_a)
    assert [r["doc"] for r in rows if not r["ok"]] == ["gt-b-match.md"]


def test_reconcile_main_exit_code(tmp_path):
    from tools.verify.reconcile import main
    res, ev, gt_b, gt_a = _fake_results(tmp_path)
    facts = json.loads((res / "facts.json").read_text(encoding="utf-8"))
    (res / "gate-v2.md").write_text(f"# 게이트\n| 축 | 값 |\n|---|---|\n| recall | {facts['sca.recall_cve']} <!-- fact:sca.recall_cve --> |\n", encoding="utf-8")
    assert main(["--results", str(res), "--evidence-root", str(ev), "--gt-b", gt_b, "--gt-a", gt_a]) == 0
    assert (res / "reconcile-report.md").read_text(encoding="utf-8").rstrip().endswith("✓ 통과")
    (res / "gate-v2.md").write_text("# 게이트\n| 축 | 값 |\n|---|---|\n| recall | 46/46 <!-- fact:sca.recall_cve --> | 3 |\n", encoding="utf-8")
    assert main(["--results", str(res), "--evidence-root", str(ev), "--gt-b", gt_b, "--gt-a", gt_a]) == 1
```

- [ ] **Step 2: 실패 확인**

Run: `.venv/bin/pytest tests/test_verify_tools.py -q -k "markers or unmarked or provenance or raw_vs_typed or regenerate or reconcile_main"`
Expected: FAIL — `ModuleNotFoundError: tools.verify.reconcile`

- [ ] **Step 3: `tools/verify/reconcile.py`**

```python
"""정본 검증기 — 결과 문서의 수치가 증거에서 재계산한 정본과 같은지 기계적으로 검사(spec §4.5, 축 9).

AI(컨트롤러·서브에이전트)가 쓴 수치·분류·판정이 섞였는지 잡는다. 위반이면 문서를 고친다 — 정본은 불변.
"""

from __future__ import annotations

import argparse
import json
import re
import tempfile
from pathlib import Path

from secscan.measure import load_gt_manifest
from secscan.output.json_io import from_json

from . import differential, report
from .jar_surface import render_doc as render_surface
from .known_fp import check_known_fp, render as render_fp
from .profile_contract import render_doc as render_profiles

_MARK = re.compile(r"(\S+)\s*<!--\s*fact:([A-Za-z0-9_.\-/가-힣]+)\s*-->")
# 수치 토큰: 앞뒤가 영숫자·'.'·'/'·'-'·'§' 가 아닌 정수 또는 N/M ("9건"·"0(" 은 잡고, 날짜·버전·SHA·CVE id·§5 는 제외)
_NUM = re.compile(r"(?<![0-9A-Za-z./§-])(\d+(?:/\d+)?)(?![0-9A-Za-z./-])")
_MARK_TOKEN = re.compile(r"\S*\d\S*\s*<!--\s*fact:[^>]*-->")
_KNOWN_FP = dict(package="com.microsoft.sqlserver:mssql-jdbc", advisory="CVE-2025-59250", expected_version="13.2.1.jre11")


def parse_markers(md: str) -> list[tuple[str, str]]:
    """`<값> <!-- fact:<id> -->` 쌍 → (id, 값)."""
    return [(m.group(2), m.group(1)) for m in _MARK.finditer(md)]


def check_markers(md: str, facts: dict) -> list[dict]:
    rows = []
    for fid, val in parse_markers(md):
        fact = facts.get(fid)
        rows.append({"id": fid, "doc": val, "fact": None if fact is None else str(fact),
                     "ok": fact is not None and str(fact) == val})
    return rows


_VALUE_HEADERS = ("측정값", "값")


def unmarked_numbers(md: str, section: str | None) -> list[str]:
    """`## <section>` 절(None=문서 전체)의 표에서 **측정값/값 열**의 셀 중 수치 토큰(`N`·`N/M`)인데 마커가 없는 것 = 출처 불명.
    행 라벨("2 SCA")·기준 열("≥ 44/46")은 대상이 아니다. "9건"·"0(…)" 처럼 붙은 표기도 잡는다.
    날짜·버전·SHA·CVE id·`§5` 는 수치로 보지 않는다. 헤더에 측정값/값 열이 없는 표는 검사하지 않는다."""
    out: list[str] = []
    inside = section is None
    cols: list[int] | None = None  # 현재 표에서 검사할 열 인덱스
    for ln in md.splitlines():
        if ln.startswith("## "):
            if section is not None:
                inside = ln[3:].strip().startswith(section)
            cols = None
            continue
        s = ln.strip()
        if not s.startswith("|"):
            cols = None
            continue
        if not inside or set(s) <= set("|-: "):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if cols is None:  # 표의 첫 줄 = 헤더
            cols = [i for i, c in enumerate(cells) if c in _VALUE_HEADERS]
            continue
        for i in cols:
            if i < len(cells):
                bare = _MARK_TOKEN.sub(" ", cells[i])  # 마커 붙은 값은 제거하고 남은 수치만 본다
                out.extend(m.group(1) for m in _NUM.finditer(bare))
    return out


def check_provenance(triage: dict) -> list[dict]:
    """override 는 사람 확정(`human:<이름>`)만 유효 — AI 분류 덮어쓰기 금지."""
    rows = []
    for o in triage.get("overrides", []) or []:
        prov = str(o.get("provenance", "") or "")
        rows.append({"dedup_key": o.get("dedup_key"), "provenance": prov or "(없음)", "ok": prov.startswith("human:")})
    return rows


def raw_vs_typed(trivy_json: str, findings) -> dict:
    """raw trivy 고유 VulnerabilityID vs typed SCA 고유 advisory — 정규화 손실 검출(차이는 사실로 기록)."""
    raw: set[str] = set()
    for res in json.loads(trivy_json or "{}").get("Results", []) or []:
        for v in res.get("Vulnerabilities") or []:
            if v.get("VulnerabilityID"):
                raw.add(v["VulnerabilityID"])
    typed = {f.advisory.id for f in findings if f.category == "sca" and f.advisory}
    return {"raw_count": len(raw), "typed_count": len(typed),
            "only_raw": sorted(raw - typed), "only_typed": sorted(typed - raw)}


def regenerate(results_dir, evidence_root, gt_b, gt_a) -> list[dict]:
    """생성 문서를 같은 증거로 다시 만들어 바이트 비교."""
    res, ev = Path(results_dir), Path(evidence_root)
    std = ev / "a483b3b1-standard"
    rows: list[dict] = []

    def cmp(name: str, text: str) -> None:
        p = res / name
        if not p.exists():
            rows.append({"doc": name, "ok": False, "note": "결과 파일 없음"})
            return
        same = p.read_text(encoding="utf-8") == text
        rows.append({"doc": name, "ok": same, "note": "" if same else "재생성 결과와 다름"})

    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        report.main(["--evidence", str(std), "--gt", str(gt_b), "--out", str(t / "m.md"), "--facts", str(t / "f.json")])
        cmp("gt-b-match.md", (t / "m.md").read_text(encoding="utf-8"))
        cmp("facts.json", (t / "f.json").read_text(encoding="utf-8"))
        differential.main(["--evidence-root", str(ev), "--gt", str(gt_a), "--out", str(t / "d.md"), "--facts", str(t / "g.json")])
        cmp("gt-a-differential.md", (t / "d.md").read_text(encoding="utf-8"))
        cmp("facts-gta.json", (t / "g.json").read_text(encoding="utf-8"))
    bom, trivy = std / "raw" / "bom.cdx.json", std / "raw" / "trivy.json"
    if bom.exists() and trivy.exists():
        cmp("known-fp.md", render_fp(check_known_fp(bom.read_text(encoding="utf-8"), trivy.read_text(encoding="utf-8"), **_KNOWN_FP)))
    else:
        rows.append({"doc": "known-fp.md", "ok": False, "note": "raw/bom.cdx.json 또는 raw/trivy.json 없음"})
    deep = ev / "a483b3b1-deep" / "meta.json"
    if deep.exists():
        statuses = {s["tool"]: s["status"] for s in json.loads(deep.read_text(encoding="utf-8"))["scanner_status"]}
        cmp("profile-contract.md", render_profiles(statuses))
    jar, status = res / "input-surface.trivy-fs.json", res / "input-surface.status.json"
    if jar.exists() and status.exists() and bom.exists():
        ok = bool(json.loads(status.read_text(encoding="utf-8")).get("jar_build_scan_ok", False))
        cmp("input-surface.md", render_surface(ok, bom.read_text(encoding="utf-8"), jar.read_text(encoding="utf-8"), load_gt_manifest(gt_b)))
    else:
        rows.append({"doc": "input-surface.md", "ok": False, "note": "trivy-fs.json / status.json / bom 없음"})
    return rows


def load_facts(results_dir) -> dict:
    facts: dict = {}
    for p in sorted(Path(results_dir).glob("facts*.json")):
        facts.update(json.loads(p.read_text(encoding="utf-8")))
    return facts


def render_report(regen: list[dict], markers: dict[str, list[dict]], unmarked: dict[str, list[str]],
                  prov: list[dict], rvt: dict) -> str:
    L = ["# 정본 검증 (spec §4.5 · 축 9)", "", "## 생성 문서 재생성 비교", "| 문서 | 일치 | 비고 |", "|---|---|---|"]
    L += [f"| {r['doc']} | {'✓' if r['ok'] else '✗'} | {r['note']} |" for r in regen]
    L += ["", "## fact 마커 대조", "| 문서 | id | 문서값 | 정본값 | 일치 |", "|---|---|---|---|---|"]
    L += [f"| {doc} | {r['id']} | {r['doc']} | {r['fact']} | {'✓' if r['ok'] else '✗'} |"
          for doc, rows in markers.items() for r in rows]
    un = [f"- {doc}: {', '.join(v)}" for doc, v in unmarked.items() if v]
    L += ["", "## 출처 불명 수치(마커 없음)", *(un or ["- 없음"])]
    pv = [f"- {r['dedup_key']}: {r['provenance']} {'✓' if r['ok'] else '✗'}" for r in prov]
    L += ["", "## override provenance", *(pv or ["- override 없음"])]
    L += ["", "## raw↔typed 카디널리티 (a483b3b1-standard)",
          f"- raw trivy 고유 VulnerabilityID: {rvt['raw_count']}", f"- typed SCA 고유 advisory: {rvt['typed_count']}",
          f"- raw 에만: {', '.join(rvt['only_raw']) or '없음'}", f"- typed 에만: {', '.join(rvt['only_typed']) or '없음'}"]
    fails = (sum(not r["ok"] for r in regen) + sum(not r["ok"] for rows in markers.values() for r in rows)
             + sum(len(v) for v in unmarked.values()) + sum(not r["ok"] for r in prov))
    L += ["", f"## 판정: {'✓ 통과' if fails == 0 else f'✗ 위반 {fails}건 — 문서를 고친다(정본 불변)'}"]
    return "\n".join(L) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="tools.verify.reconcile")
    p.add_argument("--results", required=True)
    p.add_argument("--evidence-root", required=True)
    p.add_argument("--gt-b", required=True)
    p.add_argument("--gt-a", required=True)
    p.add_argument("--measurement", default=None, help="측정 문서(md) — `## 요약` 절 마커 검사")
    p.add_argument("--out", default=None)
    a = p.parse_args(argv)
    res = Path(a.results)
    facts = load_facts(res)
    regen = regenerate(res, a.evidence_root, a.gt_b, a.gt_a)
    docs: dict[str, tuple[Path, str | None]] = {"gate-v2.md": (res / "gate-v2.md", None), "gate-v3.md": (res / "gate-v3.md", None)}
    if a.measurement:
        docs["measurement"] = (Path(a.measurement), "요약")
    markers: dict[str, list[dict]] = {}
    unmarked: dict[str, list[str]] = {}
    for name, (path, section) in docs.items():
        if not path.exists():
            continue
        md = path.read_text(encoding="utf-8")
        markers[name] = check_markers(md, facts)
        unmarked[name] = unmarked_numbers(md, section)
    triage = res / "extras-triage.json"
    prov = check_provenance(json.loads(triage.read_text(encoding="utf-8"))) if triage.exists() else []
    std = Path(a.evidence_root) / "a483b3b1-standard"
    rvt = raw_vs_typed((std / "raw" / "trivy.json").read_text(encoding="utf-8"),
                       from_json((std / "findings.json").read_text(encoding="utf-8")))
    text = render_report(regen, markers, unmarked, prov, rvt)
    Path(a.out or res / "reconcile-report.md").write_text(text, encoding="utf-8")
    print(text.splitlines()[-1])
    return 0 if text.rstrip().endswith("✓ 통과") else 1


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: 통과 확인 + 전체 회귀**

Run: `.venv/bin/pytest tests/test_verify_tools.py -q` 그리고 `.venv/bin/pytest -q`
Expected: PASS (기존 green 유지)

- [ ] **Step 5: 실측 결과에 실행 (문서가 틀리면 문서를 고친다)**

```bash
export VDATE=<Task 6 의 날짜>; export EVD=docs/verification/evidence/$VDATE; export RES=docs/verification/results/$VDATE
.venv/bin/python -m tools.verify.reconcile --results $RES --evidence-root $EVD \
  --gt-b docs/verification/ground-truth/gt-b-sca.json --gt-a docs/verification/ground-truth/gt-a-source.json \
  --measurement docs/measurements/$VDATE-message-gate-verification.md; echo "exit=$?"
cat $RES/reconcile-report.md
```
Expected: `## 판정: ✓ 통과`, exit 0. ✗ 가 있으면 **해당 문서(gate-v2/v3, 측정 문서)의 인용을 정본 값으로 고치거나 마커를 달고** 재실행한다. 생성 문서(`gt-b-match.md` 등)가 ✗ 면 손으로 고친 흔적이므로 생성기로 다시 만든다. `facts*.json` 과 생성기 코드는 이 단계에서 고치지 않는다(고쳐야 하면 BLOCKED 로 보고).

- [ ] **Step 6: 커밋**

```bash
git add tools/verify/reconcile.py tests/test_verify_tools.py docs/verification/results docs/measurements
git commit -m "feat(V3): 정본 검증기 reconcile — 생성 문서 재생성 비교·fact 마커·출처불명 수치·override provenance·raw↔typed (spec §4.5 축 9)

다음: 플랜 2(V4~V7) 작성 — 판정 단계 H·모델 확장·xlsx"
```

---

## Self-Review (작성자 체크 결과)

- **Spec coverage**: §3.4 매니페스트(Task 1) · §4.1 격리(Task 5) · §4.2 추적기(Task 3) · §4.3 대조기·초과분(Task 2, 7, 8) · §4.4 증거 동결(Task 4, 6) · §5 축 1(Task 7·8) 축 2~4(Task 8) 축 5(Task 9) 축 6(Task 7 비교표 + Task 10) 축 7(Task 11) · §6 도달성 픽스처(Task 10). §4.5 정본 검증·축 9(Task 13, 2026-09-05 사용자 원칙 반영 — 실행자 수치·분류·판정 금지, facts.json 인용 + 마커). 축 8(보고서 충실성)·§6 secret/억제/deep 픽스처·§7·§8·§9 V4~V7 은 플랜 2.
- **Placeholder scan**: `<YYYY-MM-DD>`/`<date>`/`N` 은 실행 시 채워지는 값이며, 코드·명령에는 미완성 지시 없음.
- **Type consistency**: `GtEntry.key`, `GtManifest.raw_entries`, `MatchReport.recall_entry(strict=)`, `TraceSink.record/record_raw/to_dict`, `write_evidence(out_dir, *, result, trace, meta)`, `check_known_fp(..., package, advisory, expected_version)`, `evaluate_pair(entry, vuln, fixed)` — 정의와 사용처 일치. `Finding.advisory.aliases` 에 자기 id 포함 관례(`parse_trivy`)를 대조기가 전제함.
