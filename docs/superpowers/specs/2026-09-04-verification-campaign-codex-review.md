# 검증 캠페인(V) 설계 — Codex 독립 검토 원문 (2026-09-04)

- 모드: consult (gstack /codex), reasoning medium, 535k tokens
- 입력: 브레인스토밍 단계의 계획 초안 + message-gate 정답지 사실관계
- 반영: `2026-09-04-verification-campaign-design.md` §12 반영표 참조

---

- [P1] **GT-B denominator가 틀렸다.** 알려진 실제 취약점은 34건이 아니라 최소 46건(기존 TP 34 + 누락 12)이다. 34/34는 secscan recall이 아니라 기존 Trivy 결과 재현율이다. 12건을 별도 “extra”로 두면 기존 scanner의 FN을 ground truth에서 제거하는 셈이다.

- [P1] **이 데이터로 “precision”을 측정할 수 없다.** 알려진 FP 1건과 미완전한 positive 목록만 있다. `our extra findings`를 전수 판정하지 않으면 precision/PPV가 아니라 “known-FP regression + extra triage”다. 이름부터 바꿔야 한다.

- [P1] **현재 계획은 heavily trained-on target을 독립 benchmark처럼 취급한다.** GT-A로 custom rule을 만들었으므로 같은 커밋 재측정은 regression이지 일반화 성능이 아니다. message-gate 하나로 제품 수준 recall/precision을 주장하면 misleading하다.

- [P1] **Trivy DB drift를 CVE 공개일로 사후 보정하는 것은 불충분하다.** 공개일과 DB ingest 시점은 다르고, advisory 수정·withdrawal·package range 변경·severity 변경도 발생한다. Trivy의 공식 옵션은 기존 cache를 쓰는 `--skip-db-update`이지 임의 날짜의 DB를 복원하는 기능이 아니다. 공식 OCI tag도 날짜 tag가 아니라 schema tag가 기본이다. 2026-08-31 cache 또는 당시 OCI digest가 보존돼 있지 않으면 정확한 역사 재현은 불가능하다. scanner binary, vuln DB, jar 식별용 Java DB까지 함께 고정해야 한다. [Trivy DB 문서](https://github.com/aquasecurity/trivy/blob/main/docs/guide/configuration/db.md), [trivy-db 저장소](https://github.com/aquasecurity/trivy-db)

- [P1] **DB를 못 고정하면 34/34를 pass criterion으로 둘 수 없다.** “historical reproduction”과 “current effectiveness”를 분리해야 한다. 전자는 당시 raw JSON/cache가 기준이고, 후자는 46건 전체를 현재 DB로 재평가해야 한다.

- [P1] **jar와 BOM은 같은 input surface가 아니다.** GT-B 재현의 canonical surface는 당시 배포 대상과 동일한 built artifact다. secscan 제품 경로의 canonical surface는 resolved Gradle runtime graph/SBOM이다. 하나를 primary, 다른 하나를 secondary로 뭉개지 말고 별도 실험으로 취급해야 한다:
  - artifact detection accuracy
  - dependency inventory accuracy
  - vulnerability matching accuracy

- [P1] **“같은 commit”만으로 동일 dependency set이 보장되지 않는다.** lockfile이 없으므로 repository metadata, dynamic/transitive resolution, plugin 동작에 따라 8월 31일과 다른 JAR가 만들어질 수 있다. 당시 artifact 또는 resolved dependency report와 checksums가 없으면 GT-B 입력 재현이 아니다.

- [P1] **mssql 비탐지만 확인하면 거짓 pass가 가능하다.** component 자체를 BOM/JAR에서 누락해도 “CVE 미보고” 조건을 통과한다. 반드시 `13.2.1.jre11` component 존재 → purl/version 보존 → vulnerability range 판정 결과 비해당의 3단계를 각각 검증해야 한다.

- [P1] **현재 reachability와 human verdict는 의미가 다르다.** 구현은 vulnerable method나 call path를 분석하지 않는다. Maven 좌표를 추정 Java package prefix로 바꾼 뒤 앱 코드에 해당 type이 하나라도 보이면 package 전체를 `reachable`, 없으면 `unreachable`로 확정한다. [`depscan.py`](/Users/picpal/Desktop/workspace/security-checker/secscan/reachability/depscan.py) 인간 판정은 HTTP/2, Realm, SiftingAppender, polymorphic typing 같은 CVE-specific activation 조건이다. agreement matrix는 숫자만 그럴듯하고 의미가 없다.

- [P1] **“human unreachable일 때 reachable이라고 하지 않기”도 잘못된 metric이다.** 모든 건을 `unreachable`로 출력하면 만점이다. 안전상 중요한 것은 false-unreachable이다. positive reachable ground truth, abstention rate, unsupported-condition 처리 없이는 측정 불가다.

- [P1] **현재 인간 라벨이 거의 전부 negative라 reachability sensitivity를 검증할 수 없다.** config-gated 건은 현재 엔진에서 `unknown`이 정직한 기대값이다. `unreachable`을 기대하면 package-use heuristic을 안전 증거로 과대평가한다.

- [P1] **SCA 측정 단위가 정의되지 않았다.** `CVE` 단위, `(advisory, package, installed version)` 단위, raw occurrence/target 단위는 결과가 다르다. 현재 dedup key는 component+version+canonical advisory다. CVE-level 34/34는 특정 Spring module 누락을 숨길 수 있다.

- [P1] **alias union matcher는 equivalence를 보장하지 않는다.** alias source/version, canonicalization 규칙, package normalization이 없다. 단순 `id ∪ aliases + package`는 renamed artifact, GHSA-only advisory, alias 충돌, version suffix를 잘못 합치거나 놓칠 수 있다.

- [P1] **pipeline 전체를 검증한다면서 final output만 비교한다.** raw scanner → normalize → merge → exclude → reachability → suppression → output 각 단계별 attrition을 기록해야 한다. 그렇지 않으면 scanner가 찾았지만 normalizer가 버린 FN과 scanner 자체 FN을 구분하지 못한다.

- [P1] **현재 모델로 security-team Excel layout을 충실히 만들 수 없다.** merge가 첫 finding의 `source`만 남기고 raw occurrence count와 복수 target을 버린다. [`merge.py`](/Users/picpal/Desktop/workspace/security-checker/secscan/normalize/merge.py) 따라서 `Targets`, `Finding Count`, CVE별 복수 package aggregation을 사후 복원할 수 없다.

- [P1] **“12 columns”라고 했지만 열거된 기존 열은 11개다.** schema부터 확정되지 않았다. 기존 workbook sample을 golden artifact로 두지 않으면 호환성 주장은 검증 불가능하다.

- [P1] **Markdown/SARIF/xlsx의 lossless round trip 요구는 현재 설계와 충돌한다.** Markdown parser가 없고 `Finding.id`도 출력하지 않는다. SARIF도 aliases, references, source, verified, suppression scope/basis 등 여러 typed field를 잃는다. [`sarif.py`](/Users/picpal/Desktop/workspace/security-checker/secscan/output/sarif.py), [`markdown.py`](/Users/picpal/Desktop/workspace/security-checker/secscan/output/markdown.py) 각 포맷의 명시적 projection contract를 만들거나 lossless canonical JSON을 별도로 추가해야 한다.

- [P1] **CVSS를 singular `score/source`로 모델링하면 다시 정보 손실이 생긴다.** Trivy는 source별 vector/score를 가질 수 있다. `Max CVSS Score`는 Excel용 파생값이어야 하고 canonical model에는 source별 version/vector/score를 보존해야 한다. vendor severity와 CVSS를 섞어 순위를 재계산해서도 안 된다.

- [P1] **stdlib `zipfile`로 XLSX를 직접 구현하는 것은 minimal-deps가 아니라 format implementation을 떠안는 선택이다.** OOXML escaping, styles, shared strings, dimensions, deterministic ZIP metadata, Excel 호환성까지 직접 유지해야 한다. `openpyxl` 같은 단일 dependency가 훨씬 단순하다. zero-dependency가 절대 조건이면 XLSX가 아니라 CSV bundle이 더 정직하다.

- [P1] **Excel formula injection 검증이 필수다.** `=`, `+`, `-`, `@`뿐 아니라 선행 whitespace/control character 뒤 formula marker도 고려해야 한다. apostrophe escaping은 표시값과 raw round-trip을 바꾸므로 canonical raw data와 presentation cell을 분리해야 한다.

- [P1] **GT-A의 “in-category”가 사전 정의되지 않았다.** `(snapshot, file, line/pattern, expected rule, expected category, expected tier)` manifest가 필요하다. `259/760/89/497/489...` 같은 ellipsis와 “100%”는 결과를 보고 분모를 조정할 수 있다.

- [P1] **GT-A의 detection recall과 actionable recall을 섞고 있다.** MyBatis identifier rule과 loadtest findings는 `review`로 강등될 수 있다. “탐지됨”과 “exit-code/우선 조치에 포함됨”을 별도 측정해야 한다.

- [P2] GT-A 재실행은 snapshot provenance와 end-to-end wiring 확인에는 가치가 있다. 새 accuracy 증거는 아니다. 더 나은 신호는 vulnerable/fixed commit pair에서 finding이 정확히 나타났다 사라지는지 보는 differential test다. 170개 commit은 라벨을 먼저 만들지 않으면 단순 commit mining에 불과하다.

- [P1] **mutation의 reachability test가 너무 약하다.** call site 제거는 현재 package-presence heuristic을 그대로 재확인할 뿐이다. 같은 library의 safe API만 사용하는 경우와 vulnerable API를 사용하는 경우, reflection/DI/config activation, transitive-only 호출을 paired fixture로 만들어야 한다.

- [P2] secret mutation은 working tree high/low entropy만으로 부족하다. `gitleaks dir`은 git history scanner가 아니다. working-tree secret, history-only secret, allowlisted example, generated/build 경로, low-entropy credential을 분리해야 한다.

- [P2] deep의 고가치 fixture는 단순 bytecode-only finding보다 `gradlew` 전용 프로젝트, multi-module output, build failure, stale classes를 포함해야 한다. 현재 SpotBugs가 system `gradle`을 호출하는 문제는 이미 알려져 있다.

- [P1] **suppression mutation의 기대가 구현과 맞지 않는다.** version bump는 dedup key가 달라져 suppression이 적용되지 않을 뿐 `invalidated`로 보고되지 않는다. 현재 invalidation list는 같은 scope의 expiry/reachability 변화만 잡는다. 계획대로라면 테스트가 실패하거나, 더 나쁘게 assertion을 약화해 거짓 pass가 된다.

- [P1] **partial failure가 Excel/Markdown/SARIF fidelity 범위에 없다.** 현재 partial failure는 CLI stdout에만 나온다. 성공한 scanner 이름도 실제 status가 아니라 구성된 adapter 이름으로 보고한다. scanner status, version, DB timestamps/digests, command/input surface, target commit을 workbook metadata sheet에 남겨야 한다.

- [P1] **profile contract drift를 계획이 놓쳤다.** spec은 `accurate-sca = Trivy + OSV`, 구현은 `bom-sca` 하나뿐이다. 따라서 SCA consensus는 사실상 동작하지 않는다. [`profiles.py`](/Users/picpal/Desktop/workspace/security-checker/secscan/profiles.py) “각 detection process 검증” 목표라면 profile별 expected adapters와 실제 실행/status부터 검사해야 한다.

- [P1] **재현성 cache가 위험하다.** BOM cache key가 code hash가 아니라 target absolute path뿐이다. 같은 scratch path에서 commit을 바꾸면 stale BOM을 재사용할 수 있다. [`sbom.py`](/Users/picpal/Desktop/workspace/security-checker/secscan/sbom.py) snapshot별 격리 cache 또는 content-addressed key가 선행돼야 한다.

- [P2] 결과 결정성도 검증되지 않았다. adapter 결과는 completion order로 수집되고, merge는 첫 finding의 title/source 등을 유지하며, SARIF는 정렬하지 않는다. XLSX ZIP timestamp까지 포함해 반복 실행 byte stability 또는 semantic stability 기준이 필요하다.

- [P1] **“read-only scan” 표현은 틀렸다.** cdxgen/Gradle/SpotBugs는 scratch checkout과 caches에 쓰며, Gradle build script/plugin은 임의 코드를 실행할 수 있다. 역사적 취약 repo를 build하는 실험은 credential 없는 격리 환경, network policy, writable scratch, 별도 Gradle cache로 실행해야 한다.

- [P1] **pass criterion이 비판정적이다.** “any miss/every disagreement root-caused”는 전부 실패해도 설명만 쓰면 통과한다. 최소 허용 recall, false-unreachable=0, required stage statuses, 허용 가능한 unknown rate 등 명확한 gate가 필요하다.

- [P2] measurement와 XLSX/model 변경을 한 cycle에 섞으면 baseline이 이동한다. 먼저 현행 binary로 raw evidence를 동결하고, 그다음 모델/output을 변경한 뒤 동일 evidence로 regression해야 한다.

## MISSING

- scanner/cdxgen/Java/Gradle 버전과 vuln DB·Java DB digest/timestamp 고정
- exact artifact/SBOM/resolved dependency graph 및 checksum 보존
- advisory-package-version-target 단위의 versioned GT manifest
- 46개 전체 GT-B와 known FP의 evidence status
- stage-by-stage attrition 및 raw lineage/occurrence count
- positive reachable 사례와 false-unreachable 측정
- `unknown`/abstention coverage와 unsupported reason taxonomy
- vulnerable/fixed commit differential checks
- actionable recall, exit code, severity/tier fidelity
- profile-to-adapter contract와 partial-failure reporting
- SAST/secret precision용 fixed snapshot 또는 독립 holdout
- exclusions, `.gitignore`, generated source, multi-module 경계
- build isolation, network/credential safety
- runtime, peak memory, timeout, cache cold/warm 성능
- stale BOM/cache contamination 검사
- Excel formula injection, illegal XML chars, 32,767-char cells, row limit, multiline/Unicode
- workbook schema/version, sheet names, types, filters, deterministic ordering
- consumer compatibility 확인(Excel/LibreOffice/security-team importer)
- suppression expiry/reachability/version/rule-change/baseline 각각의 상태 전이
- compliance mapping completeness/correctness
- canonical lossless JSON 또는 포맷별 projection contract

## 권장 실행 순서

1. **측정 정의 수정 — 0.5~1일**  
   GT 단위, 46 TP/1 known FP, detection vs actionable, historical vs current 실험을 분리한다.

2. **재현성 확보 — 1~2일**  
   당시 raw JSON/artifact/cache 존재 여부 확인, tool/DB pin, isolated caches, target commit과 dependency evidence를 동결한다. 없으면 historical recall 주장을 폐기한다.

3. **GT manifest + stage tracer — 1~2일**  
   raw → normalize → merge → policy → output 단계별 key/lineage를 기록한다.

4. **두 input surface 실험 — 1일**  
   built artifact와 resolved SBOM을 독립 실행하고 inventory 차이, detection 차이, mssql 3단계 조건을 분석한다.

5. **SCA 측정 — 1일**  
   46건 recall, known-FP regression, extras 전수 triage를 수행한다. CVE-level과 package-level 결과를 둘 다 낸다.

6. **reachability 재정의·측정 — 1~2일**  
   기존 human negatives는 capability-gap 분석으로만 쓰고, positive/negative paired fixtures로 false-unreachable와 abstention을 측정한다.

7. **GT-A differential regression — 0.5~1일**  
   각 vulnerable/fixed pair, expected rule/category/tier/exit code만 검증한다. accuracy benchmark라고 부르지 않는다.

8. **모델과 XLSX schema 설계 — 1일**  
   occurrence/targets, CVSS source map, metadata sheet, aggregation 규칙을 먼저 확정한다.

9. **XLSX 구현·호환성/보안 테스트 — 1.5~3일**  
   직접 OOXML 구현은 이 추정치보다 더 커질 가능성이 높다.

10. **mutation·failure·performance 보강 — 1~2일**  
    vulnerable-method pair, history-only secret, transitive runtime dependency, gradlew/build failure, timeout/cache tests를 추가한다.

11. **최종 measurement doc/backlog — 0.5일**  
    pass/fail과 root cause를 분리하고 P1은 제품의 안전성·재현성·FN 순으로 정렬한다.

