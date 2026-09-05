# 출력 계약 (projection contract) — 생성 문서

`secscan/output/contracts.py` 의 상수에서 생성된다. 손으로 고치지 말 것(`tests/test_contracts.py` 가 대조).

- ✓ 포함 · ◐ 부분(비고) · ✗ 손실. `findings.json` 만 lossless canonical(spec §7.2), 나머지는 projection(spec §7.3).
- SARIF 는 출력 전용이며 내부 모델이 아니다(원칙 3).

| 필드 | findings.json | markdown | sarif | xlsx |
|---|---|---|---|---|
| `category` | ✓ | ◐ 절(SCA/시크릿 문구)로만 드러남 | ✓ | ✓ |
| `severity` | ✓ | ✓ | ✓ | ✓ |
| `title` | ✓ | ✗ | ✓ | ✓ |
| `tool` | ✓ | ✗ | ✓ | ✓ |
| `rule_id` | ✓ | ✓ | ✓ | ✓ |
| `cwe` | ✓ | ✓ | ✓ | ✓ |
| `owasp` | ✓ | ✗ | ✗ | ✗ |
| `confidence` | ✓ | ✗ | ✓ | ✓ |
| `component` | ✓ | ✓ | ✓ | ✓ |
| `advisory` | ✓ | ◐ fixed_versions 만 | ◐ fixedVersions 만(aliases·cvss·published 손실) | ◐ id·fixed·Max CVSS/Source·Published(aliases 손실) |
| `location` | ✓ | ◐ file·start_line 만 | ◐ file·startLine·endLine(snippet_ref 손실) | ◐ file·line(end_line·snippet_ref 손실) |
| `source` | ✓ | ✗ | ✗ | ✗ |
| `reachability` | ✓ | ✓ | ✓ | ✓ |
| `consensus` | ✓ | ✓ | ✓ | ✓ |
| `references` | ✓ | ✗ | ✗ | ◐ URL 열에 첫 항목만 |
| `verified` | ✓ | ✗ | ✗ | ✓ |
| `suppression` | ✓ | ◐ reason·provenance·expiry 만 | ◐ reason·provenance·evidence·expiry·state(scope·basis 손실) | ◐ 상태 열(reason 만) |
| `compliance` | ✓ | ✓ | ✓ | ✓ |
| `occurrences` | ✓ | ✗ | ✗ | ✓ |
| `disposition` | ✓ | ✗ | ✓ | ✓ |
| `tier` | ✓ | ✗ | ✓ | ✓ |
| `id` | ✓ | ✓ | ✓ | ✓ |

## markdown 추가 규칙
- finding 헤더 줄 끝에 `` · id `<12hex>` `` (억제 스코프 지정용).
- 절(우선 조치/검토 후보/낮은 우선순위/억제됨/미판정)은 `disposition` 필드만 읽는다(재계산 금지).
