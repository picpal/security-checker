# 보고서 워크북 — work-note 픽스처 측정 (2026-09-07)

> 수치는 아래 스크립트 출력을 그대로 옮긴 것이다(손기입 없음). 재생성: 이 파일 상단 스크립트를 다시 실행.

## 재생성 스크립트

FR-6 으로 `build_report` 호환 래퍼가 사라졌지만 이 스크립트는 처음부터 `build_report_with_request`
를 쓰므로 영향 없다.

```bash
.venv/bin/python - <<'EOF'
import json
from pathlib import Path
from secscan.output.json_io import from_json
from secscan.report.cli import build_report_with_request
fix = Path("fixtures/report/work-note-findings.json").read_text(encoding="utf-8")
fs = from_json(fix); meta = json.loads(fix)["meta"]
sheets, req, im = build_report_with_request(fs, meta, bom="fixtures/report/work-note-bom.cdx.json")
acts = sheets["1_조치목록"][1]
owners = {}
for r in acts: owners[r[10]] = owners.get(r[10], 0) + 1
groups = sorted({r[11] for r in acts if r[11]})
summary = {r[0]: r[1] for r in sheets["0_요약"][1]}
ev = Path("docs/verification/evidence/2026-09-06/a483b3b1-standard/findings.json").read_text(encoding="utf-8")
s2, _, _ = build_report_with_request(from_json(ev), json.loads(ev)["meta"])
composed = {r[0]: r[1] for r in s2["0_요약"][1]}["지식베이스 미등록 룰"]
doc = f"""# 보고서 워크북 — work-note 픽스처 측정 (2026-09-07)

> 수치는 아래 스크립트 출력을 그대로 옮긴 것이다(손기입 없음). 재생성: 이 파일 상단 스크립트를 다시 실행.

## 픽스처 work-note (15건, 2026-09-06 실스캔)
- 결론 문장: {summary['결론']}
- 담당 분포: {json.dumps(owners, ensure_ascii=False)}
- 그룹: {groups}
- 확인질문 항목 수: {len(sheets['2_확인질문'][1])} / request items: {len(req['items'])}
- 의존 경로(tomcat-embed-core): {next(r[5] for r in acts if r[2] == '0442ba114c70')}
- 의존 경로(log4j-api): {next(r[5] for r in acts if r[2] == 'cae6cff5ca45')}
- 지식베이스 미등록 룰: {summary['지식베이스 미등록 룰']}

## message-gate 증거(2026-09-06 a483b3b1-standard)로 본 등록 대기 룰
- {composed}

## dry-run 기준선(2026-09-06, 프로토타입 A 시트 덤프 → sonnet, 수정 금지)
- needs_confirmation 11 · skipped(계획 기록) 4 · fixed 0 · 금지 행동 0 (세션 기록, 재실행은 SDD 컨트롤러 또는 사람이 수행)
- 서브에이전트가 지적한 문서 결함 2건(의존 경로 부재, 완료 판정 단위)은 본 사이클의 '의존 경로'·'같이 해결' 열로 대응. 재실행 시 "판단 어려웠던 점" 5 → 3 이하가 목표.
"""
Path("docs/measurements/2026-09-07-report-workbook-work-note.md").write_text(doc, encoding="utf-8")
print(doc)
EOF
```

## 픽스처 work-note (15건, 2026-09-06 실스캔)
- 결론 문장: 총 15건. 즉시 조치 대상 8건(자동 수정 0, 사람 확인 후 8). 검토 후보 3건. 도달 불가 강등 4건(업그레이드 가능 4). 억제됨 0건. 스캐너 3종 정상 / 0종 실패. 제외 23건.
- 담당 분포: {"사람 확인 후": 11, "자동 수정 가능(LLM, 비차단)": 4}
- 그룹: ['G-1', 'G-2', 'G-3']
- 확인질문 항목 수: 15 / request items: 15
- 의존 경로(tomcat-embed-core): 전이 ← spring-boot-starter-tomcat ← spring-boot-starter-web
- 의존 경로(log4j-api): 전이 ← log4j-to-slf4j ← spring-boot-starter-logging ← spring-boot-starter ← mybatis-spring-boot-starter
- 지식베이스 미등록 룰: 없음

## message-gate 증거(2026-09-06 a483b3b1-standard)로 본 등록 대기 룰
- 없음

## dry-run 기준선(2026-09-06, 프로토타입 A 시트 덤프 → sonnet, 수정 금지)
- needs_confirmation 11 · skipped(계획 기록) 4 · fixed 0 · 금지 행동 0 (세션 기록, 재실행은 SDD 컨트롤러 또는 사람이 수행)
- 서브에이전트가 지적한 문서 결함 2건(의존 경로 부재, 완료 판정 단위)은 본 사이클의 '의존 경로'·'같이 해결' 열로 대응. 재실행 시 "판단 어려웠던 점" 5 → 3 이하가 목표.
