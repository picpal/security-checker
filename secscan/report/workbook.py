"""보고서 워크북 5 시트(spec §5.5). 순수·결정적. 저장은 output/xlsx.py 의 write_xlsx/write_csv_bundle 재사용.
셀 채움 색은 없다(Sheet 는 값만) — 사실/추정은 열로 분리한다. 비밀값은 어느 시트에도 싣지 않는다."""
from __future__ import annotations

from pathlib import Path

from ..models import Finding
from ..output._status import status_rows
from ..output.xlsx import Sheet, _openpyxl_available, sanitize_cell, write_csv_bundle, write_xlsx
from .derive import SEV_KO, conclusion, counts, needs_question, sort_for_report
from .models import Derived, Interpretation, KbEntry

SHEET_SUMMARY, SHEET_ACTIONS, SHEET_QUESTIONS, SHEET_RULES, SHEET_RESULT = "0_요약", "1_조치목록", "2_확인질문", "3_판정기준", "4_결과반환"
SUMMARY_HEADER = ["항목", "값", "설명"]
ACTION_HEADER = ["No.", "우선순위", "ID", "문제", "위치", "의존 경로", "무엇이 문제인가", "왜 위험한가", "해야 할 일", "조치 유형",
                 "담당", "같이 해결", "판정 근거", "심각도", "CWE", "기준(KISA/PCI)", "완료 확인 방법"]
QUESTION_HEADER = ["No.", "ID", "위치", "질문", "사실(측정)", "추정(Claude 해석)", "확인 방법", "인용", "선택지"]
RULES_HEADER = ["항목", "규칙 / 뜻"]
RESULT_HEADER = ["ID", "status", "changed_files", "verification", "question_or_reason", "commit"]
CHOICES = "① 수정(해야 할 일대로) ② 억제(사유·증거·만료를 --suppressions 파일에 기록) ③ 스캔 제외(비배포 경로, --exclude)"
RULE_ROWS = [
    ["판정(disposition) 규칙", "억제 있음 → 억제됨 / SAST → tier actionable 이면 조치대상, 아니면 검토후보 / SCA → 도달 불가면 강등, 아니면 조치대상 / Secret → 조치대상"],
    ["우선순위 규칙", "P1 = 조치대상 & 심각·위험 / P2 = 조치대상 & 보통 이하 / P3 = 검토후보(또는 미판정) / P4 = 강등 / P5 = 억제됨"],
    ["담당 규칙", "조치대상 & 룰이 문맥 무관 → 자동 수정(LLM) / 조치대상 & 문맥 필요 → 사람 확인 후 / 검토후보 → 사람 확인 후 / 강등 & 업그레이드 가능 → 자동 수정 가능(LLM, 비차단) / 강등 그 외 → 조치 불필요(모니터링)"],
    ["심각도 뜻", "심각·위험: 악용 시 인증 우회·데이터 유출 수준 / 보통: 조건부 위험 / 낮음: 제한적 / 미상: 도구가 심각도를 주지 않음(설정 권고류)"],
    ["도달성 주의", "'도달 불가' 는 정적 분석이 호출 경로를 못 찾았다는 뜻. 리플렉션·DI·역직렬화·애노테이션 라우팅은 놓칠 수 있어 우선순위 강등 근거일 뿐 안전 보증이 아님. evidence 가 없으면 근거가 더 약함"],
    ["사실 / 추정 구분", "사실(측정) = 도구 출력 또는 코드에서 직접 확인한 것. 추정(Claude 해석) = 코드 문맥으로 해석한 것이며 반드시 '확인 방법'·'인용' 이 따라붙음. 추정은 사람 확인 전 판정 근거로 쓰지 않음"],
    ["자동 억제 없음", "억제(오탐 확정)는 사람이 사유·증거·만료를 --suppressions 파일에 적어 확정. 도구도 LLM 도 스스로 억제하지 않음"],
    ["조치 유형", "upgrade 의존성 업그레이드 / externalize-secret 비밀값 외부화·회수 / sanitize-html HTML 정화 / replace-api 안전한 API 로 교체 / config-change 설정 추가·변경 / code-fix 코드 수정 / confirm-only 사람 확인만"],
    ["같이 해결", "같은 패키지·같은 목표 버전(SCA) 또는 같은 파일·같은 룰(SAST/Secret)인 항목은 G-n 으로 묶임. 대표 행 하나를 고치면 나머지도 함께 해소"],
]


def guard_rows(target: str) -> list[list]:
    pad = ["", "", "", ""]
    return [
        ["#허용 범위", "'1_조치목록' 의 담당 열이 '자동' 으로 시작하는 행만 수정한다. '사람 확인 후' 행은 수정하지 않고 '2_확인질문' 의 질문을 status=needs_confirmation 으로 옮긴다."] + pad,
        ["#금지", "억제 파일 작성·수정 / 스캔 제외 규칙 추가 / 테스트 삭제·약화 / 조치목록에 없는 파일 변경 / 스캐너·룰 설정 변경"] + pad,
        ["#완료 판정", f"수정 뒤 `secscan scan --target {target} --profile standard --out <dir>` 를 1회 실행하고 findings.json 에서 ID 를 검색한다. 판정 기준은 '1_조치목록' 의 '완료 확인 방법' 열."] + pad,
        ["#status 값", "fixed | skipped(사유 필수) | needs_confirmation(질문 필수) 세 값만"] + pad,
    ]


def _cwe(f: Finding) -> str:
    return ", ".join(f.cwe) or "해당없음"


def _std(f: Finding) -> str:
    c = f.compliance
    if not c:
        return "해당없음"
    k = ", ".join(f"KISA {w.code} {w.name}" for w in c.kisa)
    p = ", ".join(c.pci)
    return " · ".join(x for x in (k, p) if x) or "-"


def _san(rows: list[list]) -> list[list]:
    return [[sanitize_cell(c) for c in r] for r in rows]


def _summary_rows(findings, meta, kbs, derived, interp_meta) -> list[list]:
    c = counts(findings, derived)
    rows = [["대상", meta.get("target", ""), ""], ["프로파일", meta.get("profile", ""), ""]]
    for s in status_rows(meta):
        rows.append([f"스캐너 {s['tool']}", s["status"], f"{s.get('duration_s') or ''}s {s.get('message') or ''}".strip()])
    rows.append(["결론", conclusion(c, meta), "규칙 파생 문장(숫자 손기입 없음)"])
    rows += [
        ["즉시 조치 대상(P1·P2)", c["actionable"], f"규칙상 조치대상. 자동 수정 {c['auto']} · 사람 확인 후 {c['human']}"],
        ["검토 후보(P3)", c["review"], "도구 신뢰도 낮음 또는 심각도 미상. 사람이 보고 결정"],
        ["강등(P4)", c["demoted"], f"호출 경로 없음으로 판정. 업그레이드 가능 {c['auto_low']}(비차단)"],
        ["억제됨(P5)", c["suppressed"], "사람이 확정한 억제. 만료·버전 변경 시 재표면"],
        ["제외", meta.get("excluded_count", 0), "build/·node_modules/·.gitignore 대상 등 기본 제외"],
        ["시트 1_조치목록", "개발자·보안팀", "항목별 무엇/왜/어떻게/담당/근거/완료 확인"],
        ["시트 2_확인질문", "담당 개발자·보안팀", "사람이 답해야 LLM 이 움직일 수 있는 항목의 질문·사실·추정"],
        ["시트 3_판정기준", "보안팀·감사", "우선/검토/강등이 갈린 규칙, 용어 뜻"],
        ["시트 4_결과반환", "수정 LLM → 사람", "허용 범위·금지 4줄 + LLM 이 채워 돌려주는 템플릿"],
    ]
    composed = sorted({f.rule_id for f in findings if f.category != "sca" and kbs[f.id].source == "composed"})
    rows.append(["지식베이스 미등록 룰", ", ".join(composed) or "없음", "합성 폴백으로 설명됨 — rules.json 등록 대기"])
    im = interp_meta or {"status": "absent", "rejected": []}
    rej = "; ".join(f"{r['id']}: {r['reason']}" for r in im.get("rejected", []))
    rows.append(["해석 상태", im.get("status", "absent"), rej or "거부 없음"])
    return rows


def build_report_sheets(findings: list[Finding], meta: dict, kbs: dict[str, KbEntry], derived: dict[str, Derived],
                        interps: dict[str, Interpretation] | None = None, interp_meta: dict | None = None) -> dict[str, Sheet]:
    interps = interps or {}
    ordered = sort_for_report(findings, derived)
    actions, questions, results = [], [], []
    for i, f in enumerate(ordered, 1):
        kb, d = kbs[f.id], derived[f.id]
        actions.append([i, d.priority, f.id, kb.name, d.where, d.deppath, kb.what, kb.why, kb.how, kb.action, d.owner, d.group,
                        d.basis, SEV_KO.get(f.severity, f.severity), _cwe(f), _std(f), d.done])
        results.append([f.id, "", "", "", "", ""])
        if needs_question(f, d):
            it = interps.get(f.id)
            fact = f"룰 {f.rule_id} 발화 · {d.basis} · CWE {_cwe(f)}"
            questions.append([i, f.id, d.where, kb.confirm or "도달 불가 근거(evidence)가 없음 — 실제 호출 경로가 없는지 확인 필요",
                              fact, it.guess if it else "", it.check if it else "", ", ".join(it.cites) if it else "", CHOICES])
    return {
        SHEET_SUMMARY: (SUMMARY_HEADER, _san(_summary_rows(findings, meta, kbs, derived, interp_meta))),
        SHEET_ACTIONS: (ACTION_HEADER, _san(actions)),
        SHEET_QUESTIONS: (QUESTION_HEADER, _san(questions)),
        SHEET_RULES: (RULES_HEADER, _san([list(r) for r in RULE_ROWS])),
        SHEET_RESULT: (RESULT_HEADER, _san(guard_rows(str(meta.get("target", ""))) + results)),
    }


def write_report(sheets: dict[str, Sheet], out_dir, *, created: str, prefer_xlsx: bool | None = None) -> tuple[list[Path], str | None]:
    out = Path(out_dir)
    use_xlsx = _openpyxl_available() if prefer_xlsx is None else prefer_xlsx
    if use_xlsx:
        return [write_xlsx(sheets, out / "report.xlsx", created=created)], None
    return write_csv_bundle(sheets, out / "report-xlsx"), "openpyxl 미설치 — report 시트별 CSV 번들로 대체(`pip install secscan[xlsx]`)"
