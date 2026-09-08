"""보고서 워크북 5 시트(spec §5.5). 순수·결정적. 저장은 output/xlsx.py 의 write_xlsx/write_csv_bundle 재사용.
셀 채움 색은 없다(Sheet 는 값만) — 사실/추정은 열로 분리한다. 비밀값은 어느 시트에도 싣지 않는다."""
from __future__ import annotations

from datetime import datetime
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
RULES_HEADER = ["구분", "값·용어", "뜻(일반어)", "그래서 어떻게 하나"]
RESULT_HEADER = ["ID", "처리 결과", "바꾼 파일", "검증(재스캔에서 ID 가 사라졌는가)", "질문 또는 사유", "커밋", "문제(참고)", "담당(참고)", "위치(참고)"]
CHOICES = "① 수정(해야 할 일대로) ② 억제(사유·증거·만료를 --suppressions 파일에 기록) ③ 스캔 제외(비배포 경로, --exclude)"
RULE_ROWS = [
    # 우선순위 — "언제 처리하나"
    ["우선순위", "P1 지금 바로", "조치대상이면서 심각·위험", "가장 먼저 처리. 담당 열대로 자동 수정 또는 사람 확인"],
    ["우선순위", "P2 이번 사이클", "조치대상이지만 보통 이하", "계획에 넣어 처리"],
    ["우선순위", "P3 사람이 먼저 봐야 함", "도구가 확신하지 못함(신뢰도 낮음·심각도 미상)", "2_확인질문에 답한 뒤 수정 또는 억제"],
    ["우선순위", "P4 급하지 않음", "취약한 라이브러리지만 우리 코드가 그 부분을 호출하지 않는 것으로 분석됨", "정기 업그레이드로 처리. 배포를 막지 않음"],
    ["우선순위", "P5 이미 결정됨", "사람이 오탐·수용으로 억제함(사유·만료 있음)", "만료일에 재검토"],
    # 담당 — "누가 하나"
    ["담당", "자동 수정(LLM)", "문맥 확인 없이 고칠 수 있는 항목", "LLM 이 바로 고치고 4_결과반환에 적음"],
    ["담당", "사람 확인 후", "값의 출처·배포 여부처럼 사람만 아는 사실이 필요", "2_확인질문의 질문에 답하면 진행"],
    ["담당", "자동 수정 가능(LLM, 비차단)", "급하지 않지만 기계적으로 고칠 수 있음(의존성 업그레이드)", "여유 있을 때 처리"],
    ["담당", "조치 불필요(모니터링)", "급하지 않고 기계적 조치도 없음", "다음 점검에서 다시 봄"],
    ["담당", "억제됨", "사람이 이미 결정한 항목", "만료일까지 낮은 우선순위로만 표시"],
    # 판정 근거 열 — "왜 여기로 분류됐나"
    ["판정", "조치대상", "도구가 확신했고 억제 없음", "우선순위 P1·P2"],
    ["판정", "검토후보", "도구 신뢰도가 낮거나 심각도가 없음", "P3"],
    ["판정", "강등(낮은 우선순위)", "도달성 분석이 '호출 경로 없음' 으로 판정", "P4. 단 evidence 가 없으면 근거가 약해 2_확인질문에 포함"],
    ["판정", "억제됨", "사람이 사유·증거·만료를 적어 제외", "P5"],
    # 심각도
    ["심각도", "심각·위험", "악용되면 인증 우회·데이터 유출 수준", "우선 처리"],
    ["심각도", "보통", "조건이 맞아야 위험", "계획 처리"],
    ["심각도", "낮음·미상", "제한적이거나 도구가 심각도를 주지 않음(설정 권고류)", "사람이 판단"],
    # 조치 유형 — "무엇을 하면 되나"
    ["조치 유형", "upgrade", "라이브러리 버전 올리기", "완료 확인 열의 목표 버전 이상으로"],
    ["조치 유형", "externalize-secret", "비밀값을 코드 밖으로 빼고 노출된 값은 폐기·교체", "값 회수가 먼저"],
    ["조치 유형", "sanitize-html", "HTML 을 화면에 그리기 전에 정화", "정화 함수를 거치는지 확인"],
    ["조치 유형", "replace-api", "위험한 API 를 안전한 것으로 교체", "해야 할 일 열 참조"],
    ["조치 유형", "config-change", "설정 파일에 보호 옵션 추가", "설치·CI 동작 변화 검토"],
    ["조치 유형", "code-fix", "코드 수정", "해야 할 일 열 참조"],
    ["조치 유형", "confirm-only", "사람 확인만 필요", "2_확인질문"],
    # 같이 해결
    ["같이 해결", "G-1, G-2 …", "같은 라이브러리·같은 목표 버전, 또는 같은 파일·같은 룰인 항목 묶음", "대표 행 하나를 고치면 나머지도 같이 해소"],
    # 사실과 추정
    ["사실/추정", "사실(측정)", "도구 출력이나 코드에서 직접 확인한 것", "그대로 믿어도 됨"],
    ["사실/추정", "추정(Claude 해석)", "코드 문맥을 읽고 해석한 것. 반드시 '확인 방법'·'인용' 이 붙음", "사람이 확인하기 전에는 판정 근거로 쓰지 않음"],
    # 주의
    ["주의", "도달 불가", "정적 분석이 호출 경로를 못 찾았다는 뜻. 리플렉션·DI·역직렬화는 놓칠 수 있음", "우선순위를 낮추는 근거일 뿐 안전 보증이 아님"],
    ["주의", "자동 억제 없음", "도구도 LLM 도 스스로 항목을 지우지 않음", "억제는 사람이 사유·증거·만료를 --suppressions 파일에 적어 확정"],
]


def guard_rows(target: str) -> list[list]:
    """4_결과반환 상단 안내 행(첫 열이 finding ID 형식이 아니면 안내 행으로 취급된다)."""
    pad = [""] * (len(RESULT_HEADER) - 2)
    return [
        ["이 시트는", "수정을 맡은 LLM(또는 담당자)이 처리 결과를 적어 돌려주는 곳입니다. 아래 표의 한 행이 취약 항목 하나입니다. ID·문제·담당·위치는 미리 채워져 있으니 '처리 결과' 부터 '커밋' 까지만 채우세요."] + pad,
        ["고쳐도 되는 것", "'1_조치목록' 의 담당이 '자동 수정' 으로 시작하는 항목만 고칩니다. '사람 확인 후' 항목은 고치지 말고, '2_확인질문' 의 질문을 '질문 또는 사유' 칸에 옮기고 처리 결과를 needs_confirmation 으로 적으세요."] + pad,
        ["하지 말 것", "억제 파일 만들기·고치기 / 스캔 제외 규칙 추가 / 테스트 삭제·약화 / 조치목록에 없는 파일 변경 / 스캐너·룰 설정 변경"] + pad,
        ["끝났는지 확인하는 법", f"고친 뒤 `secscan scan --target {target} --profile standard --out <폴더>` 를 한 번 실행하고, 새 findings.json 에 그 ID 가 남아 있는지 봅니다. 없으면 고쳐진 것입니다. 항목별 기준은 '1_조치목록' 의 '완료 확인 방법' 열입니다."] + pad,
        ["처리 결과에 쓸 수 있는 값", "fixed = 고쳤고 재스캔에서 사라짐 · skipped = 건너뜀(사유 필수) · needs_confirmation = 사람 확인 필요(질문 필수). 이 세 값만 씁니다."] + pad,
        ["검증은 누가 하나", "사람이 믿기 전에 `secscan report --check-result <이 파일> --rescan <새 findings.json>` 으로 기계가 대조합니다. fixed 라고 적었는데 ID 가 남아 있으면 불일치로 잡힙니다."] + pad,
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
        results.append([f.id, "", "", "", "", "", kb.name, d.owner, d.where])
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
        path = write_xlsx(sheets, out / "report.xlsx", created=created)
        _style_xlsx(path, created)
        return [path], None
    return write_csv_bundle(sheets, out / "report-xlsx"), "openpyxl 미설치 — report 시트별 CSV 번들로 대체(`pip install secscan[xlsx]`)"


# 열 너비는 내용 길이로 자동 계산한다(결정적: 같은 값 → 같은 너비). 한글·전각은 2칸, 하한 MIN_WIDTH, 상한 MAX_WIDTH.
MIN_WIDTH, MAX_WIDTH = 8, 60
FREEZE = {SHEET_ACTIONS: "D2", SHEET_QUESTIONS: "C2"}


def _display_len(v) -> int:
    import unicodedata
    if v is None:
        return 0
    return sum(2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1 for ch in str(v))


def fit_width(values) -> float:
    """열의 셀 값들로 너비를 정한다: 가장 긴 값(줄바꿈 전 첫 줄 기준)에 여유 2를 더하고 [MIN_WIDTH, MAX_WIDTH] 로 자른다."""
    longest = max((_display_len(str(v).split("\n", 1)[0]) for v in values), default=0)
    return float(min(MAX_WIDTH, max(MIN_WIDTH, longest + 2)))


def _style_xlsx(path: Path, created: str) -> None:
    """가독성 서식: 내용 길이 기반 열 너비·줄바꿈·상단 정렬·굵은 헤더·틀고정.
    저장 후 modified 를 created 로 다시 고정해 결정성을 지킨다."""
    from openpyxl import load_workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    from ..output.xlsx import _pin_xlsx_modified

    wb = load_workbook(path)
    for ws in wb.worksheets:
        for col in ws.iter_cols(min_row=1, max_row=ws.max_row):
            ws.column_dimensions[get_column_letter(col[0].column)].width = fit_width(c.value for c in col)
        for row in ws.iter_rows():
            for cell in row:
                cell.alignment = Alignment(wrap_text=True, vertical="top")
        for cell in ws[1]:
            cell.font = Font(bold=True)
            cell.fill = PatternFill("solid", fgColor="D9D9D9")
        ws.freeze_panes = FREEZE.get(ws.title, "A2")
    ts = datetime.fromisoformat(created) if created else datetime(1970, 1, 1)
    wb.properties.created = ts
    wb.properties.modified = ts
    wb.save(path)
    _pin_xlsx_modified(Path(path), ts)
