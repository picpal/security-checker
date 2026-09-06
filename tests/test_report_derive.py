"""파생 규칙(spec §5.2) — 표 기반, disposition 은 읽기만. 픽스처 15건으로 분포를 고정한다."""
from pathlib import Path

import pytest

from secscan.models import DEMOTED, REVIEW, Finding, Location, Reachability, Suppression
from secscan.output.json_io import from_json
from secscan.report.derive import (basis, conclusion, counts, derive_all, needs_question, owner, priority,
                                   sort_for_report, where)
from secscan.report.kb import entry_for
from secscan.report.models import (OWNER_AUTO, OWNER_AUTO_LOW, OWNER_HUMAN, OWNER_NONE, OWNER_SUPPRESSED, KbEntry)

FS = from_json(Path("fixtures/report/work-note-findings.json").read_text(encoding="utf-8"))
BY = {f.id: f for f in FS}
KBS = {f.id: entry_for(f) for f in FS}


def _kb(action="code-fix", ctx=True, done="재스캔 {id} 부재 {package}"):
    return KbEntry("n", "w", "y", "h", action, ctx, confirm="q" if ctx else "", done=done)


def _f(disposition, severity="medium", category="sast", tier=None, **kw):
    return Finding(category=category, severity=severity, title="t", tool="x", rule_id="r", disposition=disposition, tier=tier,
                   location=Location("a/b.java", 3), **kw)


@pytest.mark.parametrize("disp,sev,expect", [
    ("actionable", "critical", "P1"), ("actionable", "high", "P1"), ("actionable", "medium", "P2"), ("actionable", "unknown", "P2"),
    ("review", "high", "P3"), ("demoted", "critical", "P4"), ("suppressed", "high", "P5"), (None, "high", "P3"),
])
def test_priority_table(disp, sev, expect):
    assert priority(_f(disp, sev)) == expect


@pytest.mark.parametrize("disp,action,ctx,expect", [
    ("actionable", "code-fix", False, OWNER_AUTO), ("actionable", "code-fix", True, OWNER_HUMAN),
    ("review", "upgrade", False, OWNER_HUMAN), ("demoted", "upgrade", False, OWNER_AUTO_LOW),
    ("demoted", "code-fix", False, OWNER_NONE), ("suppressed", "upgrade", False, OWNER_SUPPRESSED), (None, "upgrade", False, OWNER_HUMAN),
])
def test_owner_table(disp, action, ctx, expect):
    assert owner(_f(disp), _kb(action, ctx)) == expect


def test_basis_sentences_per_category_and_suppression():
    assert basis(BY["356e4bbab00c"]) == "SAST · 룰 신뢰도 high → tier actionable → 조치대상"
    assert basis(BY["0442ba114c70"]) == "SCA · 도달성 unreachable(dep-scan, evidence 없음) → 강등(낮은 우선순위)"
    assert basis(BY["108d8ee4651c"]) == "Secret · 억제 없음 → 조치대상"
    sup = _f("suppressed", suppression=Suppression("suppressed", "r", "p", "e", "2026-12-31", "k", basis="unreachable"))
    assert basis(sup).startswith("억제(unreachable, 만료 2026-12-31) → SAST ·")


def test_where_and_done_substitution():
    assert where(BY["356e4bbab00c"]) == "backend/src/main/java/com/worknote/admin/BreakGlassFile.java:88"
    assert where(BY["0442ba114c70"]) == "org.apache.tomcat.embed:tomcat-embed-core@10.1.55"
    d = derive_all([BY["0442ba114c70"]], {"0442ba114c70": _kb("upgrade", False)})
    assert d["0442ba114c70"].done == "재스캔 0442ba114c70 부재 org.apache.tomcat.embed:tomcat-embed-core"


def test_fixture_distribution_is_fixed():
    d = derive_all(FS, KBS)
    assert sorted(x.priority for x in d.values()) == ["P1"] * 2 + ["P2"] * 6 + ["P3"] * 3 + ["P4"] * 4
    owners = [x.owner for x in d.values()]
    assert owners.count(OWNER_HUMAN) == 11 and owners.count(OWNER_AUTO_LOW) == 4 and owners.count(OWNER_AUTO) == 0


def test_groups_cover_same_package_target_and_same_file_rule_only():
    d = derive_all(FS, KBS)
    tomcat = {d[i].group for i in ("0442ba114c70", "20f2b757fb2c", "e0d713155712")}
    tweaks = {d[i].group for i in ("3db4c52c28e5", "9744de7de162", "57f818868bca")}
    redmine = {d[i].group for i in ("58ed62d06bb5", "6c4480dfa2aa")}
    assert len(tomcat) == 1 and len(tweaks) == 1 and len(redmine) == 1
    assert tweaks == {"G-1"} and redmine == {"G-2"} and tomcat == {"G-3"}  # 정렬 순서대로 번호
    assert d["cae6cff5ca45"].group == "" and d["553c0d6307df"].group == ""  # 단독 / 같은 파일이지만 다른 룰
    assert d["0442ba114c70"].done.endswith("(대표)") and "G-3 대표와 함께 해소" in d["20f2b757fb2c"].done


def test_sort_is_priority_then_severity_then_location_tuple():
    d = derive_all(FS, KBS)
    ids = [f.id for f in sort_for_report(FS, d)]
    assert ids[:2] == ["356e4bbab00c", "108d8ee4651c"]  # P1: 위치 문자열순(backend < docs)
    assert ids.index("3db4c52c28e5") < ids.index("9744de7de162") < ids.index("57f818868bca")  # 줄 번호 정수 비교
    assert ids[-4:] == ["0442ba114c70", "20f2b757fb2c", "e0d713155712", "cae6cff5ca45"]  # P4: critical 먼저


def test_needs_question_for_human_rows_and_demoted_sca_without_evidence():
    d = derive_all(FS, KBS)
    assert needs_question(BY["356e4bbab00c"], d["356e4bbab00c"]) is True
    assert needs_question(BY["0442ba114c70"], d["0442ba114c70"]) is True  # demoted + evidence None
    with_ev = Finding(category="sca", severity="high", title="t", tool="trivy", rule_id="CVE-9", disposition=DEMOTED,
                      reachability=Reachability("unreachable", evidence="no call path", source="dep-scan"))
    assert needs_question(with_ev, derive_all([with_ev], {with_ev.id: _kb("upgrade", False)})[with_ev.id]) is False


def test_counts_and_conclusion_template():
    d = derive_all(FS, KBS)
    c = counts(FS, d)
    assert c == {"total": 15, "actionable": 8, "auto": 0, "human": 8, "review": 3, "demoted": 4, "auto_low": 4, "suppressed": 0}
    meta = {"scanner_status": [{"tool": "gitleaks", "status": "ok"}, {"tool": "semgrep", "status": "ok"}, {"tool": "trivy", "status": "failed"}],
            "excluded_count": 23}
    assert conclusion(c, meta) == ("총 15건. 즉시 조치 대상 8건(자동 수정 0, 사람 확인 후 8). 검토 후보 3건. "
                                   "도달 불가 강등 4건(업그레이드 가능 4). 억제됨 0건. 스캐너 2종 정상 / 1종 실패. 제외 23건.")
