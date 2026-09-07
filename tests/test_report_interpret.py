"""Claude 해석 파일 인터페이스(spec §5.4) — request 생성, response 검증(거부 사유 전수), 부재 처리."""
import json
from pathlib import Path

import pytest

from secscan.output.json_io import from_json
from secscan.report.derive import derive_all
from secscan.report.interpret import (FORBIDDEN, MAX_LEN, REQUEST_CONTEXT, RESPONSE_CONTEXT, build_request,
                                      load_interpretations, validate_response)
from secscan.report.kb import entry_for

FS = from_json(Path("fixtures/report/work-note-findings.json").read_text(encoding="utf-8"))
KBS = {f.id: entry_for(f) for f in FS}
DER = derive_all(FS, KBS)
REQ = build_request(FS, DER, KBS, target="work-note", findings_path="out/findings.json")
CITE = "backend/src/main/java/com/worknote/admin/BreakGlassFile.java:87-89"


def _resp(items):
    return {"@context": RESPONSE_CONTEXT, "written_at": "2026-09-07", "items": items}


def _ok(**kw):
    d = {"guess": "상수 PASSWORD 가 KNOWN_KEYS 집합에 들어감.", "check": "88행 리터럴 값 확인.", "cites": [CITE]}
    d.update(kw)
    return d


def test_request_lists_question_items_without_snippets():
    assert REQ["@context"] == REQUEST_CONTEXT and REQ["target"] == "work-note" and REQ["findings"] == "out/findings.json"
    ids = [i["id"] for i in REQ["items"]]
    assert len(ids) == 15 and "356e4bbab00c" in ids and "0442ba114c70" in ids
    item = next(i for i in REQ["items"] if i["id"] == "356e4bbab00c")
    assert item["where"].endswith("BreakGlassFile.java:88") and item["question"] and item["rule_id"]
    assert item["facts"][0].startswith("룰 ") and not any(k in item for k in ("snippet", "code", "lines"))


def test_valid_response_is_accepted():
    acc, rej = validate_response(_resp({"356e4bbab00c": _ok()}), REQ)
    assert rej == [] and acc["356e4bbab00c"].cites == (CITE,) and acc["356e4bbab00c"].check == "88행 리터럴 값 확인."


@pytest.mark.parametrize("item_id,item,reason", [
    ("deadbeef0000", _ok(), "unknown_id"),
    ("356e4bbab00c", _ok(guess=""), "empty"),
    ("356e4bbab00c", _ok(check=""), "empty"),
    ("356e4bbab00c", _ok(guess="x" * (MAX_LEN + 1)), "too_long"),
    ("356e4bbab00c", _ok(cites=[]), "no_cite"),
    ("356e4bbab00c", _ok(cites=["BreakGlassFile.java"]), "bad_cite"),
    ("356e4bbab00c", _ok(cites=["/abs/path.java:1"]), "bad_cite"),
    ("356e4bbab00c", _ok(cites=["../x.java:1"]), "bad_cite"),
    ("356e4bbab00c", _ok(guess="이건 오탐 확정이다."), "verdict_word"),
    ("356e4bbab00c", _ok(check="안전함"), "verdict_word"),
    ("356e4bbab00c", _ok(guess="비슷한 것이 3건 더 있다."), "count_in_guess"),
    ("356e4bbab00c", "not a dict", "bad_shape"),
])
def test_rejection_reasons(item_id, item, reason):
    acc, rej = validate_response(_resp({item_id: item}), REQ)
    assert acc == {} and rej == [{"id": item_id, "reason": reason}]


def test_forbidden_words_are_the_spec_list():
    assert FORBIDDEN == ("오탐 확정", "안전함", "문제 없음", "억제함", "수정 완료")


def test_load_absent_bad_context_and_ok(tmp_path):
    acc, meta = load_interpretations(tmp_path / "none.json", REQ)
    assert acc == {} and meta == {"status": "absent", "rejected": []}
    p = tmp_path / "bad.json"; p.write_text(json.dumps({"@context": "other/v9", "items": {}}), encoding="utf-8")
    assert load_interpretations(p, REQ)[1]["status"] == "bad_context"
    p2 = tmp_path / "broken.json"; p2.write_text("{not json", encoding="utf-8")
    assert load_interpretations(p2, REQ)[1]["status"] == "unreadable"
    p3 = tmp_path / "ok.json"; p3.write_text(json.dumps(_resp({"356e4bbab00c": _ok(), "zzz": _ok()})), encoding="utf-8")
    acc, meta = load_interpretations(p3, REQ)
    assert set(acc) == {"356e4bbab00c"} and meta == {"status": "ok", "rejected": [{"id": "zzz", "reason": "unknown_id"}]}
