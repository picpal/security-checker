"""Claude 해석 계층의 파일 인터페이스(spec §5.4). 검증기 통과분만 병합, 거부는 사유와 함께 기록. 스니펫은 넣지 않는다."""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..models import Finding
from .derive import needs_question
from .models import Derived, Interpretation, KbEntry

REQUEST_CONTEXT = "secscan-report-request/v1"
RESPONSE_CONTEXT = "secscan-interpretations/v1"
FORBIDDEN = ("오탐 확정", "안전함", "문제 없음", "억제함", "수정 완료")
MAX_LEN = 600
_CITE = re.compile(r"^[^/\s][^\s]*:\d+(-\d+)?$")
_COUNT = re.compile(r"\d+\s*건")


def build_request(findings: list[Finding], derived: dict[str, Derived], kbs: dict[str, KbEntry], *, target: str,
                  findings_path: str) -> dict:
    items = []
    for f in findings:
        d = derived[f.id]
        if not needs_question(f, d):
            continue
        items.append({"id": f.id, "where": d.where, "rule_id": f.rule_id,
                      "question": kbs[f.id].confirm or "도달 불가 근거(evidence)가 없음 — 실제 호출 경로가 없는지 확인 필요",
                      "facts": [f"룰 {f.rule_id} 발화", d.basis, f"CWE {', '.join(f.cwe) or '-'}"]})
    items.sort(key=lambda i: i["id"])
    return {"@context": REQUEST_CONTEXT, "target": target, "findings": findings_path, "items": items}


def _check_item(item) -> tuple[Interpretation | None, str | None]:
    if not isinstance(item, dict):
        return None, "bad_shape"
    guess, check = item.get("guess"), item.get("check")
    cites = item.get("cites")
    if not isinstance(guess, str) or not isinstance(check, str) or not guess.strip() or not check.strip():
        return None, "empty"
    if len(guess) > MAX_LEN or len(check) > MAX_LEN:
        return None, "too_long"
    if not isinstance(cites, list) or not cites:
        return None, "no_cite"
    for c in cites:
        if not isinstance(c, str) or not _CITE.match(c) or c.startswith("/") or ".." in c.split(":")[0].split("/"):
            return None, "bad_cite"
    for w in FORBIDDEN:
        if w in guess or w in check:
            return None, "verdict_word"
    if _COUNT.search(guess):
        return None, "count_in_guess"
    return Interpretation(guess.strip(), check.strip(), tuple(cites)), None


def validate_response(resp: dict, request: dict) -> tuple[dict[str, Interpretation], list[dict]]:
    known = {i["id"] for i in request.get("items", [])}
    accepted: dict[str, Interpretation] = {}
    rejected: list[dict] = []
    items = resp.get("items") if isinstance(resp, dict) else None
    for fid, item in (items or {}).items():
        if fid not in known:
            rejected.append({"id": fid, "reason": "unknown_id"})
            continue
        it, reason = _check_item(item)
        if it is None:
            rejected.append({"id": fid, "reason": reason})
        else:
            accepted[fid] = it
    return accepted, rejected


def load_interpretations(path, request: dict) -> tuple[dict[str, Interpretation], dict]:
    p = Path(path)
    if not p.exists():
        return {}, {"status": "absent", "rejected": []}
    try:
        resp = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}, {"status": "unreadable", "rejected": []}
    if not isinstance(resp, dict) or resp.get("@context") != RESPONSE_CONTEXT:
        return {}, {"status": "bad_context", "rejected": []}
    accepted, rejected = validate_response(resp, request)
    return accepted, {"status": "ok", "rejected": rejected}
