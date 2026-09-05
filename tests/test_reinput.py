"""V1 증거(옛 바이너리) raw 를 새 파이프라인에 재입력 — spec §4.4 회귀(baseline 이동 방지)."""
import json
from pathlib import Path

from secscan.models import ACTIONABLE, DEMOTED, REVIEW, UNREACHABLE, sast_tier
from secscan.output.json_io import from_json
from tools.verify.reinput import reinput

EV = Path("docs/verification/evidence/2026-09-05/a483b3b1-standard")


def _legacy_bucket(f):
    # 플랜 1 시점 markdown 버킷 규칙(억제 없음 전제)
    if sast_tier(f) == "review":
        return REVIEW
    if f.category == "sca" and f.reachability.status == UNREACHABLE:
        return DEMOTED
    return ACTIONABLE


def test_reinput_reproduces_v1_keys_and_disposition_matches_legacy_buckets(tmp_path):
    out = reinput(EV, tmp_path)
    new = from_json((tmp_path / "findings.json").read_text(encoding="utf-8"))
    old = from_json((EV / "findings.json").read_text(encoding="utf-8"))
    assert {f.dedup_key for f in new} == {f.dedup_key for f in old}  # excluded_count 0 인 스냅샷
    assert len(new) == len(old) == 73
    assert all(f.disposition == _legacy_bucket(f) for f in new)  # 억제 케이스 없음 → 1:1
    meta = json.loads((tmp_path / "meta.json").read_text(encoding="utf-8"))
    assert meta["reinput_from"].endswith("a483b3b1-standard") and meta["reinput_note"]
    assert {p.name for p in out} >= {"findings.json", "findings.sarif", "report.md", "trace.json", "meta.json"}


def test_reinput_carries_reachability_from_v1_findings(tmp_path):
    reinput(EV, tmp_path)
    new = from_json((tmp_path / "findings.json").read_text(encoding="utf-8"))
    assert sum(1 for f in new if f.category == "sca" and f.reachability.status == UNREACHABLE) == 48
