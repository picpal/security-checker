"""M3 인수(게이트) — SAST 탐지 + typed 모델 통합 (결정적·오프라인 골든)."""

import json
from pathlib import Path

from secscan.adapters.base import OK, RawResult
from secscan.normalize import to_findings

ROOT = Path(__file__).parent.parent
GOLDEN = ROOT / "tests" / "golden" / "semgrep-sast-app.json"


def test_gate_sast_detection_integrates_into_typed_model():
    findings = to_findings([RawResult("semgrep", OK, payload=GOLDEN.read_text())])
    sast = [f for f in findings if f.category == "sast"]
    assert len(sast) >= 1
    f = sast[0]
    assert "CWE-89" in f.cwe
    assert f.severity == "high"
    assert f.location is not None and f.location.file.endswith("Vuln.java")
    assert f.tool == "semgrep"


def test_gate_ce_taint_limitation_is_documented():
    # spec §10.2: CE intraprocedural taint 한계를 픽스처 ground truth 에 기록
    exp = json.loads((ROOT / "fixtures" / "sast-app" / "expected.json").read_text())
    assert exp["not_detected_ce_limitation"]
    assert "CWE-78" in exp["not_detected_ce_limitation"][0]["cwe"]
