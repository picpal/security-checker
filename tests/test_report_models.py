"""보고서 모델(spec §6) — 상수 닫힌 집합, 픽스처가 상대경로·비밀값 없이 로드된다."""
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from secscan.output.json_io import from_json
from secscan.report.models import (ACTIONS, OWNER_AUTO, OWNER_HUMAN, PRIORITIES, RESULT_STATUSES, Derived,
                                   Interpretation, KbEntry, ResultRow)

FIX = Path("fixtures/report/work-note-findings.json")


def test_constants_are_closed_sets():
    assert ACTIONS == ("upgrade", "externalize-secret", "sanitize-html", "replace-api", "config-change", "code-fix", "confirm-only")
    assert PRIORITIES == ("P1", "P2", "P3", "P4", "P5")
    assert RESULT_STATUSES == ("fixed", "skipped", "needs_confirmation")
    assert OWNER_AUTO == "자동 수정(LLM)" and OWNER_HUMAN == "사람 확인 후"


def test_models_are_frozen_with_defaults():
    e = KbEntry("n", "w", "y", "h", "upgrade", False)
    assert e.confirm == "" and e.done == "" and e.source == "composed"
    with pytest.raises(FrozenInstanceError):
        e.name = "x"
    assert Derived("P1", OWNER_HUMAN, "b", "", "d", "w").deppath == ""
    assert Interpretation("g", "c").cites == ()
    assert ResultRow("abc", "fixed").commit == ""


def test_fixture_loads_relative_paths_and_no_secret_values():
    text = FIX.read_text(encoding="utf-8")
    fs = from_json(text)
    assert len(fs) == 15
    assert "/Users/" not in text and "pend-" not in text and "ghp_" not in text
    assert all(not f.location.file.startswith("/") for f in fs if f.location)
    assert {f.id for f in fs} >= {"356e4bbab00c", "108d8ee4651c", "0442ba114c70"}
