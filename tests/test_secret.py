"""M2 Secret — Gitleaks 정규화(골든) + 어댑터.

골든: 시크릿 픽스처에 실제 gitleaks 를 돌린 출력. secret 은 위치형(location) finding.
보안상 raw 시크릿 값은 Finding 에 저장하지 않는다(보고서 재유출 방지).
"""

import json
from pathlib import Path

from secscan.adapters.base import OK
from secscan.adapters.gitleaks import GitleaksAdapter
from secscan.normalize.gitleaks import parse_gitleaks

GOLDEN = Path(__file__).parent / "golden" / "gitleaks-secret-app.json"


def _golden():
    return GOLDEN.read_text()


def test_parse_gitleaks_produces_secret_findings():
    findings = parse_gitleaks(_golden())
    assert len(findings) == 3
    rules = {f.rule_id for f in findings}
    assert {"aws-access-token", "github-pat", "generic-api-key"} <= rules


def test_gitleaks_finding_is_location_based():
    f = next(f for f in parse_gitleaks(_golden()) if f.rule_id == "aws-access-token")
    assert f.category == "secret"
    assert f.location is not None
    assert f.location.file.endswith("application.properties")
    assert f.location.start_line == 4
    assert f.tool == "gitleaks"


def test_gitleaks_does_not_store_raw_secret_value():
    # 보고서/SARIF 에 실제 시크릿이 새지 않도록 raw 값 미저장
    raw = json.loads(_golden())
    secret_values = [x["Secret"] for x in raw]
    findings = parse_gitleaks(_golden())
    blob = repr([(f.title, f.rule_id, f.location.snippet_ref) for f in findings])
    for sv in secret_values:
        assert sv not in blob


def test_parse_gitleaks_empty_payload():
    assert parse_gitleaks("") == []
    assert parse_gitleaks("[]") == []


def test_gitleaks_adapter_build_argv():
    argv = GitleaksAdapter().build_argv("/proj", "/tmp/r.json")
    assert argv[:2] == ["gitleaks", "dir"]
    assert "/proj" in argv
    assert argv[argv.index("--report-format") + 1] == "json"
    assert "/tmp/r.json" in argv


def test_gitleaks_adapter_real_scan_offline():
    # gitleaks 는 네트워크 불필요(파일만) → 샌드박스에서 실제 실행 가능
    fixture = Path(__file__).parent.parent / "fixtures" / "secret-app"
    r = GitleaksAdapter().run(str(fixture))
    assert r.status == OK
    assert r.tool == "gitleaks"
    findings = parse_gitleaks(r.payload)
    assert len(findings) == 3
