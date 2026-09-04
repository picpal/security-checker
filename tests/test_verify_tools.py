"""tools/verify — 스냅샷 격리·증거 작성기(부수효과는 runner 주입으로 결정적 검증)."""

import json
from pathlib import Path

from secscan.adapters.base import FAILED, OK, RawResult
from secscan.scan import ScanResult, TraceSink
from tools.verify.evidence import redact_gitleaks, tool_versions, write_evidence
from tools.verify.snapshot import isolated_env, prepare_snapshot

GOLDEN = Path(__file__).parent / "golden"


def test_prepare_snapshot_clones_local_and_checks_out(tmp_path):
    calls = []

    def fake_run(argv, **kw):
        calls.append(argv)
        if argv[:2] == ["git", "clone"]:
            Path(argv[-1]).mkdir(parents=True)
        class R: returncode = 0
        return R()

    dest = prepare_snapshot(Path("/repo"), "abc123", tmp_path, run=fake_run)
    assert dest == tmp_path / "abc123" / "repo"
    assert calls[0] == ["git", "clone", "--local", "--no-checkout", "/repo", str(dest)]
    assert calls[1] == ["git", "-C", str(dest), "checkout", "--detach", "abc123"]
    # 두 번째 호출은 재사용(clone 없음)
    calls.clear()
    prepare_snapshot(Path("/repo"), "abc123", tmp_path, run=fake_run)
    assert calls == []


def test_isolated_env_strips_credentials_and_sets_gradle_home(tmp_path):
    base = {"PATH": "/bin", "GITHUB_TOKEN": "x", "AWS_SECRET_ACCESS_KEY": "y",
            "DB_PASSWORD": "z", "MY_API_KEY": "k", "HOME": "/h", "JAVA_HOME": "/j"}
    env = isolated_env(tmp_path, "abc123", base)
    assert "GITHUB_TOKEN" not in env and "AWS_SECRET_ACCESS_KEY" not in env
    assert "DB_PASSWORD" not in env and "MY_API_KEY" not in env
    assert env["PATH"] == "/bin" and env["JAVA_HOME"] == "/j"
    assert env["GRADLE_USER_HOME"] == str(tmp_path / "abc123" / "gradle-home")
    assert env["SECSCAN_VERIFY_ISOLATED"] == "1"


def test_redact_gitleaks_blanks_secret_and_match():
    payload = (GOLDEN / "gitleaks-secret-app.json").read_text()
    out = json.loads(redact_gitleaks(payload))
    assert out and all(x["Secret"] == "<redacted>" and x["Match"] == "<redacted>" for x in out)
    assert all(x["File"] and x["RuleID"] for x in out)  # 위치·룰은 보존
    for x in json.loads(payload):
        assert x["Secret"] not in redact_gitleaks(payload)


def test_tool_versions_uses_runner():
    def fake_run(argv, **kw):
        class R:
            returncode = 0
            stdout = f"{argv[0]} 9.9.9\n"
            stderr = ""
        return R()
    v = tool_versions(run=fake_run)
    assert v["trivy"] == "trivy 9.9.9" and "java" in v and "semgrep" in v


def test_write_evidence_layout_and_redaction(tmp_path):
    trivy = (GOLDEN / "trivy-vuln-maven-app.json").read_text()
    gitleaks = (GOLDEN / "gitleaks-secret-app.json").read_text()
    from secscan.normalize import to_findings
    raws = [RawResult("trivy", OK, payload=trivy), RawResult("gitleaks", OK, payload=gitleaks),
            RawResult("semgrep", FAILED, error="exit 2")]
    findings = to_findings(raws)
    result = ScanResult(findings, raws, partial_failures=[raws[2]])
    sink = TraceSink(); sink.record("final", findings)
    written = write_evidence(tmp_path, result=result, trace=sink,
                             meta={"snapshot": "abc", "profile": "standard"})
    names = {p.relative_to(tmp_path).as_posix() for p in written}
    assert {"raw/trivy.json", "raw/gitleaks.json", "findings.json", "findings.sarif",
            "report.md", "trace.json", "meta.json"} <= names
    assert "raw/semgrep.json" not in names  # 실패 도구는 payload 없음 → 미저장
    secret_values = {x["Secret"] for x in json.loads(gitleaks)}
    for p in written:
        text = p.read_text()
        assert not any(s in text for s in secret_values), p
    meta = json.loads((tmp_path / "meta.json").read_text())
    assert meta["snapshot"] == "abc"
    assert meta["scanner_status"] == [{"tool": "trivy", "status": "ok"},
                                      {"tool": "gitleaks", "status": "ok"},
                                      {"tool": "semgrep", "status": "failed", "error": "exit 2"}]


def test_run_snapshot_parser_defaults():
    from tools.verify.run_snapshot import build_parser
    a = build_parser().parse_args(["--repo", "/r", "--sha", "abc", "--scratch", "/s", "--out", "/o"])
    assert a.profile == "standard" and a.no_reachability is False
