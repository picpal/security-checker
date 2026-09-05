"""tools/verify — 스냅샷 격리·증거 작성기(부수효과는 runner 주입으로 결정적 검증)."""

import json
import os
from pathlib import Path

import pytest

from secscan.adapters.base import FAILED, OK, RawResult
from secscan.scan import ScanResult, TraceSink
from tools.verify.evidence import redact_gitleaks, tool_versions, write_evidence
from tools.verify.snapshot import apply_isolated_env, isolated_env, prepare_snapshot

GOLDEN = Path(__file__).parent / "golden"


def test_prepare_snapshot_clones_local_and_checks_out(tmp_path):
    calls = []

    def fake_run(argv, **kw):
        calls.append(argv)
        if argv[:2] == ["git", "clone"]:
            Path(argv[-1]).mkdir(parents=True)
        class R:
            returncode = 0
            stdout = "abc123\n"  # 재사용 검증(rev-parse HEAD)에서 사용
            stderr = ""
        return R()

    dest = prepare_snapshot(Path("/repo"), "abc123", tmp_path, run=fake_run)
    assert dest == tmp_path / "abc123" / "repo"
    assert calls[0] == ["git", "clone", "--local", "--no-checkout", "/repo", str(dest)]
    assert calls[1] == ["git", "-C", str(dest), "checkout", "--detach", "abc123"]
    # 두 번째 호출은 재사용하되 HEAD 를 검증한다(clone/checkout 없음, rev-parse 만)
    calls.clear()
    prepare_snapshot(Path("/repo"), "abc123", tmp_path, run=fake_run)
    assert calls == [["git", "-C", str(dest), "rev-parse", "HEAD"]]


def test_prepare_snapshot_checkout_failure_removes_partial_clone(tmp_path):
    def fake_run(argv, **kw):
        if argv[:2] == ["git", "clone"]:
            Path(argv[-1]).mkdir(parents=True)
            class R:
                returncode = 0
                stderr = ""
            return R()
        # checkout 호출은 실패(예: 잘못된 sha)
        class R:
            returncode = 1
            stderr = "unknown revision"
        return R()

    dest = tmp_path / "abc123" / "repo"
    with pytest.raises(RuntimeError):
        prepare_snapshot(Path("/repo"), "abc123", tmp_path, run=fake_run)
    assert not dest.exists()  # 부분 클론이 남아 재사용되면 안 됨


def test_prepare_snapshot_reuse_with_matching_head_returns_without_clone(tmp_path):
    dest = tmp_path / "abc123" / "repo"
    dest.mkdir(parents=True)
    calls = []

    def fake_run(argv, **kw):
        calls.append(argv)
        class R:
            returncode = 0
            stdout = "abc123\n"
            stderr = ""
        return R()

    got = prepare_snapshot(Path("/repo"), "abc123", tmp_path, run=fake_run)
    assert got == dest
    assert calls == [["git", "-C", str(dest), "rev-parse", "HEAD"]]


def test_prepare_snapshot_reuse_with_mismatching_head_raises(tmp_path):
    dest = tmp_path / "abc123" / "repo"
    dest.mkdir(parents=True)

    def fake_run(argv, **kw):
        class R:
            returncode = 0
            stdout = "deadbeef\n"  # 요청한 sha 와 다른 커밋에 체크아웃돼 있음
            stderr = ""
        return R()

    with pytest.raises(RuntimeError):
        prepare_snapshot(Path("/repo"), "abc123", tmp_path, run=fake_run)


def test_apply_isolated_env_clears_credentials_from_process_environ(tmp_path, monkeypatch):
    # os.environ.clear() 를 실제로 수행하므로, monkeypatch 가 추적하지 못하는 다른 환경변수까지
    # 지워질 위험이 있다 — 테스트가 끝나면 전체를 원상복구해 다른 테스트로 상태가 새지 않게 한다.
    saved = dict(os.environ)
    try:
        monkeypatch.setenv("GITHUB_TOKEN", "leaked")
        monkeypatch.setenv("PATH", "/bin:/usr/bin")
        env = apply_isolated_env(tmp_path, "abc123")
        assert "GITHUB_TOKEN" not in os.environ
        assert "GITHUB_TOKEN" not in env
        assert os.environ["PATH"] == "/bin:/usr/bin"
        assert os.environ["GRADLE_USER_HOME"] == str(tmp_path / "abc123" / "gradle-home")
        assert env["GRADLE_USER_HOME"] == str(tmp_path / "abc123" / "gradle-home")
    finally:
        os.environ.clear()
        os.environ.update(saved)


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


# --- V2: 리포트·프로파일 계약·known-FP ---
from secscan.measure import GtEntry, GtManifest, match_ground_truth
from secscan.models import UNKNOWN, UNREACHABLE, Advisory, Component, Finding, Reachability
from tools.verify.known_fp import check_known_fp
from tools.verify.profile_contract import SPEC_PROFILES, compare_profiles, render as render_profiles
from tools.verify.report import published_dates, render_attrition, render_human_verdicts, render_match


def _sca(pkg, ver, cve, reach=UNKNOWN, evidence=None):
    return Finding(category="sca", severity="high", tool="trivy", rule_id=cve,
                   component=Component("maven", pkg, ver), advisory=Advisory(cve, aliases=(cve,)),
                   reachability=Reachability(reach, evidence=evidence))


def test_render_attrition_table_shows_stage_deltas():
    trace = {"raw": [{"tool": "trivy", "status": "ok", "bytes": 10}],
             "stages": [{"stage": "merge", "count": 5, "keys": []},
                        {"stage": "exclude", "count": 3, "keys": []},
                        {"stage": "final", "count": 3, "keys": []}]}
    md = render_attrition(trace)
    assert "| merge | 5 |" in md and "| exclude | 3 | -2 |" in md


def test_render_match_lists_recall_and_extra_classes():
    m = GtManifest("sca", "s", "2026-08-31", (GtEntry("CVE-1", "g:a", "1.0"), GtEntry("CVE-2", "g:b", "1.0")), [])
    r = match_ground_truth([_sca("g:a", "1.0", "CVE-1"), _sca("g:z", "1.0", "CVE-9")], m)
    md = render_match(r, {r.extras[0].dedup_key: "inventory-diff"})
    assert "CVE 단위 recall(GT-B 합산): 1/2" in md and "origin 별 CVE recall:" in md and "CVE-2" in md and "inventory-diff" in md


def test_render_human_verdicts_compares_reason_classes():
    m = GtManifest("sca", "s", "2026-08-31",
                   (GtEntry("CVE-T", "org.apache.tomcat.embed:tomcat-embed-core", "11.0.22",
                            human_verdict="unreachable", reason_class="config-gated", reason="HTTP/2 off"),), [])
    md = render_human_verdicts(m, [_sca("org.apache.tomcat.embed:tomcat-embed-core", "11.0.22", "CVE-T", UNREACHABLE)])
    assert "config-gated" in md and "unreachable" in md and "패키지 prefix" in md


def test_published_dates_from_trivy_json():
    payload = (GOLDEN / "trivy-vuln-maven-app.json").read_text()
    d = published_dates(payload)
    assert d["CVE-2022-42889"].startswith("2022-10")


def test_profile_contract_detects_bom_sca_vs_trivy_osv_drift():
    rows = compare_profiles()
    acc = next(r for r in rows if r["profile"] == "accurate-sca")
    assert acc["spec"] == sorted(SPEC_PROFILES["accurate-sca"])
    assert "osv-scanner" in acc["missing"]
    md = render_profiles(rows, {"trivy": "ok", "gitleaks": "ok"})
    assert "accurate-sca" in md and "osv-scanner" in md


def test_check_known_fp_three_stages():
    bom = json.dumps({"components": [{"purl": "pkg:maven/com.microsoft.sqlserver/mssql-jdbc@13.2.1.jre11",
                                      "group": "com.microsoft.sqlserver", "name": "mssql-jdbc", "version": "13.2.1.jre11"}]})
    trivy_clean = json.dumps({"Results": [{"Target": "bom.json", "Vulnerabilities": []}]})
    r = check_known_fp(bom, trivy_clean, package="com.microsoft.sqlserver:mssql-jdbc",
                       advisory="CVE-2025-59250", expected_version="13.2.1.jre11")
    assert r == {"component_present": True, "version_preserved": True, "not_reported": True,
                 "found_version": "13.2.1.jre11"}
    trivy_fp = json.dumps({"Results": [{"Target": "bom.json", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2025-59250", "PkgName": "com.microsoft.sqlserver:mssql-jdbc", "InstalledVersion": "13.2.1"}]}]})
    assert check_known_fp(bom, trivy_fp, package="com.microsoft.sqlserver:mssql-jdbc",
                          advisory="CVE-2025-59250", expected_version="13.2.1.jre11")["not_reported"] is False


def test_collect_facts_ids_and_values():
    from tools.verify.report import collect_facts
    m = GtManifest("gt-b-sca", "a483b3b1", "2026-08-31", entries=(
        GtEntry("CVE-1", "g:a", "1.0", "present", "team", 1, severity_team="HIGH"),
        GtEntry("CVE-2", "g:b", "1.0", "present", "team", 2),), raw_entries=())
    fs = [_sca("g:a", "1.0", "CVE-1"), _sca("g:z", "9.9", "CVE-9")]
    rep = match_ground_truth(fs, m)
    facts = collect_facts(rep, {fs[1].dedup_key: "inventory-diff"}, fs,
                          {"stages": [{"stage": "merge", "count": 2}, {"stage": "final", "count": 2}]},
                          {"scanner_status": [{"tool": "trivy", "status": "ok"}]})
    assert facts["sca.recall_cve"] == "1/2" and facts["sca.missed"] == 1 and facts["sca.missed_high_important"] == 0
    assert facts["sca.extras"] == 1 and facts["sca.extras.inventory-diff"] == 1 and facts["sca.extras.unclassified"] == 0
    assert facts["attrition.final"] == 2 and facts["scanner.trivy"] == "ok" and facts["findings.sca"] == 2
    assert facts["sca.recall_cve.team"] == "1/2" and "sca.recall_cve.dev-found" not in facts
    # reach.reachable/unreachable/unknown 은 값이 0 이어도 항상 출력된다(부재가 아니라 "관측 0건").
    # _sca() 기본값은 UNKNOWN 이므로 fs 두 건 모두 unknown 으로 집계된다.
    assert facts["reach.reachable"] == 0 and facts["reach.unreachable"] == 0 and facts["reach.unknown"] == 2


def test_known_fp_render_and_profile_render_doc_are_full_docs():
    from tools.verify.known_fp import render as render_fp
    from tools.verify.profile_contract import render_doc
    fp = render_fp({"component_present": True, "version_preserved": True, "not_reported": True, "found_version": "13.2.1.jre11"})
    assert fp.startswith("# known-FP CVE-2025-59250") and "| not_reported | True |" in fp
    doc = render_doc({"trivy": "ok"})
    assert doc.startswith("# 프로파일 계약") and "standard" in doc


# --- V2: 입력면 교차 ---
from tools.verify.jar_surface import compare_installed, diff_inventories, inventory_from_bom, inventory_from_trivy


def test_inventories_and_diff():
    bom = json.dumps({"components": [
        {"group": "g", "name": "a", "version": "1.0", "purl": "pkg:maven/g/a@1.0"},
        {"group": "g", "name": "b", "version": "2.0", "purl": "pkg:maven/g/b@2.0"}]})
    # g:a 는 jar 쪽에서 두 버전으로 이중 보고된다(예: mssql-jdbc 13.2.1 / 13.2.1.jre11 재현) —
    # 덮어쓰지 않고 " / "로 병기되어야 한다("|"는 마크다운 표 셀 구분자와 충돌).
    trivy = json.dumps({"Results": [{"Target": "Java", "Packages": [
        {"Name": "g:a", "Version": "1.0"}, {"Name": "g:a", "Version": "1.0.1"},
        {"Name": "g:c", "Version": "3.0"}],
        "Vulnerabilities": [{"PkgName": "g:b", "InstalledVersion": "2.0.jre11", "VulnerabilityID": "CVE-1"}]}]})
    ia, ib = inventory_from_bom(bom), inventory_from_trivy(trivy)
    assert ia == {"g:a": "1.0", "g:b": "2.0"}
    assert ib == {"g:a": "1.0 / 1.0.1", "g:c": "3.0", "g:b": "2.0.jre11"}
    d = diff_inventories(ia, ib)
    assert d["only_a"] == [] and d["only_b"] == ["g:c"]
    assert d["version_differs"] == {"g:a": ("1.0", "1.0 / 1.0.1"), "g:b": ("2.0", "2.0.jre11")}


def test_compare_installed_against_manifest():
    m = GtManifest("sca", "s", "2026-08-31", (GtEntry("CVE-1", "g:a", "1.0"), GtEntry("CVE-2", "g:x", "9")), [])
    rows = compare_installed({"g:a": "1.0"}, m)
    assert rows == [{"package": "g:a", "manifest": "1.0", "inventory": "1.0", "match": True},
                    {"package": "g:x", "manifest": "9", "inventory": None, "match": False}]


def test_build_and_scan_jar_runs_gradle_then_trivy_rootfs(tmp_path):
    from tools.verify.jar_surface import build_and_scan_jar

    calls = []

    def fake_run(argv, **kw):
        calls.append((argv, kw))
        class R:
            returncode = 0
            stdout = '{"Results": []}'
            stderr = ""
        return R()

    repo_dir = tmp_path / "repo"
    out_json = tmp_path / "input-surface.trivy-fs.json"
    ok = build_and_scan_jar(repo_dir, out_json, run=fake_run)
    assert ok is True
    assert calls[0][0] == ["./gradlew", "bootJar", "-x", "test", "--no-daemon", "-q"]
    assert calls[0][1]["cwd"] == str(repo_dir)
    trivy_argv = calls[1][0]
    assert trivy_argv[:7] == ["trivy", "rootfs", "--scanners", "vuln", "--list-all-pkgs", "--format", "json"]
    assert trivy_argv[-1] == str(repo_dir / "build" / "libs")
    assert out_json.read_text(encoding="utf-8") == '{"Results": []}'


def test_build_and_scan_jar_gradle_failure_skips_trivy(tmp_path):
    from tools.verify.jar_surface import build_and_scan_jar

    calls = []

    def fake_run(argv, **kw):
        calls.append(argv)
        class R:
            returncode = 1
            stdout = ""
            stderr = "boom"
        return R()

    repo_dir = tmp_path / "repo"
    out_json = tmp_path / "input-surface.trivy-fs.json"
    ok = build_and_scan_jar(repo_dir, out_json, run=fake_run)
    assert ok is False
    assert len(calls) == 1
    assert out_json.with_suffix(".build-error.txt").read_text(encoding="utf-8") == "boom"


def test_build_and_scan_jar_trivy_nonzero_still_records_partial_output(tmp_path):
    from tools.verify.jar_surface import build_and_scan_jar

    calls = []

    def fake_run(argv, **kw):
        calls.append(argv)
        if argv[0] == "./gradlew":
            class R:
                returncode = 0
                stdout = ""
                stderr = ""
        else:
            class R:
                returncode = 1
                stdout = '{"Results": []}'
                stderr = "trivy failed"
        return R()

    repo_dir = tmp_path / "repo"
    out_json = tmp_path / "input-surface.trivy-fs.json"
    ok = build_and_scan_jar(repo_dir, out_json, run=fake_run)
    assert ok is False
    assert out_json.read_text(encoding="utf-8") == '{"Results": []}'


def test_render_doc_empty_jar_payload_shapes_are_equivalent():
    from tools.verify.jar_surface import render_doc

    bom = json.dumps({"components": [{"group": "g", "name": "a", "version": "1.0"}]})
    m = GtManifest("sca", "s", "2026-08-31", (GtEntry("CVE-1", "g:a", "1.0"),), [])
    a = render_doc(False, bom, '{"SchemaVersion": 2}', m)
    b = render_doc(False, bom, "{}", m)
    assert a == b
    assert a.startswith("# 입력면 교차 — jar 빌드/스캔 실패(부분)")


def test_vuln_installed_versions_sorted_tuples():
    from tools.verify.jar_surface import vuln_installed_versions

    trivy = json.dumps({"Results": [{"Vulnerabilities": [
        {"VulnerabilityID": "CVE-2025-59250", "PkgName": "com.microsoft.sqlserver:mssql-jdbc", "InstalledVersion": "13.2.1"},
        {"VulnerabilityID": "CVE-1", "PkgName": "g:z", "InstalledVersion": "9.9"}]}]})
    assert vuln_installed_versions(trivy) == [
        ("CVE-1", "g:z", "9.9"),
        ("CVE-2025-59250", "com.microsoft.sqlserver:mssql-jdbc", "13.2.1"),
    ]


def test_render_doc_vuln_table_lists_gt_packages_only():
    from tools.verify.jar_surface import render_doc

    bom = json.dumps({"components": [
        {"group": "com.microsoft.sqlserver", "name": "mssql-jdbc", "version": "13.2.1.jre11"}]})
    trivy = json.dumps({"Results": [{"Vulnerabilities": [
        {"VulnerabilityID": "CVE-2025-59250", "PkgName": "com.microsoft.sqlserver:mssql-jdbc", "InstalledVersion": "13.2.1"},
        {"VulnerabilityID": "CVE-9", "PkgName": "not:in-gt", "InstalledVersion": "9.9"}]}]})
    m = GtManifest("sca", "s", "2026-08-31",
                   (GtEntry("CVE-2025-59250", "com.microsoft.sqlserver:mssql-jdbc", "13.2.1.jre11"),), [])
    doc = render_doc(True, bom, trivy, m)
    assert "## jar 표면의 취약점 부착 버전(정답지 패키지만)" in doc
    assert "| CVE-2025-59250 | com.microsoft.sqlserver:mssql-jdbc | 13.2.1 |" in doc
    # not:in-gt 는 정답지에 없는 패키지이므로 취약점 부착 버전 표에서는 빠져야 한다
    # (인벤토리 차이 섹션에는 별개로 등장할 수 있음 — 여기서는 표의 행만 확인).
    assert "| CVE-9 | not:in-gt | 9.9 |" not in doc
