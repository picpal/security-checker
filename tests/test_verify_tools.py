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


def test_render_attrition_normalize_rows_are_independent_not_cumulative():
    """I1 — normalize:<tool> 행은 도구별 독립 건수다(파이프라인 누적이 아니다). 증감 칸은 비우고,
    normalize(합계) 합성 행을 넣어 그 이후(merge~)부터만 증감을 계산한다. merge 는 76→73 로
    실제로 3건이 줄었으므로 -3 이어야 한다(예전엔 도구 행 사이 알파벳순 차를 찍어 +25 로 뒤집혔다)."""
    trace = {"raw": [], "stages": [
        {"stage": "normalize:gitleaks", "count": 13, "keys": []},
        {"stage": "normalize:semgrep", "count": 15, "keys": []},
        {"stage": "normalize:trivy", "count": 48, "keys": []},
        {"stage": "merge", "count": 73, "keys": []},
        {"stage": "exclude", "count": 73, "keys": []},
        {"stage": "final", "count": 73, "keys": []},
    ]}
    md = render_attrition(trace)
    assert "| normalize:gitleaks | 13 |  |" in md
    assert "| normalize:semgrep | 15 |  |" in md
    assert "| normalize:trivy | 48 |  |" in md
    assert "| normalize(합계) | 76 |  |" in md
    assert "| merge | 73 | -3 |" in md  # 76 → 73
    assert "| exclude | 73 | +0 |" in md
    assert "| final | 73 | +0 |" in md


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
                          {"scanner_status": [{"tool": "trivy", "status": "ok"}]}, [])
    assert facts["sca.recall_cve"] == "1/2" and facts["sca.missed"] == 1 and facts["sca.missed_high_important"] == 0
    assert facts["sca.extras"] == 1 and facts["sca.extras.inventory-diff"] == 1 and facts["sca.extras.unclassified"] == 0
    assert facts["attrition.final"] == 2 and facts["scanner.trivy"] == "ok" and facts["findings.sca"] == 2
    assert facts["sca.recall_cve.team"] == "1/2" and "sca.recall_cve.dev-found" not in facts
    # human.verdict_rows/verdict_advisories — 픽스처 엔트리는 human_verdict 가 없으므로 0.
    assert facts["human.verdict_rows"] == 0 and facts["human.verdict_advisories"] == 0
    # reach.reachable/unreachable/unknown 은 값이 0 이어도 항상 출력된다(부재가 아니라 "관측 0건").
    # _sca() 기본값은 UNKNOWN 이므로 fs 두 건 모두 unknown 으로 집계된다.
    assert facts["reach.reachable"] == 0 and facts["reach.unreachable"] == 0 and facts["reach.unknown"] == 2
    # CVE-2/g:b 는 어느 trace 단계에도 없고 raw_vulns([])에도 없음 → scanner(리뷰 I2).
    assert facts["sca.missed_by_stage.scanner"] == 1 and facts["sca.missed_by_stage.normalize"] == 0


def test_missed_stage_attribution_scanner_normalize_and_pipeline_drop():
    """I2 — 미탐 항목이 어느 단계에서 빠졌는지 기계적으로 귀속한다.
    trace.stages[*].keys 에서 dedup_key(sca|ecosystem|package|version|advisory) 를 패키지·advisory 로
    대조해 마지막으로 관측된 단계를 찾고, 그 다음 단계를 "빠진 단계"로 본다."""
    from tools.verify.report import missed_stage
    trace = {"stages": [
        {"stage": "normalize:trivy", "count": 2, "keys": ["sca|maven|g:a|1.0|CVE-1", "sca|maven|g:b|1.0|CVE-2"]},
        {"stage": "merge", "count": 2, "keys": ["sca|maven|g:a|1.0|CVE-1", "sca|maven|g:b|1.0|CVE-2"]},
        {"stage": "exclude", "count": 1, "keys": ["sca|maven|g:a|1.0|CVE-1"]},  # g:b/CVE-2 는 exclude 에서 빠짐
        {"stage": "final", "count": 1, "keys": ["sca|maven|g:a|1.0|CVE-1"]},
    ]}
    raw_vulns = [{"PkgName": "g:a", "VulnerabilityID": "CVE-1"}, {"PkgName": "g:c", "VulnerabilityID": "CVE-3"}]

    # 1) normalize:trivy·merge 엔 있고 exclude 부턴 없음 → "빠진" 단계는 그 다음인 exclude.
    assert missed_stage(GtEntry("CVE-2", "g:b", "1.0"), trace, raw_vulns) == "exclude"
    # 2) raw trivy 출력에도 아예 없음 → scanner(애초에 미생산).
    assert missed_stage(GtEntry("CVE-9", "g:z", "9.9"), trace, raw_vulns) == "scanner"
    # 3) raw 엔 있지만 trace 어느 단계에도 없음 → normalize(정규화가 버림).
    assert missed_stage(GtEntry("CVE-3", "g:c", "1.0"), trace, raw_vulns) == "normalize"
    # 4) final 까지 살아남았는데 미탐 처리된 극단 케이스 → matcher(대조기 자체를 봐야 함).
    assert missed_stage(GtEntry("CVE-1", "g:a", "1.0"), trace, raw_vulns) == "matcher"


def test_render_match_includes_stage_column_for_missed_entries():
    from tools.verify.report import missed_stages
    m = GtManifest("sca", "s", "2026-08-31", (GtEntry("CVE-1", "g:a", "1.0"), GtEntry("CVE-2", "g:b", "1.0")), [])
    r = match_ground_truth([_sca("g:a", "1.0", "CVE-1")], m)  # CVE-2/g:b 는 미탐
    trace = {"stages": [{"stage": "merge", "count": 1, "keys": []}]}
    stages = missed_stages(r, trace, [])
    md = render_match(r, {}, stages)
    assert "단계" in md and "| CVE-2 | g:b | 1.0 | - | team | scanner |" in md


def test_known_fp_render_and_profile_render_doc_are_full_docs():
    from tools.verify.known_fp import render as render_fp
    from tools.verify.profile_contract import render_doc
    fp = render_fp({"component_present": True, "version_preserved": True, "not_reported": True, "found_version": "13.2.1.jre11"})
    assert fp.startswith("# known-FP CVE-2025-59250") and "| not_reported | True |" in fp
    doc = render_doc({"trivy": "ok"})
    assert doc.startswith("# 프로파일 계약") and "standard" in doc


def test_facts_text_is_canonical_serialization():
    """I3/I4/I6 의 공통 헬퍼(M2) — 네 곳의 직렬화가 전부 이 함수 하나로 통일된다."""
    from tools.verify._facts import facts_text
    assert facts_text({"b": 1, "a": 2}) == '{\n  "a": 2,\n  "b": 1\n}\n'
    assert facts_text({"k": "한글"}) == '{\n  "k": "한글"\n}\n'  # ensure_ascii=False


def test_profile_contract_collect_facts_from_compare_profiles_rows():
    """I3 — profile.rows/profile.drift 는 렌더된 마크다운을 되파싱하지 않고 compare_profiles() 에서 직접 계산한다."""
    from tools.verify.profile_contract import collect_facts
    facts = collect_facts({"trivy": "ok", "gitleaks": "ok"})
    assert facts["profile.rows"] == 4
    assert facts["profile.drift"] == 3  # quick 은 spec·구현 일치, 나머지 3개는 osv-scanner 누락


def test_known_fp_collect_facts_ids_and_string_values():
    """I4 — 축 3 값에도 fact id 를 부여해 손전사를 막는다. 값은 비수치라 문자열로 인용된다."""
    from tools.verify.known_fp import collect_facts
    result = {"component_present": True, "version_preserved": True, "not_reported": True, "found_version": "13.2.1.jre11"}
    facts = collect_facts(result)
    assert facts == {
        "knownfp.component_present": "True",
        "knownfp.version_preserved": "True",
        "knownfp.not_reported": "True",
        "knownfp.found_version": "13.2.1.jre11",
    }


def test_parse_markers_resolves_non_numeric_tokens():
    """비수치 마커(True/버전 문자열) — parse_markers 는 토큰 전체를 값으로 쓴다(단, 새 facts:knownfp.* 용).
    마커 직전 토큰이 값 그 자체여야 한다("키=값" 형태로 값에 접두어가 붙으면 안 됨) — 문서는
    "component_present: True <!-- fact:... -->" 처럼 값과 마커 사이만 공백으로 둔다."""
    from tools.verify.reconcile import parse_markers
    md = ("| component_present: True <!-- fact:knownfp.component_present --> |\n"
          "| found_version: 13.2.1.jre11 <!-- fact:knownfp.found_version --> |\n")
    assert parse_markers(md) == [
        ("knownfp.component_present", "True"),
        ("knownfp.found_version", "13.2.1.jre11"),
    ]


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


def test_collect_facts_surface_ids_and_values():
    """Task 12 Step 0(사후 개정) — 축 5 입력면 정본 수치. BOM 2 컴포넌트, jar 는 1 패키지 2버전 + GT 패키지 취약점 1행."""
    from tools.verify.jar_surface import collect_facts

    bom = json.dumps({"components": [
        {"group": "g", "name": "a", "version": "1.0", "purl": "pkg:maven/g/a@1.0"},
        {"group": "g", "name": "b", "version": "2.0", "purl": "pkg:maven/g/b@2.0"}]})
    trivy = json.dumps({"Results": [{"Target": "Java", "Packages": [
        {"Name": "g:a", "Version": "1.0"}, {"Name": "g:a", "Version": "1.0.1"}],
        "Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "g:a", "InstalledVersion": "1.0"}]}]})
    m = GtManifest("sca", "s", "2026-08-31",
                   (GtEntry("CVE-1", "g:a", "1.0"), GtEntry("CVE-2", "g:x", "9")), [])
    facts = collect_facts(True, bom, trivy, m)
    assert facts == {
        "surface.jar_ok": "True",
        "surface.bom_only": 1,       # g:b — BOM 에만
        "surface.jar_only": 0,
        "surface.version_differs": 1,  # g:a: BOM "1.0" vs jar "1.0 / 1.0.1"
        "surface.gt_match_bom": "1/2",  # g:a 일치, g:x 없음
        "surface.gt_match_jar": "0/2",  # g:a 는 " / " 병기로 불일치, g:x 없음
        "surface.vuln_rows_gt": 1,      # CVE-1/g:a 1행 (g:x 는 취약점 없음)
        "surface.jar_packages": 1,
        "surface.bom_packages": 2,
    }


# --- V3: GT-A differential ---
from secscan.models import Location, sast_tier
from tools.verify.differential import evaluate_pair, find_expected


def _sast(rule, file, conf="high", sev="high"):
    return Finding(category="sast", severity=sev, tool="semgrep", rule_id=rule, confidence=conf,
                   location=Location(file, 5))


def test_evaluate_pair_in_category_present_then_absent():
    entry = {"cwe": "CWE-760", "file_suffix": "LoadtestSeederConfig.java", "expected_rule_suffix": "zero-salt",
             "expected_tier": "review", "class": "in-category"}
    vuln = [_sast("secscan.rules.zero-salt", "src/main/java/x/loadtest/LoadtestSeederConfig.java")]
    r = evaluate_pair(entry, vuln, [])
    assert r["present_in_vulnerable"] and r["absent_in_fixed"] and r["passed"]
    assert r["tier_vulnerable"] == "review" and r["tier_ok"]


def test_evaluate_pair_fails_when_still_present_in_fixed():
    entry = {"cwe": "CWE-89", "file_suffix": "LgCarrierMapper.xml", "expected_rule_suffix": "mybatis-sqli-identifier",
             "expected_tier": "review", "class": "in-category"}
    f = _sast("secscan.rules.mybatis-sqli-identifier", "src/main/resources/mybatis/mapper/lg/LgCarrierMapper.xml", conf="low")
    r = evaluate_pair(entry, [f], [f])
    assert r["present_in_vulnerable"] and not r["absent_in_fixed"] and not r["passed"]


def test_evaluate_pair_measure_then_classify_records_observed_rules():
    entry = {"cwe": "CWE-497", "file_suffix": "TestDbReset.java", "expected_rule_suffix": None,
             "expected_tier": None, "class": "measure-then-classify"}
    vuln = [_sast("java.lang.security.audit.x", "src/main/java/t/TestDbReset.java"),
            _sast("other.rule", "src/main/java/t/Other.java")]
    r = evaluate_pair(entry, vuln, [])
    assert r["passed"] is None and r["observed"] == ["java.lang.security.audit.x"]


# --- V3: 정본 검증기 (spec §4.5) ---
from tools.verify.reconcile import (check_markers, check_provenance, parse_markers, raw_vs_typed,
                                    regenerate, unmarked_numbers)


def test_parse_and_check_markers():
    md = "| recall | 38/46 <!-- fact:sca.recall_cve --> | 미탐 3 <!-- fact:sca.missed --> |"
    assert parse_markers(md) == [("sca.recall_cve", "38/46"), ("sca.missed", "3")]
    rows = check_markers(md, {"sca.recall_cve": "38/46", "sca.missed": 4})
    assert [r["ok"] for r in rows] == [True, False] and rows[1]["fact"] == "4"
    assert check_markers("7 <!-- fact:nope -->", {})[0]["ok"] is False


def test_unmarked_numbers_only_in_section_tables_and_value_columns():
    md = ("## 요약\n| 축 | 기준 | 측정값 | 판정 |\n|---|---|---|---|\n"
          "| 1 a | ≥ 44/46 | 38/46 <!-- fact:x --> | ✓ |\n| 2 b | ≤ 1 | 7 | ✗ |\n| 3 c | - | 2026-09-05 | ✓ |\n"
          "## 기타\n| 축 | 값 |\n|---|---|\n| z | 99 |\n| w | 5 |\n")
    assert unmarked_numbers(md, "요약") == ["7"]          # 행 라벨 1·2·3 과 기준 열 44/46·1 은 대상 아님
    assert unmarked_numbers(md, None) == ["7", "99", "5"]  # "값" 열도 검사 대상


def test_unmarked_numbers_catches_attached_tokens_and_skips_ids():
    md = ("| 축 | 측정값 |\n|---|---|\n"
          "| 2 a | 미탐 9건 · 미분류 0(키 없음) · 기준 44/46 |\n"
          "| 4 b | 3 <!-- fact:m -->건 · a483b3b1 · CVE-2026-40992 · 13.2.1.jre11 · spec §5 · 2026-09-05 |\n"
          "| 표 없는 헤더 | 77 |\n")
    assert unmarked_numbers(md, None) == ["9", "0", "44/46", "77"]
    assert unmarked_numbers("| a | b |\n|---|---|\n| 1 | 2 |\n", None) == []  # 측정값/값 열이 없는 표는 검사 안 함


def test_check_provenance_requires_human():
    t = {"overrides": [{"dedup_key": "k1", "provenance": "human:picpal"}, {"dedup_key": "k2", "provenance": "ai:claude"},
                       {"dedup_key": "k3"}]}
    assert [r["ok"] for r in check_provenance(t)] == [True, False, False]
    assert check_provenance({"overrides": []}) == []


def test_raw_vs_typed_cardinality():
    trivy = json.dumps({"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-1"}, {"VulnerabilityID": "CVE-2"}]}]})
    r = raw_vs_typed(trivy, [_sca("g:a", "1.0", "CVE-1")])
    assert (r["raw_count"], r["typed_count"], r["only_raw"], r["only_typed"]) == (2, 1, ["CVE-2"], [])


def test_unmarked_numbers_ignores_table_inside_code_fence():
    """M5 — 펜스 코드블록 안의 `|` 로 시작하는 줄(pytest 표 예시 등)은 표로 오인하지 않는다."""
    md = ("## 요약\n| 축 | 측정값 |\n|---|---|\n| 1 | 3 <!-- fact:x --> |\n\n"
          "```\n| 축 | 측정값 |\n|---|---|\n| z | 99 |\n```\n")
    assert unmarked_numbers(md, "요약") == []


def test_table_stats_counts_tables_and_missing_value_column():
    """M6 — 값 열이 없어 검사에서 빠진 표의 개수를 노출한다(사각지대를 보이게 한다)."""
    from tools.verify.reconcile import table_stats
    md = ("## 요약\n"
          "| 축 | 측정값 |\n|---|---|\n| 1 | 3 |\n\n"
          "| 축 | 기준 |\n|---|---|\n| 2 | ≥ 1 |\n")
    assert table_stats(md, "요약") == (2, 1)  # 표 2개, 그중 값 열 없는 표 1개("기준" 헤더만)


def test_check_quoted_tables_identical_ok_and_changed_cell_mismatch():
    """I8 — 측정 문서의 "전체 인용" 표를 원본 문서의 동일 헤더 표와 행 단위로 대조한다."""
    from tools.verify.reconcile import check_quoted_tables
    src = "# 미탐\n\n| advisory | 패키지 |\n|---|---|\n| CVE-1 | g:a |\n| CVE-2 | g:b |\n"
    md_ok = "### 미탐 (`src.md` 표 전체 인용)\n\n| advisory | 패키지 |\n|---|---|\n| CVE-1 | g:a |\n| CVE-2 | g:b |\n"
    md_bad = "### 미탐 (`src.md` 표 전체 인용)\n\n| advisory | 패키지 |\n|---|---|\n| CVE-1 | g:a |\n| CVE-9 | g:b |\n"

    def _run(md, tmp_path):
        (tmp_path / "src.md").write_text(src, encoding="utf-8")
        return check_quoted_tables(md, tmp_path)

    import tempfile
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        rows_ok = _run(md_ok, td)
        assert len(rows_ok) == 1 and rows_ok[0]["ok"] is True
        rows_bad = _run(md_bad, td)
        assert len(rows_bad) == 1 and rows_bad[0]["ok"] is False and rows_bad[0]["note"]


def test_check_quoted_tables_ignores_fact_markers_when_comparing():
    """마커(<!-- fact:... -->)는 표 대조에서 제거하고 비교한다 — 마커 유무만으로 불일치를 만들지 않는다."""
    from tools.verify.reconcile import check_quoted_tables
    src = "# gt\n\n| 축 | 값 |\n|---|---|\n| a | 3 |\n"
    md = "### 요약 (`gt.md` 전체 인용)\n\n| 축 | 값 |\n|---|---|\n| a | 3 <!-- fact:x --> |\n"
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        (td / "gt.md").write_text(src, encoding="utf-8")
        rows = check_quoted_tables(md, td)
        assert len(rows) == 1 and rows[0]["ok"] is True


def test_check_quoted_tables_finds_preceding_table_when_none_follows():
    """`위 표는 …전체 인용이며` 처럼 표를 먼저 보여준 뒤 인용을 선언하는 경우도 대응한다."""
    from tools.verify.reconcile import check_quoted_tables
    src = "# gt\n\n| 축 | 값 |\n|---|---|\n| a | 3 |\n"
    md = "| 축 | 값 |\n|---|---|\n| a | 3 |\n\n위 표는 `gt.md` 의 전체 인용이며 정본과 동일하다.\n\n## 다음 절\n"
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        (td / "gt.md").write_text(src, encoding="utf-8")
        rows = check_quoted_tables(md, td)
        assert len(rows) == 1 and rows[0]["ok"] is True


def test_check_quoted_tables_skips_explicit_non_quote_negation():
    """"…전체 인용 아님(요약만)" 처럼 명시적으로 전체 인용이 아니라고 선언한 문장은 대상이 아니다."""
    from tools.verify.reconcile import check_quoted_tables
    md = "전체 결과는 `docs/reconcile-report.md`(전체 인용 아님 — 요약만) 참조.\n"
    rows = check_quoted_tables(md, Path("/nonexistent"))
    assert rows == []


def _fake_results(tmp_path):
    """가짜 증거 + 그 증거로 생성한 결과 문서 — 재생성 비교의 양성 케이스."""
    from tools.verify import differential, report
    from tools.verify._facts import facts_text
    from tools.verify.jar_surface import render_doc as render_surface
    from tools.verify.known_fp import check_known_fp, collect_facts as knownfp_facts, render as render_fp
    from tools.verify.profile_contract import collect_facts as profile_facts, render_doc as render_profiles
    from secscan.output.json_io import to_json
    ev = tmp_path / "evidence"; std = ev / "a483b3b1-standard"; (std / "raw").mkdir(parents=True)
    fs = [_sca("org.apache.tomcat.embed:tomcat-embed-core", "11.0.22", "CVE-2026-1"),
          _sca("com.microsoft.sqlserver:mssql-jdbc", "13.2.1.jre11", "CVE-2020-9")]
    (std / "findings.json").write_text(to_json(fs), encoding="utf-8")
    (std / "trace.json").write_text(json.dumps({"raw": [{"tool": "trivy", "status": "ok", "bytes": 1}],
                                                "stages": [{"stage": "merge", "count": 2}, {"stage": "final", "count": 2}]}), encoding="utf-8")
    (std / "meta.json").write_text(json.dumps({"scanner_status": [{"tool": "trivy", "status": "ok"}]}), encoding="utf-8")
    (std / "raw" / "trivy.json").write_text(json.dumps({"Results": [{"Target": "Java", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2026-1", "PkgName": "org.apache.tomcat.embed:tomcat-embed-core", "InstalledVersion": "11.0.22", "PublishedDate": "2026-08-25T00:00:00Z"}]}]}), encoding="utf-8")
    (std / "raw" / "bom.cdx.json").write_text(json.dumps({"components": [
        {"group": "com.microsoft.sqlserver", "name": "mssql-jdbc", "version": "13.2.1.jre11", "purl": "pkg:maven/com.microsoft.sqlserver/mssql-jdbc@13.2.1.jre11?type=jar"}]}), encoding="utf-8")
    deep = ev / "a483b3b1-deep"; deep.mkdir()
    (deep / "meta.json").write_text(json.dumps({"scanner_status": [{"tool": "trivy", "status": "ok"}, {"tool": "spotbugs", "status": "ok"}]}), encoding="utf-8")
    res = tmp_path / "results"; res.mkdir()
    gt_b = "docs/verification/ground-truth/gt-b-sca.json"; gt_a = "docs/verification/ground-truth/gt-a-source.json"
    report.main(["--evidence", str(std), "--gt", gt_b, "--out", str(res / "gt-b-match.md"), "--facts", str(res / "facts.json")])
    differential.main(["--evidence-root", str(ev), "--gt", gt_a, "--out", str(res / "gt-a-differential.md"), "--facts", str(res / "facts-gta.json")])
    r = check_known_fp((std / "raw" / "bom.cdx.json").read_text(), (std / "raw" / "trivy.json").read_text(),
                       package="com.microsoft.sqlserver:mssql-jdbc", advisory="CVE-2025-59250", expected_version="13.2.1.jre11")
    (res / "known-fp.md").write_text(render_fp(r), encoding="utf-8")
    (res / "facts-knownfp.json").write_text(facts_text(knownfp_facts(r)), encoding="utf-8")
    statuses = {"trivy": "ok", "spotbugs": "ok"}
    (res / "profile-contract.md").write_text(render_profiles(statuses), encoding="utf-8")
    (res / "facts-profile.json").write_text(facts_text(profile_facts(statuses)), encoding="utf-8")
    (res / "input-surface.trivy-fs.json").write_text("{}", encoding="utf-8")
    (res / "input-surface.status.json").write_text(json.dumps({"jar_build_scan_ok": False}), encoding="utf-8")
    from secscan.measure import load_gt_manifest
    (res / "input-surface.md").write_text(render_surface(False, (std / "raw" / "bom.cdx.json").read_text(), "{}", load_gt_manifest(gt_b)), encoding="utf-8")
    from tools.verify.jar_surface import collect_facts as surface_facts
    (res / "facts-surface.json").write_text(facts_text(surface_facts(False, (std / "raw" / "bom.cdx.json").read_text(), "{}", load_gt_manifest(gt_b))), encoding="utf-8")
    return res, ev, gt_b, gt_a


def test_regenerate_passes_then_detects_tampering(tmp_path):
    res, ev, gt_b, gt_a = _fake_results(tmp_path)
    rows = regenerate(res, ev, gt_b, gt_a)
    assert rows and all(r["ok"] for r in rows), rows
    p = res / "gt-b-match.md"; p.write_text(p.read_text(encoding="utf-8") + "\n손으로 고친 줄", encoding="utf-8")
    rows = regenerate(res, ev, gt_b, gt_a)
    assert [r["doc"] for r in rows if not r["ok"]] == ["gt-b-match.md"]


def test_reconcile_main_exit_code(tmp_path):
    from tools.verify.reconcile import main
    res, ev, gt_b, gt_a = _fake_results(tmp_path)
    facts = json.loads((res / "facts.json").read_text(encoding="utf-8"))
    (res / "gate-v2.md").write_text(f"# 게이트\n| 축 | 값 |\n|---|---|\n| recall | {facts['sca.recall_cve']} <!-- fact:sca.recall_cve --> |\n", encoding="utf-8")
    assert main(["--results", str(res), "--evidence-root", str(ev), "--gt-b", gt_b, "--gt-a", gt_a]) == 0
    assert (res / "reconcile-report.md").read_text(encoding="utf-8").rstrip().endswith("✓ 통과")
    (res / "gate-v2.md").write_text("# 게이트\n| 축 | 값 |\n|---|---|\n| recall | 46/46 <!-- fact:sca.recall_cve --> | 3 |\n", encoding="utf-8")
    assert main(["--results", str(res), "--evidence-root", str(ev), "--gt-b", gt_b, "--gt-a", gt_a]) == 1


def test_reconcile_main_writes_facts_reconcile_json(tmp_path):
    """컨트롤러 룰링 1: main 은 reconcile-report.md 외에 facts-reconcile.json 도 같은 직렬화로 남긴다."""
    from tools.verify.reconcile import main
    res, ev, gt_b, gt_a = _fake_results(tmp_path)
    facts = json.loads((res / "facts.json").read_text(encoding="utf-8"))
    (res / "gate-v2.md").write_text(f"# 게이트\n| 축 | 값 |\n|---|---|\n| recall | {facts['sca.recall_cve']} <!-- fact:sca.recall_cve --> |\n", encoding="utf-8")
    assert main(["--results", str(res), "--evidence-root", str(ev), "--gt-b", gt_b, "--gt-a", gt_a]) == 0
    fr = json.loads((res / "facts-reconcile.json").read_text(encoding="utf-8"))
    assert set(fr) == {"reconcile.regen_mismatch", "reconcile.marker_mismatch", "reconcile.unmarked",
                       "reconcile.provenance_violations", "reconcile.raw_typed_mismatch",
                       "reconcile.raw_count", "reconcile.typed_count", "reconcile.only_raw", "reconcile.only_typed",
                       "reconcile.quote_mismatch", "reconcile.verdict"}
    assert fr["reconcile.verdict"] == "통과"
    # 판정(spec §4.5)을 좌우하는 5종(재생성·마커·출처불명·provenance·인용표)은 이 픽스처에서 전부 0 — 통과.
    assert all(fr[k] == 0 for k in ("reconcile.regen_mismatch", "reconcile.marker_mismatch",
                                    "reconcile.unmarked", "reconcile.provenance_violations",
                                    "reconcile.quote_mismatch"))
    # raw_typed_mismatch 는 기록용(spec §4.5 "차이는 사실로 기록") — 판정을 좌우하지 않는다.
    # 이 픽스처는 findings.json 에 CVE-2020-9 를 typed 전용으로 넣어(raw trivy.json 에는 없음)
    # 0 이 아닌 값도 통과를 막지 않음을 함께 확인한다.
    assert fr["reconcile.raw_typed_mismatch"] == 1
    assert (fr["reconcile.raw_count"], fr["reconcile.typed_count"]) == (1, 2)
    assert (fr["reconcile.only_raw"], fr["reconcile.only_typed"]) == (0, 1)
    raw = (res / "facts-reconcile.json").read_text(encoding="utf-8")
    assert raw == json.dumps(fr, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def test_reconcile_does_not_trust_stale_self_citation(tmp_path):
    """I7 — reconcile.* 마커는 직전 실행의 facts-reconcile.json 이 아니라 이번 실행 값과 대조해야 한다.
    문서가 "위반 1건 존재"라고 스스로 인용하면서 최종 판정이 통과일 수는 없다(자기모순 금지).
    (재현: 직전 facts-reconcile.json 이 marker_mismatch=1 로 낡아 있고, gate-v2.md 가 같은 값을
    인용하면 예전 코드는 우연히 일치를 "확인됨"으로 착각해 통과를 내줬다.)"""
    from tools.verify.reconcile import main
    res, ev, gt_b, gt_a = _fake_results(tmp_path)
    facts = json.loads((res / "facts.json").read_text(encoding="utf-8"))
    (res / "gate-v2.md").write_text(
        f"# 게이트\n| 축 | 값 |\n|---|---|\n| recall | {facts['sca.recall_cve']} <!-- fact:sca.recall_cve --> |\n"
        "| 재귀 | 1 <!-- fact:reconcile.marker_mismatch --> |\n", encoding="utf-8")
    # 직전 실행의 결과라고 가정하고 낡은 facts-reconcile.json 을 먼저 놓는다 — 우연히 문서의
    # 거짓 주장("1")과 값이 같다.
    (res / "facts-reconcile.json").write_text(json.dumps({
        "reconcile.regen_mismatch": 0, "reconcile.marker_mismatch": 1, "reconcile.unmarked": 0,
        "reconcile.provenance_violations": 0, "reconcile.raw_typed_mismatch": 0, "reconcile.quote_mismatch": 0,
        "reconcile.raw_count": 0, "reconcile.typed_count": 0, "reconcile.only_raw": 0, "reconcile.only_typed": 0,
        "reconcile.verdict": "위반",
    }, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    rc = main(["--results", str(res), "--evidence-root", str(ev), "--gt-b", gt_b, "--gt-a", gt_a])
    report_text = (res / "reconcile-report.md").read_text(encoding="utf-8")
    # 문서가 "위반이 있다"고 스스로 적었는데 판정이 통과인 자기모순은 금지 — exit 1 이어야 한다.
    assert rc == 1
    assert report_text.rstrip().endswith("✓ 통과") is False
    # 이번 실행이 실제로 계산한 값(직전의 낡은 값이 아니라)이 기록돼야 한다: 자기인용 행 자체가
    # 이제 doc="1" vs fact="0" 불일치로 잡히므로 marker_mismatch >= 1.
    fr = json.loads((res / "facts-reconcile.json").read_text(encoding="utf-8"))
    assert fr["reconcile.marker_mismatch"] >= 1


def test_regenerate_suppresses_generator_stdout(tmp_path, capsys):
    """M11 — regenerate 는 report.main/differential.main 의 print 출력을 흘리지 않는다."""
    res, ev, gt_b, gt_a = _fake_results(tmp_path)
    capsys.readouterr()  # _fake_results 내부에서 이미 호출된 report.main/differential.main 출력 비우기
    regenerate(res, ev, gt_b, gt_a)
    captured = capsys.readouterr()
    assert captured.out == ""


def test_write_evidence_meta_carries_scanner_status_fields(tmp_path):
    from secscan.adapters.base import OK, RawResult
    from secscan.models import ScannerStatus
    from secscan.scan import ScanResult
    from tools.verify.evidence import write_evidence
    r = RawResult("trivy", OK, payload="{}", version="0.71.2", duration_s=1.25)
    res = ScanResult(findings=[], raw_results=[r], scanner_status=[ScannerStatus("trivy", OK, "0.71.2", 1.25, "")])
    write_evidence(tmp_path, result=res, trace=None, meta={"snapshot": "x"})
    meta = json.loads((tmp_path / "meta.json").read_text())
    assert meta["scanner_status"] == [{"tool": "trivy", "status": "ok", "tool_version": "0.71.2", "duration_s": 1.25}]
