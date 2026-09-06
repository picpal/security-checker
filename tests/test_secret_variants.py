"""secret 변이 픽스처(spec §6) — 저엔트로피·allowlist·history-only. 사실을 기록한다(우회하지 않는다)."""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from secscan.disposition import decide
from secscan.models import ACTIONABLE
from secscan.normalize.gitleaks import parse_gitleaks
from secscan.normalize.semgrep import parse_semgrep

GOLDEN = Path(__file__).parent / "golden"
EXPECTED = json.loads(Path("fixtures/secret-app/expected.json").read_text(encoding="utf-8"))


def test_low_entropy_password_missed_by_gitleaks_but_caught_by_custom_rule():
    g = parse_gitleaks((GOLDEN / "gitleaks-secret-app.json").read_text())
    assert not any(f.location and f.location.file.endswith("Config.java") for f in g)
    assert not any(f.location and f.location.start_line and "db.password" in f.title for f in g)
    s = decide(parse_semgrep((GOLDEN / "semgrep-secret-app-custom.json").read_text()))
    hit = [f for f in s if f.rule_id.endswith("hardcoded-credential") and f.location.file.endswith("Config.java")]
    assert hit and hit[0].disposition == ACTIONABLE and hit[0].tier == EXPECTED["variants"]["low_entropy_password"]["expected_tier"]


def test_prefixed_identifier_is_missed_by_custom_rule_observed():
    """관측된 갭을 고정한다(바람직한 동작이 아니다).

    hardcoded-credential 룰의 metavariable-regex 는 식별자 접두사 매칭이다. 같은 값이라도
    키워드가 변수명 접두사가 아니면(DB_PASSWORD 처럼 DB_ 뒤에 옴) 실도구 실측상 탐지되지
    않는다. 픽스처를 룰에 맞춰 고치지 않고 이 미탐을 사실로 고정한다(룰 개선은 백로그 후보).
    """
    config_java = Path("fixtures/secret-app/src/main/java/com/example/Config.java")
    lines = config_java.read_text(encoding="utf-8").splitlines()
    db_password_line = next(i for i, l in enumerate(lines, start=1) if "DB_PASSWORD" in l and "=" in l)
    s = decide(parse_semgrep((GOLDEN / "semgrep-secret-app-custom.json").read_text()))
    assert not any(
        f.rule_id.endswith("hardcoded-credential")
        and f.location.file.endswith("Config.java")
        and f.location.start_line == db_password_line
        for f in s
    )
    assert EXPECTED["variants"]["low_entropy_prefixed_identifier"]["custom_rule"] == "absent"


def test_inline_allowlist_is_respected():
    g = parse_gitleaks((GOLDEN / "gitleaks-secret-app.json").read_text())
    props = Path("fixtures/secret-app/config/application.properties").read_text(encoding="utf-8").splitlines()
    allow_line = next(i for i, l in enumerate(props, start=1) if "gitleaks:allow" in l)
    assert not any(f.location and f.location.start_line == allow_line for f in g)
    assert {f.rule_id for f in g} == {"aws-access-token", "generic-api-key", "github-pat"}


@pytest.mark.skipif(shutil.which("gitleaks") is None or shutil.which("git") is None, reason="gitleaks/git 필요(실도구)")
def test_history_only_secret_is_missed_by_dir_mode_and_found_by_git_mode(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@x", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@x"}
    run = lambda *a: subprocess.run(a, cwd=repo, env=env, check=True, capture_output=True, text=True)
    run("git", "init", "-q")
    (repo / "app.properties").write_text("aws.accessKeyId=AKIAZ7XK4PQR2WMTBN3D\n", encoding="utf-8")
    run("git", "add", "."); run("git", "commit", "-q", "-m", "add secret")
    (repo / "app.properties").write_text("aws.accessKeyId=${AWS_KEY}\n", encoding="utf-8")
    run("git", "add", "."); run("git", "commit", "-q", "-m", "remove secret")
    def leaks(mode):
        rep = tmp_path / f"{mode}.json"
        subprocess.run(["gitleaks", mode, str(repo), "--report-format", "json", "--report-path", str(rep), "--no-banner", "--exit-code", "0"],
                       capture_output=True, text=True, check=True)
        return json.loads(rep.read_text() or "[]")
    assert leaks("dir") == []  # 사실: dir 모드는 working tree 만 본다
    assert any(x["RuleID"] == "aws-access-token" for x in leaks("git"))
