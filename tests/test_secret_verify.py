"""M2 시크릿 검증 정책 — TruffleHog opt-in + network 안전장치(spec §8).

핵심 안전 속성: 검증은 발견된 자격증명을 제3자 서비스로 전송한다. 따라서
- 기본 off → 절대 전송 안 함(runner 미호출)
- --verify-secrets → opt-in 전송
- --network-off → never (verify 를 켰어도 강제 차단)
검증 runner 미호출 == 네트워크 미전송. 이걸 테스트로 못박는다.
"""

import pytest

from secscan.models import Finding, Location
from secscan.secret.trufflehog import parse_trufflehog_verified_files
from secscan.secret.verify import (
    resolve_secret_policy,
    verify_secrets_in_findings,
)


def _secret(file="config/app.properties", line=4, rule="aws-access-token"):
    return Finding(category="secret", severity="high", rule_id=rule,
                   location=Location(file, start_line=line))


def _boom_runner(target):
    raise AssertionError("network runner must not be called")


# --- 정책 해석 ---

@pytest.mark.parametrize("verify,netoff,expected", [
    (False, False, "off"),
    (True, False, "verify"),
    (True, True, "never"),   # network-off 가 verify 를 이긴다
    (False, True, "never"),
])
def test_resolve_secret_policy(verify, netoff, expected):
    assert resolve_secret_policy(verify, netoff) == expected


# --- 기본 off: 네트워크 전송 없음 ---

def test_off_policy_does_not_call_runner():
    out = verify_secrets_in_findings([_secret()], "/proj", policy="off", runner=_boom_runner)
    assert out.ran is False
    assert out.findings[0].verified is None  # 미검증 그대로


# --- never: verify 요청과 무관하게 네트워크 차단 ---

def test_never_policy_blocks_network_even_with_secrets():
    out = verify_secrets_in_findings([_secret()], "/proj", policy="never", runner=_boom_runner)
    assert out.ran is False
    assert out.findings[0].verified is None


# --- verify: opt-in 전송, 라이브 확인 시 표시 ---

def test_verify_marks_live_secret_and_bumps_severity():
    findings = [
        _secret(file="config/live.properties", rule="aws-access-token"),
        _secret(file="config/dead.properties", rule="github-pat"),
    ]
    # runner 는 "라이브 시크릿이 있는 파일" 집합을 돌려준다(트러플호그 검증 결과)
    runner = lambda target: {"config/live.properties"}
    out = verify_secrets_in_findings(findings, "/proj", policy="verify", runner=runner)

    assert out.ran is True
    assert out.verified_count == 1
    by_file = {f.location.file: f for f in out.findings}
    assert by_file["config/live.properties"].verified is True
    assert by_file["config/live.properties"].severity == "critical"  # 라이브 → 상향
    assert by_file["config/dead.properties"].verified is False


def test_verify_with_no_secret_findings_skips():
    sca = Finding(category="sca", severity="high")
    out = verify_secrets_in_findings([sca], "/proj", policy="verify", runner=_boom_runner)
    assert out.ran is False  # 검증할 시크릿 없음 → 네트워크 안 씀


# --- TruffleHog JSONL 파서 (--only-verified 결과) ---

def test_parse_trufflehog_returns_only_verified_files():
    jsonl = "\n".join([
        '{"SourceMetadata":{"Data":{"Filesystem":{"file":"/a/b/live.txt"}}},"DetectorName":"AWS","Verified":true}',
        '{"SourceMetadata":{"Data":{"Filesystem":{"file":"/a/b/dead.txt"}}},"DetectorName":"AWS","Verified":false}',
        "",  # 빈 줄 무시
    ])
    files = parse_trufflehog_verified_files(jsonl)
    assert files == {"/a/b/live.txt"}


def test_parse_trufflehog_empty_is_empty_set():
    assert parse_trufflehog_verified_files("") == set()
