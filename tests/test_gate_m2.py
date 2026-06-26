"""M2 인수(게이트) — 시크릿 탐지 + 검증 network 정책 (결정적·오프라인 골든)."""

from pathlib import Path

from secscan.adapters.base import OK, RawResult
from secscan.normalize import to_findings
from secscan.secret.verify import resolve_secret_policy, verify_secrets_in_findings

GOLDEN = Path(__file__).parent / "golden" / "gitleaks-secret-app.json"


def _boom(target):
    raise AssertionError("off/never 에서 검증 runner 호출 금지(네트워크 전송 없음)")


def _secret_findings():
    raws = [RawResult("gitleaks", OK, payload=GOLDEN.read_text())]
    return to_findings(raws)


def test_gate_secret_detection():
    secrets = [f for f in _secret_findings() if f.category == "secret"]
    assert len(secrets) == 3


def test_gate_default_off_sends_nothing():
    findings = _secret_findings()
    out = verify_secrets_in_findings(findings, ".", policy="off", runner=_boom)
    assert out.ran is False
    assert all(f.verified is None for f in findings if f.category == "secret")


def test_gate_network_off_forces_never_and_blocks():
    assert resolve_secret_policy(verify_secrets=True, network_off=True) == "never"
    out = verify_secrets_in_findings(_secret_findings(), ".", policy="never", runner=_boom)
    assert out.ran is False


def test_gate_verify_optin_marks_live():
    findings = _secret_findings()
    target_file = next(f.location.file for f in findings if f.category == "secret")
    out = verify_secrets_in_findings(
        findings, ".", policy="verify", runner=lambda t: {target_file}
    )
    assert out.ran is True
    assert out.verified_count >= 1
    assert any(f.verified for f in out.findings if f.category == "secret")
