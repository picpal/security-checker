"""M1 dep-scan 도달성 provider — 순수 로직(atom usage 슬라이스 파싱 + 컴포넌트 매칭).

골든: 픽스처에 실제 dep-scan(SemanticReachability)을 돌려 얻은 atom usage 슬라이스.
거기엔 commons-text(StringSubstitutor) 호출은 있고 snakeyaml 은 전혀 없다 →
탐지(trivy/osv)된 취약 컴포넌트의 도달성을 슬라이스로 판정한다.
"""

from pathlib import Path

from secscan.models import (
    REACHABLE,
    UNREACHABLE,
    Advisory,
    Component,
    Finding,
)
from secscan.reachability.depscan import (
    decide_reachability,
    package_prefixes,
    parse_invoked_symbols,
)

GOLDEN = Path(__file__).parent / "golden" / "atom-usages-vuln-maven-app.json"


def _sca(pkg, ver, cve):
    return Finding(category="sca", severity="high",
                   component=Component("maven", pkg, ver),
                   advisory=Advisory(id=cve, aliases=(cve,)))


def test_package_prefixes_from_maven_coordinate():
    assert "org.apache.commons.text" in package_prefixes("org.apache.commons:commons-text")
    assert "org.yaml.snakeyaml" in package_prefixes("org.yaml:snakeyaml")
    assert "org.apache.commons.lang3" in package_prefixes("org.apache.commons:commons-lang3")


def test_parse_invoked_symbols_from_golden_slice():
    invoked = parse_invoked_symbols(GOLDEN.read_text())
    assert any(s.startswith("org.apache.commons.text") for s in invoked)
    assert not any("snakeyaml" in s for s in invoked)  # snakeyaml 미사용


def test_decide_marks_used_reachable_unused_unreachable():
    invoked = parse_invoked_symbols(GOLDEN.read_text())
    findings = [
        _sca("org.apache.commons:commons-text", "1.9", "CVE-2022-42889"),
        _sca("org.yaml:snakeyaml", "1.30", "CVE-2022-1471"),
        _sca("org.apache.commons:commons-lang3", "3.11", "CVE-2025-48924"),
    ]
    result = decide_reachability(findings, invoked)

    assert result.status == "ok"
    assert result.verdicts["org.apache.commons:commons-text@1.9"] == REACHABLE
    assert result.verdicts["org.yaml:snakeyaml@1.30"] == UNREACHABLE
    # 앱이 직접 호출 안 하는 전이 의존은 (앱 레벨) 도달 불가로 본다
    assert result.verdicts["org.apache.commons:commons-lang3@3.11"] == UNREACHABLE


def test_decide_provides_evidence_for_reachable():
    invoked = parse_invoked_symbols(GOLDEN.read_text())
    findings = [_sca("org.apache.commons:commons-text", "1.9", "CVE-2022-42889")]
    result = decide_reachability(findings, invoked)
    ev = result.evidence["org.apache.commons:commons-text@1.9"]
    assert "org.apache.commons.text" in ev


def test_end_to_end_engine_with_depscan_decision():
    # 엔진 + 실제 슬라이스 기반 provider 결합 (provider 는 슬라이스를 미리 읽어 결정)
    from secscan.reachability.engine import enrich_reachability

    invoked = parse_invoked_symbols(GOLDEN.read_text())

    def provider(target, timeout, findings):
        return decide_reachability(findings, invoked)

    findings = [
        _sca("org.apache.commons:commons-text", "1.9", "CVE-2022-42889"),
        _sca("org.yaml:snakeyaml", "1.30", "CVE-2022-1471"),
    ]
    out = enrich_reachability(findings, "/proj", provider=provider,
                              env_ok=lambda: True, count_loc=lambda t: 10)
    by = {f.component.package: f.reachability.status for f in out.findings}
    assert by["org.apache.commons:commons-text"] == REACHABLE
    assert by["org.yaml:snakeyaml"] == UNREACHABLE
