"""projection 계약(spec §7.3) — 문서는 코드 상수에서 생성되고, 포함 필드는 실제 출력에서 확인된다."""
from dataclasses import replace
from pathlib import Path

from secscan.disposition import decide_one
from secscan.models import (Advisory, Component, Compliance, Consensus, Cvss, Finding, KisaWeakness, Location,
                            Occurrence, Reachability, Suppression, UNREACHABLE)
from secscan.output.contracts import CONTRACTS, FIELDS, PROBES, render_contracts
from secscan.output.markdown import to_markdown
from secscan.output.sarif import to_sarif

DOC = Path("docs/output-contracts.md")


def _full():
    f = Finding(
        category="sca", severity="high", title="TitleProbe", tool="trivy", rule_id="CVE-2099-0001",
        cwe=("CWE-94",), owasp=("A03",), confidence="high",
        component=Component("maven", "org.example:lib", "1.2.3"),
        advisory=Advisory("CVE-2099-0001", aliases=("GHSA-xxxx",), fixed_versions=("1.2.4",),
                          cvss=(Cvss("nvd", "3.1", 9.1, "CVSS:3.1/AV:N"),), published="2099-01-01T00:00:00Z"),
        source="pom.xml", reachability=Reachability(UNREACHABLE, evidence="EvidenceProbe", source="dep-scan"),
        consensus=Consensus(("trivy",), 1), references=("https://example.org/ref",), verified=None,
        suppression=Suppression("suppressed", "ReasonProbe", "alice", "SupEvidenceProbe", "2099-12-31", "scope", basis="unreachable"),
        compliance=Compliance(kisa=(KisaWeakness("IV-01", "입력데이터 검증 및 표현", "KisaProbe"),), pci=("PCI-DSS 6.2.4 — injection",)),
        occurrences=(Occurrence("trivy", "pom.xml", "org.example:lib", "1.2.3"),),
    )
    return decide_one(f)


def test_contract_partitions_every_field():
    for name, c in CONTRACTS.items():
        assert c.includes | set(c.partial) | c.loses == set(FIELDS), name
        assert not (c.includes & c.loses) and not (c.includes & set(c.partial)), name


def test_doc_is_generated_from_constants():
    assert DOC.read_text(encoding="utf-8") == render_contracts()


def test_markdown_and_sarif_contain_probe_for_every_included_field():
    # _full() 은 suppression 을 갖고 있어 markdown 의 억제됨 섹션(reason·provenance·expiry 만 출력)에
    # 실린다. cwe/component/advisory/reachability/consensus/compliance 처럼 우선 조치/검토/낮은
    # 우선순위 절에서만 렌더되는 필드를 검증하려면 억제 없는 변형도 함께 렌더해야 한다(controller ruling C).
    suppressed = _full()
    unsuppressed = decide_one(replace(suppressed, suppression=None, disposition=None, tier=None))
    findings = [suppressed, unsuppressed]
    md, sarif = to_markdown(findings), str(to_sarif(findings))
    for fmt, text in (("markdown", md), ("sarif", sarif)):
        for field in CONTRACTS[fmt].includes | set(CONTRACTS[fmt].partial):
            # severity: markdown 은 한글 라벨("위험")만, SARIF 는 properties.severity 에 원문("high")만
            # 싣는다 — 포맷마다 표현이 달라 단일 프로브로 양쪽을 동시에 검증할 수 없다.
            if field == "severity" and fmt == "sarif":
                probe = suppressed.severity
            else:
                probe = PROBES[field](suppressed)
            assert probe.lower() in text.lower(), f"{fmt}: {field} 포함 선언인데 출력에 없음 ({probe})"
