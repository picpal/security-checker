"""typed Finding → SARIF 2.1.0.

SCA 전용 필드(package/version/fixedVersions/reachability/consensus)는 SARIF result
의 properties bag 에 싣는다(spec §6). 도달성은 주석만 — 자동 억제 금지(원칙 4).
"""

from __future__ import annotations

from ..models import CRITICAL, HIGH, LOW, MEDIUM, Finding, sast_tier

_LEVEL = {CRITICAL: "error", HIGH: "error", MEDIUM: "warning", LOW: "note"}
_SECURITY_SEVERITY = {CRITICAL: "9.0", HIGH: "7.0", MEDIUM: "5.0", LOW: "3.0"}

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def _level(severity: str) -> str:
    return _LEVEL.get(severity, "note")


def _rule(f: Finding) -> dict:
    rule = {
        "id": f.rule_id,
        "name": f.title or f.rule_id,
        "shortDescription": {"text": f.title or f.rule_id},
        "properties": {"tags": [f.category, *(list(f.cwe))]},
    }
    if f.severity in _SECURITY_SEVERITY:
        rule["properties"]["security-severity"] = _SECURITY_SEVERITY[f.severity]
    return rule


def _result(f: Finding) -> dict:
    props: dict = {
        "category": f.category,
        "severity": f.severity,
        "tools": list(f.consensus.tools) if f.consensus else ([f.tool] if f.tool else []),
    }
    if f.cwe:
        props["cwe"] = list(f.cwe)
    if f.component:
        props["package"] = f.component.package
        props["version"] = f.component.version
        props["ecosystem"] = f.component.ecosystem
    if f.advisory and f.advisory.fixed_versions:
        props["fixedVersions"] = list(f.advisory.fixed_versions)
    # 도달성: 주석만(억제 아님)
    props["reachability"] = f.reachability.status
    if f.reachability.evidence:
        props["reachabilityEvidence"] = f.reachability.evidence
    if f.reachability.source:
        props["reachabilitySource"] = f.reachability.source
    if f.consensus:
        props["consensus"] = {"tools": list(f.consensus.tools), "score": f.consensus.score}
    # 컴플라이언스(CWE→KISA/PCI)는 properties bag 에 — 출력 전용, 직렬화 가능 형태로.
    if f.compliance and (f.compliance.kisa or f.compliance.pci):
        props["compliance"] = {
            "kisa": [{"code": w.code, "category": w.category, "name": w.name}
                     for w in f.compliance.kisa],
            "pci": list(f.compliance.pci),
        }
    # SAST 신뢰도 신호 — 출력 전용 properties.
    if f.confidence and f.confidence != "unknown":
        props["confidence"] = f.confidence
    _tier = sast_tier(f)
    if _tier:
        props["sastTier"] = _tier

    msg = f.title or f.rule_id
    if f.component:
        msg = f"{f.rule_id} in {f.component.package}@{f.component.version}"

    # 억제는 사람이 확정한 것만 emit (자동 억제 없음, spec §12).
    suppressions = []
    if f.suppression is not None:
        suppressions.append({
            "kind": "external",
            "justification": f.suppression.reason,
            "properties": {
                "provenance": f.suppression.provenance,
                "evidence": f.suppression.evidence,
                "expiry": f.suppression.expiry,
                "state": f.suppression.state,
            },
        })

    result = {
        "ruleId": f.rule_id,
        "level": _level(f.severity),
        "message": {"text": msg},
        "properties": props,
        "suppressions": suppressions,
    }

    # 위치형(secret/SAST)은 SARIF locations 를 채운다 → GitHub code scanning·IDE 연동.
    if f.location is not None:
        region: dict = {}
        if f.location.start_line is not None:
            region["startLine"] = f.location.start_line
        if f.location.end_line is not None:
            region["endLine"] = f.location.end_line
        phys: dict = {"artifactLocation": {"uri": f.location.file}}
        if region:
            phys["region"] = region
        result["locations"] = [{"physicalLocation": phys}]

    return result


def to_sarif(findings: list[Finding], tool_version: str = "0.0.1") -> dict:
    rules: dict[str, dict] = {}
    results = []
    for f in findings:
        if f.rule_id and f.rule_id not in rules:
            rules[f.rule_id] = _rule(f)
        results.append(_result(f))

    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "secscan",
                        "informationUri": "https://github.com/local/secscan",
                        "version": tool_version,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
