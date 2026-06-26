"""Gitleaks JSON → typed Finding (secret, 위치형).

보안: raw 시크릿 값(`Secret`/`Match`)은 저장하지 않는다. 안정 식별자인 Fingerprint
만 snippet_ref 로 싣는다(보고서/SARIF 재유출 방지).
"""

from __future__ import annotations

import json

from ..models import HIGH, Consensus, Finding, Location


def parse_gitleaks(payload: str, tool_version: str | None = None) -> list[Finding]:
    if not payload or not payload.strip():
        return []
    data = json.loads(payload)
    findings: list[Finding] = []
    for x in data:
        findings.append(
            Finding(
                category="secret",
                severity=HIGH,  # 노출된 자격증명은 기본 high (검증 시 상향 가능 — M2 trufflehog)
                title=x.get("Description") or x.get("RuleID", ""),
                tool="gitleaks",
                rule_id=x.get("RuleID", ""),
                location=Location(
                    file=x.get("File", ""),
                    start_line=x.get("StartLine"),
                    end_line=x.get("EndLine"),
                    snippet_ref=x.get("Fingerprint"),  # raw 값 대신 fingerprint
                ),
                consensus=Consensus(tools=("gitleaks",), score=1),
            )
        )
    return findings
