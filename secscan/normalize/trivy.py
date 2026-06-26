"""Trivy JSON → typed Finding (SCA)."""

from __future__ import annotations

import json

from ..models import Advisory, Component, Consensus, Finding, normalize_severity


def _ecosystem_from_purl(purl: str | None, fallback: str = "maven") -> str:
    # "pkg:maven/group/artifact@ver" -> "maven"
    if purl and purl.startswith("pkg:"):
        return purl[4:].split("/", 1)[0].lower()
    return fallback


def _fixed_versions(raw: str | None) -> tuple[str, ...]:
    if not raw:
        return ()
    return tuple(s.strip() for s in raw.split(",") if s.strip())


def parse_trivy(payload: str, tool_version: str | None = None) -> list[Finding]:
    data = json.loads(payload)
    findings: list[Finding] = []
    for res in data.get("Results", []) or []:
        for v in res.get("Vulnerabilities") or []:
            cve = v.get("VulnerabilityID", "")
            purl = (v.get("PkgIdentifier") or {}).get("PURL")
            findings.append(
                Finding(
                    category="sca",
                    severity=normalize_severity(v.get("Severity")),
                    title=v.get("Title") or cve,
                    tool="trivy",
                    rule_id=cve,
                    cwe=tuple(v.get("CweIDs") or ()),
                    component=Component(
                        _ecosystem_from_purl(purl),
                        v.get("PkgName", ""),
                        v.get("InstalledVersion", ""),
                    ),
                    advisory=Advisory(
                        id=cve,
                        aliases=(cve,),
                        fixed_versions=_fixed_versions(v.get("FixedVersion")),
                    ),
                    consensus=Consensus(tools=("trivy",), score=1),
                    references=((v["PrimaryURL"],) if v.get("PrimaryURL") else ()),
                )
            )
    return findings
