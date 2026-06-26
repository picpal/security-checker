"""osv-scanner v2 JSON → typed Finding (SCA).

osv 의 primary id 는 GHSA 인 경우가 많다. dedup 을 위해 aliases 의 CVE 를
canonical id 로 승격한다(trivy 와 같은 키로 합쳐지도록).
"""

from __future__ import annotations

import json

from ..models import Advisory, Component, Consensus, Finding, normalize_severity


def _canonical_id(vuln_id: str, aliases: list[str]) -> str:
    for a in aliases:
        if a.startswith("CVE-"):
            return a
    return vuln_id


def _fixed_versions(vuln: dict) -> tuple[str, ...]:
    fixed = []
    for aff in vuln.get("affected", []) or []:
        for rng in aff.get("ranges", []) or []:
            for ev in rng.get("events", []) or []:
                if "fixed" in ev:
                    fixed.append(ev["fixed"])
    return tuple(dict.fromkeys(fixed))  # 순서 유지 dedup


def _severity(vuln: dict) -> str:
    # GHSA 리뷰 severity 가 가장 깔끔
    db = vuln.get("database_specific") or {}
    return normalize_severity(db.get("severity"))


def parse_osv(payload: str, tool_version: str | None = None) -> list[Finding]:
    data = json.loads(payload)
    findings: list[Finding] = []
    for res in data.get("results", []) or []:
        for p in res.get("packages", []) or []:
            pkg = p.get("package", {}) or {}
            eco = (pkg.get("ecosystem") or "").lower()
            for v in p.get("vulnerabilities", []) or []:
                aliases = list(v.get("aliases") or [])
                vid = v.get("id", "")
                canonical = _canonical_id(vid, aliases)
                all_aliases = tuple(dict.fromkeys([vid, *aliases]))
                db = v.get("database_specific") or {}
                findings.append(
                    Finding(
                        category="sca",
                        severity=_severity(v),
                        title=v.get("summary") or canonical,
                        tool="osv-scanner",
                        rule_id=canonical,
                        cwe=tuple(db.get("cwe_ids") or ()),
                        component=Component(eco, pkg.get("name", ""), pkg.get("version", "")),
                        advisory=Advisory(
                            id=canonical,
                            aliases=all_aliases,
                            fixed_versions=_fixed_versions(v),
                        ),
                        consensus=Consensus(tools=("osv-scanner",), score=1),
                    )
                )
    return findings
