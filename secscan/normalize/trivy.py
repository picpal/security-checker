"""Trivy JSON → typed Finding (SCA)."""

from __future__ import annotations

import json

from ..models import Advisory, Component, Consensus, Cvss, Finding, Occurrence, normalize_severity


def _ecosystem_from_purl(purl: str | None, fallback: str = "maven") -> str:
    # "pkg:maven/group/artifact@ver" -> "maven"
    if purl and purl.startswith("pkg:"):
        return purl[4:].split("/", 1)[0].lower()
    return fallback


def _fixed_versions(raw: str | None) -> tuple[str, ...]:
    if not raw:
        return ()
    return tuple(s.strip() for s in raw.split(",") if s.strip())


_CVSS_PREFIXES = (("V2", "2.0"), ("V3", None), ("V40", "4.0"))  # None = 벡터 접두에서 3.0/3.1 판별


def _cvss(v: dict) -> tuple[Cvss, ...]:
    """trivy `CVSS{source: {V2Score, V2Vector, V3Score, V3Vector, V40Score, V40Vector}}` 전부 보존."""
    out: list[Cvss] = []
    for source, m in sorted((v.get("CVSS") or {}).items()):
        if not isinstance(m, dict):
            continue
        for prefix, fixed in _CVSS_PREFIXES:
            score, vector = m.get(f"{prefix}Score"), m.get(f"{prefix}Vector")
            if score is None and vector is None:
                continue
            ver = fixed
            if ver is None:
                ver = vector.split("/")[0].split(":")[1] if (vector or "").startswith("CVSS:3") else "3.x"
            out.append(Cvss(source, ver, float(score) if score is not None else None, vector))
    return tuple(out)


def parse_trivy(payload: str, tool_version: str | None = None) -> list[Finding]:
    data = json.loads(payload)
    findings: list[Finding] = []
    for res in data.get("Results", []) or []:
        target = res.get("Target", "")
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
                    source=target,
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
                        cvss=_cvss(v),
                        published=v.get("PublishedDate"),
                    ),
                    occurrences=(Occurrence("trivy", target, v.get("PkgName", ""), v.get("InstalledVersion", "")),),
                    consensus=Consensus(tools=("trivy",), score=1),
                    references=((v["PrimaryURL"],) if v.get("PrimaryURL") else ()),
                )
            )
    return findings
