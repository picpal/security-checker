"""SpotBugs/FindSecBugs SARIF → typed Finding (sast, 바이트코드).

SpotBugs 는 SARIF 2.1.0 을 내보낸다. rule 메타에서 CWE 를 추출한다(가능하면).
"""

from __future__ import annotations

import json
import re

from ..models import HIGH, LOW, MEDIUM, Consensus, Finding, Location

_LEVEL = {"error": HIGH, "warning": MEDIUM, "note": LOW}
_CWE_RE = re.compile(r"CWE-\d+")


def _level_to_sev(level: str | None) -> str:
    return _LEVEL.get((level or "").lower(), "unknown")


def _rule_cwe(rule: dict) -> tuple[str, ...]:
    blob = json.dumps(rule)  # tags/properties/relationships 어디에 있든 긁어낸다
    return tuple(dict.fromkeys(_CWE_RE.findall(blob)))


def parse_spotbugs_sarif(payload: str, tool_version: str | None = None) -> list[Finding]:
    if not payload or not payload.strip():
        return []
    data = json.loads(payload)
    findings: list[Finding] = []
    for run in data.get("runs", []) or []:
        driver = (run.get("tool", {}) or {}).get("driver", {}) or {}
        rules = {r.get("id"): r for r in driver.get("rules", []) or []}
        for res in run.get("results", []) or []:
            rid = res.get("ruleId", "")
            locs = res.get("locations") or []
            phys = (locs[0].get("physicalLocation", {}) if locs else {})
            art = phys.get("artifactLocation", {}) or {}
            region = phys.get("region", {}) or {}
            findings.append(
                Finding(
                    category="sast",
                    severity=_level_to_sev(res.get("level")),
                    title=((res.get("message", {}) or {}).get("text") or rid)[:200],
                    tool="spotbugs",
                    rule_id=rid,
                    cwe=_rule_cwe(rules.get(rid, {})),
                    location=Location(
                        file=art.get("uri", ""),
                        start_line=region.get("startLine"),
                        end_line=region.get("endLine"),
                    ),
                    consensus=Consensus(tools=("spotbugs",), score=1),
                )
            )
    return findings
