"""Semgrep JSON → typed Finding (sast, 위치형).

CE 한계: taint 는 intraprocedural(함수 내)만. cross-function/file 흐름은 놓친다
(spec §10.2). 이 한계는 보고서에서 안내한다.
"""

from __future__ import annotations

import json

from ..models import HIGH, LOW, MEDIUM, Consensus, Finding, Location

_SEV = {"ERROR": HIGH, "WARNING": MEDIUM, "INFO": LOW}


def _cwe_codes(raw) -> tuple[str, ...]:
    # ["CWE-89: Improper ..."] -> ("CWE-89",)
    out = []
    for item in raw or ():
        code = item.split(":", 1)[0].strip()
        if code.startswith("CWE-"):
            out.append(code)
    return tuple(out)


def parse_semgrep(payload: str, tool_version: str | None = None) -> list[Finding]:
    if not payload or not payload.strip():
        return []
    data = json.loads(payload)
    findings: list[Finding] = []
    for r in data.get("results", []) or []:
        extra = r.get("extra", {}) or {}
        md = extra.get("metadata", {}) or {}
        check_id = r.get("check_id", "")
        findings.append(
            Finding(
                category="sast",
                severity=_SEV.get((extra.get("severity") or "").upper(), "unknown"),
                title=(extra.get("message") or check_id)[:200],
                tool="semgrep",
                rule_id=check_id,
                cwe=_cwe_codes(md.get("cwe")),
                owasp=tuple(md.get("owasp") or ()),
                location=Location(
                    file=r.get("path", ""),
                    start_line=(r.get("start") or {}).get("line"),
                    end_line=(r.get("end") or {}).get("line"),
                    snippet_ref=extra.get("fingerprint"),
                ),
                consensus=Consensus(tools=("semgrep",), score=1),
            )
        )
    return findings
