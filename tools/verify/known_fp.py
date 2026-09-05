"""known-FP 3단계 검사(spec §5 축 3): 컴포넌트 존재 → 버전 보존 → 비해당 판정."""

from __future__ import annotations

import json


def check_known_fp(bom_json: str, trivy_json: str, *, package: str, advisory: str,
                   expected_version: str) -> dict:
    """known-FP 3단계 검사: BOM에 컴포넌트가 있는지, 버전이 보존되었는지, 비해당 판정인지."""
    group, _, name = package.partition(":")
    found = None
    for c in json.loads(bom_json or "{}").get("components", []) or []:
        purl = c.get("purl", "")
        if (c.get("group") == group and c.get("name") == name) or purl.startswith(f"pkg:maven/{group}/{name}@"):
            found = c.get("version") or purl.split("@", 1)[-1]
            break
    reported = False
    for res in json.loads(trivy_json or "{}").get("Results", []) or []:
        for v in res.get("Vulnerabilities") or []:
            if v.get("VulnerabilityID") == advisory and (v.get("PkgName") in (package, name)):
                reported = True
    return {
        "component_present": found is not None,
        "version_preserved": found == expected_version,
        "not_reported": not reported,
        "found_version": found,
    }


def collect_facts(result: dict) -> dict:
    """정본 수치(spec §4.5, 축 3). 값이 비수치(True/False/버전 문자열)라 문자열로 인용한다(리뷰 I4)."""
    return {
        "knownfp.component_present": str(result["component_present"]),
        "knownfp.version_preserved": str(result["version_preserved"]),
        "knownfp.not_reported": str(result["not_reported"]),
        "knownfp.found_version": str(result["found_version"]),
    }


def render(result: dict) -> str:
    """known-FP 3단계 문서(생성기 — reconcile 이 같은 함수로 재생성해 비교한다)."""
    rows = "\n".join(f"| {k} | {v} |" for k, v in result.items())
    return "# known-FP CVE-2025-59250 (mssql-jdbc) 3단계\n\n| 단계 | 결과 |\n|---|---|\n" + rows + "\n"
