"""projection 계약(spec §7.3) — 포맷별 포함/부분/손실 필드. `docs/output-contracts.md` 는 이 상수에서 생성된다."""
from __future__ import annotations

from dataclasses import dataclass, fields

from ..models import Finding

FIELDS: tuple[str, ...] = tuple(f.name for f in fields(Finding)) + ("id",)


@dataclass(frozen=True)
class Contract:
    includes: frozenset[str]
    partial: dict[str, str]  # 필드 → 어떤 부분만 실리는지
    loses: frozenset[str]


def _c(includes, partial, loses) -> Contract:
    return Contract(frozenset(includes), dict(partial), frozenset(loses))


CONTRACTS: dict[str, Contract] = {
    "findings.json": _c(FIELDS, {}, ()),
    "markdown": _c(
        ["id", "severity", "rule_id", "cwe", "component", "reachability", "consensus", "compliance"],
        {"category": "절(SCA/시크릿 문구)로만 드러남", "advisory": "fixed_versions 만", "location": "file·start_line 만",
         "suppression": "reason·provenance·expiry 만"},
        # disposition/tier: markdown.py 는 disposition 을 "어느 절에 넣을지" 판단에만 쓰고 값 자체는
        # 리터럴로 출력하지 않는다(섹션 제목도 한글 고정 문구뿐). tier 는 어디서도 참조되지 않는다.
        # SARIF 와 달리 실제로 값이 텍스트에 실리지 않으므로 loses 로 기재(계약은 사실을 적는다).
        ["title", "tool", "owasp", "confidence", "source", "references", "verified", "occurrences",
         "disposition", "tier"]),
    "sarif": _c(
        ["id", "category", "severity", "title", "tool", "rule_id", "cwe", "confidence", "component", "reachability",
         "consensus", "compliance", "disposition", "tier"],
        {"advisory": "fixedVersions 만(aliases·cvss·published 손실)", "location": "file·startLine·endLine(snippet_ref 손실)",
         "suppression": "reason·provenance·evidence·expiry·state(scope·basis 손실)"},
        # references: rule helpUri 로 실릴 것으로 보였으나 secscan/output/sarif.py 는 f.references 를
        # 어디에도 쓰지 않는다(rule 에 helpUri 필드 자체가 없다) — 실제 출력에 맞춰 loses 로 기재.
        ["owasp", "source", "verified", "occurrences", "references"]),
    "xlsx": _c(
        ["id", "category", "severity", "title", "tool", "rule_id", "cwe", "confidence", "component", "reachability",
         "consensus", "verified", "compliance", "occurrences", "disposition", "tier"],
        {"advisory": "id·fixed·Max CVSS/Source·Published(aliases 손실)", "location": "file·line(end_line·snippet_ref 손실)",
         "suppression": "상태 열(reason 만)", "references": "URL 열에 첫 항목만"},
        ["owasp", "source"]),
}

# 계약 테스트용 프로브: 포함/부분 선언 필드가 출력 텍스트에 실제로 나타나는지 확인할 대표 문자열.
PROBES = {
    "id": lambda f: f.id, "category": lambda f: "SCA" if f.category == "sca" else f.category,
    "severity": lambda f: "위험" if f.severity == "high" else f.severity, "title": lambda f: f.title,
    "tool": lambda f: f.tool, "rule_id": lambda f: f.rule_id, "cwe": lambda f: f.cwe[0],
    "owasp": lambda f: f.owasp[0], "confidence": lambda f: f.confidence,
    "component": lambda f: f.component.package, "advisory": lambda f: f.advisory.fixed_versions[0],
    "location": lambda f: f.location.file if f.location else "", "source": lambda f: f.source,
    "reachability": lambda f: f.reachability.evidence, "consensus": lambda f: f.consensus.tools[0],
    "references": lambda f: f.references[0], "verified": lambda f: str(f.verified),
    "suppression": lambda f: f.suppression.reason, "compliance": lambda f: f.compliance.kisa[0].name,
    "occurrences": lambda f: f.occurrences[0].target, "disposition": lambda f: f.disposition,
    "tier": lambda f: f.tier or "",
}
# severity: markdown 은 한글 라벨("위험" 등)만, SARIF 는 "error"/"warning" 레벨이 아니라
# properties.severity 원문(영문, "high" 등)만 싣는다 — 포맷별 표현이 갈려 위 PROBES["severity"]
# 단일 문자열로는 양쪽을 동시에 검증할 수 없다. tests/test_contracts.py 가 sarif 검증 시
# f.severity(원문)를 별도로 쓴다(sarif.py 가 props["severity"] 에 원문을 싣는다).


def render_contracts() -> str:
    fmts = list(CONTRACTS)
    L = ["# 출력 계약 (projection contract) — 생성 문서", "",
         "`secscan/output/contracts.py` 의 상수에서 생성된다. 손으로 고치지 말 것(`tests/test_contracts.py` 가 대조).", "",
         "- ✓ 포함 · ◐ 부분(비고) · ✗ 손실. `findings.json` 만 lossless canonical(spec §7.2), 나머지는 projection(spec §7.3).",
         "- SARIF 는 출력 전용이며 내부 모델이 아니다(원칙 3).", "",
         "| 필드 | " + " | ".join(fmts) + " |", "|---|" + "---|" * len(fmts)]
    for field in FIELDS:
        cells = []
        for fmt in fmts:
            c = CONTRACTS[fmt]
            if field in c.includes:
                cells.append("✓")
            elif field in c.partial:
                cells.append(f"◐ {c.partial[field]}")
            else:
                cells.append("✗")
        L.append(f"| `{field}` | " + " | ".join(cells) + " |")
    L += ["", "## markdown 추가 규칙", "- finding 헤더 줄 끝에 `` · id `<12hex>` `` (억제 스코프 지정용).",
          "- 절(우선 조치/검토 후보/낮은 우선순위/억제됨/미판정)은 `disposition` 필드만 읽는다(재계산 금지).", ""]
    return "\n".join(L)
