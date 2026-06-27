"""합의(consensus) dedup — 같은 취약점을 지목한 도구를 한 Finding 으로 병합.

dedup_key 가 같으면 합친다(spec §10 레버 ③). severity 는 max, cwe/fixed/aliases/
references 는 union, consensus.tools/score 는 누적. 입력 Finding 은 변형하지 않는다.
"""

from __future__ import annotations

from dataclasses import replace

from ..models import Advisory, Consensus, Finding, max_severity, min_confidence


def _uniq(*seqs) -> tuple:
    out: dict = {}
    for seq in seqs:
        for x in seq or ():
            out[x] = None
    return tuple(out)


def _combine(a: Finding, b: Finding) -> Finding:
    tools = _uniq(
        a.consensus.tools if a.consensus else (),
        b.consensus.tools if b.consensus else (),
    )
    adv = a.advisory
    if adv is not None:
        b_adv = b.advisory
        adv = Advisory(
            id=adv.id,
            aliases=_uniq(adv.aliases, b_adv.aliases if b_adv else ()),
            fixed_versions=_uniq(adv.fixed_versions, b_adv.fixed_versions if b_adv else ()),
        )
    return replace(
        a,
        severity=max_severity(a.severity, b.severity),
        confidence=min_confidence(a.confidence, b.confidence),
        cwe=_uniq(a.cwe, b.cwe),
        owasp=_uniq(a.owasp, b.owasp),
        references=_uniq(a.references, b.references),
        advisory=adv,
        consensus=Consensus(tools=tools, score=len(tools)),
        tool="+".join(tools),
    )


def merge_consensus(findings: list[Finding]) -> list[Finding]:
    merged: dict[str, Finding] = {}
    for f in findings:
        key = f.dedup_key
        if key in merged:
            merged[key] = _combine(merged[key], f)
        else:
            merged[key] = f
    return list(merged.values())
