"""프로파일 계약(spec §5 축 1): 원 spec §8 기대 어댑터 vs 구현 PROFILES + 실제 status."""

from __future__ import annotations

from secscan.profiles import PROFILES

# 원 spec 2026-06-26 §8. bom-sca 는 "trivy(BOM)" 로 간주해 trivy 로 정규화한다.
SPEC_PROFILES: dict[str, frozenset[str]] = {
    "quick": frozenset({"trivy", "gitleaks"}),
    "accurate-sca": frozenset({"trivy", "osv-scanner"}),
    "standard": frozenset({"semgrep", "trivy", "osv-scanner", "gitleaks"}),
    "deep": frozenset({"semgrep", "trivy", "osv-scanner", "gitleaks", "spotbugs"}),
}
_ALIAS = {"bom-sca": "trivy"}


def compare_profiles() -> list[dict]:
    """원 spec vs 현재 구현 비교."""
    rows = []
    for name, spec in SPEC_PROFILES.items():
        impl = {_ALIAS.get(a, a) for a in PROFILES[name].adapter_names} if name in PROFILES else set()
        rows.append({"profile": name, "spec": sorted(spec), "impl": sorted(impl),
                     "missing": sorted(spec - impl), "extra": sorted(impl - spec),
                     "reachability": PROFILES[name].reachability if name in PROFILES else None})
    return rows


def render(rows: list[dict], statuses: dict[str, str]) -> str:
    """프로파일 계약 비교 표."""
    L = ["| 프로파일 | spec §8 | 구현 | 누락 | 초과 | 실제 status |", "|---|---|---|---|---|---|"]
    for r in rows:
        st = ", ".join(f"{a}={statuses.get(a, '-')}" for a in r["impl"])
        L.append(f"| {r['profile']} | {', '.join(r['spec'])} | {', '.join(r['impl'])} | "
                 f"{', '.join(r['missing']) or '-'} | {', '.join(r['extra']) or '-'} | {st} |")
    return "\n".join(L)


def render_doc(statuses: dict[str, str]) -> str:
    """프로파일 계약 문서(생성기 — reconcile 재생성 비교 대상)."""
    return "# 프로파일 계약 (spec §8 vs 구현 vs 실제)\n\n" + render(compare_profiles(), statuses) + "\n"


def collect_facts(statuses: dict[str, str]) -> dict:
    """정본 수치(spec §4.5, 축 1). `compare_profiles()` 의 missing/extra 리스트에서 직접 계산한다 —
    렌더된 마크다운을 되파싱하지 않는다(리뷰 I3)."""
    rows = compare_profiles()
    return {
        "profile.rows": len(rows),
        "profile.drift": sum(1 for r in rows if r["missing"] or r["extra"]),
    }
