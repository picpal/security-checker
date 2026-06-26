"""M1 인수(게이트) 회귀 테스트 — 결정적·오프라인(골든).

실제 스캐너/네트워크 없이, 픽스처에서 캡처한 골든(trivy/osv 출력 + atom usage 슬라이스)
으로 전체 파이프라인을 재현해 게이트 수치를 고정한다:
- 도달성 ground-truth 정확도 100% (commons-text 도달가능 / snakeyaml 도달불가)
- 도달성 on 으로 조치대상(actionable) FP 가 유의미하게 감소
"""

import json
from pathlib import Path

from secscan.adapters.base import OK, RawResult
from secscan.measure import reachability_stats, score_ground_truth
from secscan.models import REACHABLE, UNREACHABLE
from secscan.normalize import to_findings
from secscan.reachability.depscan import decide_reachability, parse_invoked_symbols
from secscan.reachability.engine import enrich_reachability

ROOT = Path(__file__).parent.parent
GOLDEN = ROOT / "tests" / "golden"


def _scan_findings_with_reachability():
    raws = [
        RawResult("trivy", OK, payload=(GOLDEN / "trivy-vuln-maven-app.json").read_text()),
        RawResult("osv-scanner", OK, payload=(GOLDEN / "osv-vuln-maven-app.json").read_text()),
    ]
    findings = to_findings(raws)
    invoked = parse_invoked_symbols((GOLDEN / "atom-usages-vuln-maven-app.json").read_text())
    out = enrich_reachability(
        findings, ".",
        provider=lambda t, to, f: decide_reachability(f, invoked),
        env_ok=lambda: True, count_loc=lambda t: 10,
    )
    assert out.ran is True
    return out.findings


def test_gate_reachability_ground_truth_is_perfect():
    findings = _scan_findings_with_reachability()
    gt = json.loads((ROOT / "fixtures" / "vuln-maven-app" / "expected.json").read_text())
    score = score_ground_truth(findings, gt)
    assert score.accuracy == 1.0, score.mistakes
    assert score.mistakes == []


def test_gate_reachable_and_unreachable_classified():
    findings = _scan_findings_with_reachability()
    by_cve = {}
    for f in findings:
        if f.advisory:
            by_cve[f.advisory.id] = f.reachability.status
    assert by_cve["CVE-2022-42889"] == REACHABLE  # commons-text, 앱이 호출
    assert by_cve["CVE-2022-1471"] == UNREACHABLE  # snakeyaml, 미호출


def test_gate_reachability_reduces_actionable_noise():
    findings = _scan_findings_with_reachability()
    stats = reachability_stats(findings)
    assert stats.total == 9
    assert stats.reachable == 1
    assert stats.actionable_on < stats.actionable_off  # FP 감소
    assert stats.noise_reduction >= 0.8  # 80%+ 노이즈 강등
