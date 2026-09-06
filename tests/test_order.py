"""출력 전 안정 정렬(spec §7.1): category → severity 내림 → 도달성 내림 → dedup_key."""
from secscan.models import REACHABLE, UNREACHABLE, Advisory, Component, Finding, Location, Reachability
from secscan.output.order import sort_findings


def _sca(pkg, sev, reach):
    return Finding(category="sca", severity=sev, component=Component("maven", pkg, "1"), advisory=Advisory("CVE-1"),
                   reachability=Reachability(reach))


def test_sort_is_deterministic_and_keyed_as_spec():
    fs = [_sca("z:z", "low", REACHABLE), _sca("a:a", "high", UNREACHABLE), _sca("b:b", "high", REACHABLE),
          Finding(category="sast", severity="critical", rule_id="r", location=Location("x", 1)),
          Finding(category="secret", severity="high", rule_id="k", location=Location("y", 1))]
    out = sort_findings(fs)
    assert [f.category for f in out] == ["sast", "sca", "sca", "sca", "secret"]
    sca = [f.component.package for f in out if f.category == "sca"]
    assert sca == ["b:b", "a:a", "z:z"]  # high reachable → high unreachable → low
    assert sort_findings(list(reversed(fs))) == out
