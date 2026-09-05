"""V4 모델 확장(spec §7.1) — 새 필드의 기본값·불변식. dedup_key 는 변하지 않는다."""

from dataclasses import fields, is_dataclass

import secscan.models as m
from secscan.models import (
    ACTIONABLE, DEMOTED, DISPOSITIONS, REVIEW, SUPPRESSED,
    Advisory, Component, Cvss, Finding, Occurrence, ScannerStatus,
)


def test_new_fields_have_safe_defaults():
    f = Finding(category="sca", component=Component("maven", "a:b", "1.0"), advisory=Advisory("CVE-1"))
    assert f.occurrences == () and f.disposition is None and f.tier is None
    assert f.advisory.cvss == () and f.advisory.published is None
    assert f.dedup_key == "sca|maven|a:b|1.0|CVE-1"  # 키 구성 불변


def test_occurrence_and_cvss_are_hashable_for_union():
    o = Occurrence("trivy", "pom.xml", "a:b", "1.0")
    c = Cvss("nvd", "3.1", 9.8, "CVSS:3.1/AV:N")
    assert len({o, Occurrence("trivy", "pom.xml", "a:b", "1.0")}) == 1
    assert len({c, c}) == 1


def test_disposition_constants():
    assert DISPOSITIONS == (ACTIONABLE, REVIEW, DEMOTED, SUPPRESSED)
    assert ScannerStatus("trivy", "ok").duration_s is None and ScannerStatus("trivy", "ok").message == ""


def test_every_dataclass_in_models_is_a_dataclass():
    for name in ("Occurrence", "Cvss", "ScannerStatus"):
        assert is_dataclass(getattr(m, name))
