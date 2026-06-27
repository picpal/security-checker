"""컴플라이언스 매핑 — CWE 를 허브로 KISA(49 보안약점)·PCI-DSS 6.2.4 로 파생.

KISA/PCI 는 공식 기계가독 룰셋을 제공하지 않으므로(가이드 PDF + CWE 매핑만 제공),
우리는 도구가 이미 채운 typed Finding.cwe 를 역매핑해 컴플라이언스 뷰를 만든다.
순수 결정적 함수 — 외부 룰 의존 0 (원칙2: 결정적/LLM 경계).
"""

from secscan.compliance import enrich_compliance, map_compliance
from secscan.models import Compliance, Finding


def test_maps_sql_injection_cwe_to_kisa_and_pci():
    c = map_compliance(("CWE-89",))
    assert any(w.name == "SQL 삽입" for w in c.kisa)
    assert any("입력" in w.category for w in c.kisa)
    assert any("injection" in p for p in c.pci)


def test_maps_deserialization_cwe_to_kisa_code_error():
    c = map_compliance(("CWE-502",))
    assert any(w.name == "신뢰할 수 없는 데이터의 역직렬화" for w in c.kisa)
    assert any("코드오류" in w.category for w in c.kisa)


def test_maps_hardcoded_secret_cwe_to_kisa_security_function():
    c = map_compliance(("CWE-798",))
    assert any("하드코드" in w.name for w in c.kisa)
    assert any("보안기능" in w.category for w in c.kisa)
    assert any("access control" in p for p in c.pci)


def test_maps_weak_crypto_to_pci_cryptography():
    c = map_compliance(("CWE-327",))
    assert any("취약한 암호화" in w.name for w in c.kisa)
    assert any("cryptography" in p for p in c.pci)


def test_multiple_cwes_are_deduped():
    c = map_compliance(("CWE-89", "CWE-89"))
    assert len([w for w in c.kisa if w.name == "SQL 삽입"]) == 1


def test_unmapped_cwe_returns_empty():
    c = map_compliance(("CWE-99999",))
    assert c.kisa == ()
    assert c.pci == ()


def test_empty_cwe_returns_empty_compliance():
    assert map_compliance(()) == Compliance()


def test_enrich_sets_compliance_on_findings_with_cwe():
    f = Finding(category="sast", cwe=("CWE-89",))
    out = enrich_compliance([f])
    assert out[0].compliance is not None
    assert any(w.name == "SQL 삽입" for w in out[0].compliance.kisa)


def test_enrich_leaves_compliance_none_when_no_mapping():
    # cwe 없거나 매핑 없는 finding 은 compliance 를 비워둔다(보고서에서 표기 생략).
    f = Finding(category="secret", cwe=())
    out = enrich_compliance([f])
    assert out[0].compliance is None


def test_kisa_table_covers_49_weaknesses():
    from secscan.compliance import _KISA_TABLE

    codes = {w.code for w, _ in _KISA_TABLE}
    assert len(codes) == 49  # KISA 2021 가이드 = 49개 약점


def test_each_cwe_maps_to_single_kisa_weakness():
    # 한 CWE 가 두 약점에 매핑되면 역매핑이 모호해진다 — 데이터 무결성 가드.
    from secscan.compliance import _KISA_TABLE

    seen: dict[str, str] = {}
    for w, cwes in _KISA_TABLE:
        for c in cwes:
            assert c not in seen, f"{c} 중복: {seen.get(c)} vs {w.code}"
            seen[c] = w.code
