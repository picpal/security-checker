"""컴플라이언스 매핑 — CWE 를 허브로 KISA·PCI-DSS 뷰를 파생(결정적).

배경(2026-06 조사): KISA(행안부 소프트웨어 보안약점)·PCI-DSS 둘 다 *기계가독 탐지
룰셋을 공식 제공하지 않는다*. KISA 는 49개 약점을 가이드 PDF + 각 약점의 MITRE CWE
매핑으로만, PCI-DSS v4.0.1 §6.2.4 는 공격유형 분류로만 제공한다. 따라서 우리는 별도
룰을 저작하지 않고, 도구들이 이미 채운 typed Finding.cwe 를 역매핑해 컴플라이언스
뷰를 만든다. 이는 판정(oracle)이 아니라 분류이며 순수 결정적(원칙2 경계 준수).

출처:
- KISA 소프트웨어 보안약점 진단가이드(2021) — 49개 약점, 7대 분류, 각 항목 CWE 매핑.
- PCI-DSS v4.0.1 Requirement 6.2.4 — injection/data/crypto/business-logic/access-control.
KisaWeakness.code 는 보고 안정성을 위한 *내부* 식별자이며 KISA 공식 번호가 아니다.
"""

from __future__ import annotations

from .models import Compliance, Finding, KisaWeakness

# --- 7대 분류 ---
_IV = "입력데이터 검증 및 표현"
_SF = "보안기능"
_TS = "시간 및 상태"
_EH = "에러처리"
_CE = "코드오류"
_EN = "캡슐화"
_AM = "API 오용"

# 약점(코드, 분류, 이름) → 해당 약점에 매핑되는 CWE 목록. KISA 가이드 기준.
_KISA_TABLE: list[tuple[KisaWeakness, list[str]]] = [
    # 입력데이터 검증 및 표현 (17)
    (KisaWeakness("IV-01", _IV, "SQL 삽입"), ["CWE-89"]),
    (KisaWeakness("IV-02", _IV, "코드 삽입"), ["CWE-94", "CWE-95"]),
    (KisaWeakness("IV-03", _IV, "경로 조작 및 자원 삽입"), ["CWE-22", "CWE-99"]),
    (KisaWeakness("IV-04", _IV, "크로스사이트 스크립트(XSS)"), ["CWE-79"]),
    (KisaWeakness("IV-05", _IV, "운영체제 명령어 삽입"), ["CWE-78"]),
    (KisaWeakness("IV-06", _IV, "위험한 형식 파일 업로드"), ["CWE-434"]),
    (KisaWeakness("IV-07", _IV, "신뢰되지 않는 URL 주소로 자동접속 연결"), ["CWE-601"]),
    (KisaWeakness("IV-08", _IV, "부적절한 XML 외부 개체 참조(XXE)"), ["CWE-611"]),
    (KisaWeakness("IV-09", _IV, "XML 삽입"), ["CWE-91", "CWE-643", "CWE-652"]),
    (KisaWeakness("IV-10", _IV, "LDAP 삽입"), ["CWE-90"]),
    (KisaWeakness("IV-11", _IV, "크로스사이트 요청 위조(CSRF)"), ["CWE-352"]),
    (KisaWeakness("IV-12", _IV, "서버사이드 요청 위조(SSRF)"), ["CWE-918"]),
    (KisaWeakness("IV-13", _IV, "HTTP 응답분할"), ["CWE-113"]),
    (KisaWeakness("IV-14", _IV, "정수형 오버플로우"), ["CWE-190"]),
    (KisaWeakness("IV-15", _IV, "보안기능 결정에 사용되는 부적절한 입력값"), ["CWE-807"]),
    (KisaWeakness("IV-16", _IV, "메모리 버퍼 오버플로우"), ["CWE-119", "CWE-120"]),
    (KisaWeakness("IV-17", _IV, "포맷 스트링 삽입"), ["CWE-134"]),
    # 보안기능 (16)
    (KisaWeakness("SF-01", _SF, "적절한 인증 없는 중요기능 허용"), ["CWE-306"]),
    (KisaWeakness("SF-02", _SF, "부적절한 인가"), ["CWE-285"]),
    (KisaWeakness("SF-03", _SF, "중요한 자원에 대한 잘못된 권한 설정"), ["CWE-732"]),
    (KisaWeakness("SF-04", _SF, "취약한 암호화 알고리즘 사용"), ["CWE-327"]),
    (KisaWeakness("SF-05", _SF, "암호화되지 않은 중요정보"), ["CWE-311", "CWE-312", "CWE-319"]),
    (KisaWeakness("SF-06", _SF, "하드코드된 중요정보"), ["CWE-798", "CWE-259", "CWE-321"]),
    (KisaWeakness("SF-07", _SF, "충분하지 않은 키 길이 사용"), ["CWE-326"]),
    (KisaWeakness("SF-08", _SF, "적절하지 않은 난수값 사용"), ["CWE-330", "CWE-338"]),
    (KisaWeakness("SF-09", _SF, "취약한 비밀번호 허용"), ["CWE-521"]),
    (KisaWeakness("SF-10", _SF, "부적절한 전자서명 확인"), ["CWE-347"]),
    (KisaWeakness("SF-11", _SF, "부적절한 인증서 유효성 검증"), ["CWE-295"]),
    (KisaWeakness("SF-12", _SF, "사용자 하드디스크에 저장되는 쿠키를 통한 정보 노출"), ["CWE-539"]),
    (KisaWeakness("SF-13", _SF, "주석문 안에 포함된 시스템 주요정보"), ["CWE-615"]),
    (KisaWeakness("SF-14", _SF, "솔트 없이 일방향 해시함수 사용"), ["CWE-759", "CWE-760"]),
    (KisaWeakness("SF-15", _SF, "무결성 검사 없는 코드 다운로드"), ["CWE-494"]),
    (KisaWeakness("SF-16", _SF, "반복된 인증시도 제한 기능 부재"), ["CWE-307"]),
    # 시간 및 상태 (2)
    (KisaWeakness("TS-01", _TS, "경쟁조건: 검사시점과 사용시점(TOCTOU)"), ["CWE-367"]),
    (KisaWeakness("TS-02", _TS, "종료되지 않는 반복문 또는 재귀함수"), ["CWE-835"]),
    # 에러처리 (3)
    (KisaWeakness("EH-01", _EH, "오류 메시지 정보 노출"), ["CWE-209"]),
    (KisaWeakness("EH-02", _EH, "오류 상황 대응 부재"), ["CWE-390", "CWE-391"]),
    (KisaWeakness("EH-03", _EH, "부적절한 예외 처리"), ["CWE-248", "CWE-754"]),
    # 코드오류 (5)
    (KisaWeakness("CE-01", _CE, "Null Pointer 역참조"), ["CWE-476"]),
    (KisaWeakness("CE-02", _CE, "부적절한 자원 해제"), ["CWE-404", "CWE-772"]),
    (KisaWeakness("CE-03", _CE, "해제된 자원 사용"), ["CWE-416"]),
    (KisaWeakness("CE-04", _CE, "초기화되지 않은 변수 사용"), ["CWE-457"]),
    (KisaWeakness("CE-05", _CE, "신뢰할 수 없는 데이터의 역직렬화"), ["CWE-502"]),
    # 캡슐화 (4)
    (KisaWeakness("EN-01", _EN, "잘못된 세션에 의한 데이터 정보 노출"), ["CWE-488"]),
    (KisaWeakness("EN-02", _EN, "제거되지 않고 남은 디버그 코드"), ["CWE-489"]),
    (KisaWeakness("EN-03", _EN, "Public 메서드로부터 반환된 Private 배열"), ["CWE-495"]),
    (KisaWeakness("EN-04", _EN, "Private 배열에 Public 데이터 할당"), ["CWE-496"]),
    # API 오용 (2)
    (KisaWeakness("AM-01", _AM, "DNS lookup 에 의존한 보안결정"), ["CWE-350"]),
    (KisaWeakness("AM-02", _AM, "취약한 API 사용"), ["CWE-227", "CWE-676"]),
]

KISA_BY_CWE: dict[str, KisaWeakness] = {
    cwe: weakness for weakness, cwes in _KISA_TABLE for cwe in cwes
}

# --- PCI-DSS v4.0.1 §6.2.4 공격유형 ---
_PCI_INJECTION = "PCI-DSS 6.2.4 — injection"
_PCI_DATA = "PCI-DSS 6.2.4 — data/buffer manipulation"
_PCI_CRYPTO = "PCI-DSS 6.2.4 — cryptography"
_PCI_LOGIC = "PCI-DSS 6.2.4 — business logic"
_PCI_ACCESS = "PCI-DSS 6.2.4 — access control"

# 6.2.4 는 거친 공격유형 분류라 코드레벨로 명확히 대응되는 CWE 만 매핑한다.
# (정보노출·코드품질 약점 등은 6.2.4 직접 대응이 약해 비워둔다 — 과대 매핑 금지.)
_PCI_GROUPS: list[tuple[str, list[str]]] = [
    (_PCI_INJECTION, ["CWE-89", "CWE-79", "CWE-94", "CWE-95", "CWE-78", "CWE-90",
                      "CWE-91", "CWE-643", "CWE-652", "CWE-113", "CWE-611",
                      "CWE-134", "CWE-502", "CWE-22", "CWE-99"]),
    (_PCI_DATA, ["CWE-119", "CWE-120", "CWE-190"]),
    (_PCI_CRYPTO, ["CWE-327", "CWE-326", "CWE-311", "CWE-312", "CWE-319",
                   "CWE-330", "CWE-338", "CWE-347", "CWE-295", "CWE-759",
                   "CWE-760", "CWE-321"]),
    (_PCI_LOGIC, ["CWE-352", "CWE-601", "CWE-918", "CWE-807", "CWE-350",
                  "CWE-367", "CWE-434"]),
    (_PCI_ACCESS, ["CWE-306", "CWE-285", "CWE-732", "CWE-798", "CWE-259",
                   "CWE-521", "CWE-307"]),
]


def _build_pci() -> dict[str, tuple[str, ...]]:
    out: dict[str, list[str]] = {}
    for label, cwes in _PCI_GROUPS:
        for cwe in cwes:
            out.setdefault(cwe, []).append(label)
    return {cwe: tuple(labels) for cwe, labels in out.items()}


PCI_BY_CWE: dict[str, tuple[str, ...]] = _build_pci()


def map_compliance(cwes: tuple[str, ...]) -> Compliance:
    """CWE 튜플 → KISA/PCI 컴플라이언스 뷰. 순서 보존 + 중복 제거."""
    kisa: list[KisaWeakness] = []
    pci: list[str] = []
    seen_k: set[str] = set()
    seen_p: set[str] = set()
    for cwe in cwes:
        w = KISA_BY_CWE.get(cwe)
        if w is not None and w.code not in seen_k:
            seen_k.add(w.code)
            kisa.append(w)
        for label in PCI_BY_CWE.get(cwe, ()):
            if label not in seen_p:
                seen_p.add(label)
                pci.append(label)
    return Compliance(kisa=tuple(kisa), pci=tuple(pci))


def enrich_compliance(findings: list[Finding]) -> list[Finding]:
    """각 finding 의 cwe 로 컴플라이언스 매핑을 채운다. 매핑 없으면 None 유지."""
    for f in findings:
        c = map_compliance(f.cwe)
        f.compliance = c if (c.kisa or c.pci) else None
    return findings
