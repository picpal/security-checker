"""시크릿 검증 — Gitleaks(광범위 탐지) → TruffleHog(라이브 키만 검증) 2단.

검증은 자격증명을 제3자(TruffleHog 검증 엔드포인트)로 전송하므로 기본 off.
network 정책으로 강제 차단(never)을 보장한다(spec §8).
"""
