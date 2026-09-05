"""증거 README 생성기(최종 리뷰 Rec 5) — meta.json 들에서 표를 만든다. 손기입 수치 없음."""
from __future__ import annotations

import json
from pathlib import Path

from secscan.output._status import status_rows


def render(evidence_root: Path) -> str:
    root = Path(evidence_root)
    L = [f"# 증거 동결 {root.name} (생성 문서 — tools/verify/evidence_readme.py)", "",
         "| 디렉토리 | 스냅샷 | 프로파일 | 스캐너 status | findings | 소요(s) | 도달성 사유 | 재입력 |", "|---|---|---|---|---|---|---|---|"]
    for d in sorted(p for p in root.iterdir() if p.is_dir() and (p / "meta.json").exists()):
        m = json.loads((d / "meta.json").read_text(encoding="utf-8"))
        n = len(json.loads((d / "findings.json").read_text(encoding="utf-8")).get("findings", [])) if (d / "findings.json").exists() else "-"
        st = ", ".join(f"{s['tool']}({s['status']})" for s in status_rows(m))
        L.append(f"| {d.name} | {m.get('snapshot', '')} | {m.get('profile', '')} | {st} | {n} | {m.get('elapsed_s', '')} | "
                 f"{m.get('reachability', {}).get('reason', '')} | {'예' if m.get('reinput_from') else ''} |")
    L += ["", "- 도구 버전: 각 `meta.json` `tool_versions`. 격리: 스냅샷별 scratch·GRADLE_USER_HOME·크리덴셜 제거·secret 검증 never(`meta.isolated`).", ""]
    return "\n".join(L)
