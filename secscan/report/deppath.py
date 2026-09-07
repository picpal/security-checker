"""CycloneDX(cdxgen) 의존 그래프 → 직접/전이 경로 문자열(spec §5.3). 루트에서 BFS 최단 경로."""
from __future__ import annotations

import json
from collections import deque
from pathlib import Path

from ..models import Finding

NO_BOM = "BOM 없음"
NOT_IN_BOM = "BOM 에 없음"
UNREACHED = "BOM 에 있음(경로 미상)"
MAX_HOPS = 4


class DepGraph:
    def __init__(self, bom: dict):
        self.root = ((bom.get("metadata") or {}).get("component") or {}).get("bom-ref", "")
        self.deps = {d.get("ref"): list(d.get("dependsOn") or []) for d in bom.get("dependencies") or []}
        self.name = {}  # ref → artifact 이름
        self.by_key: dict[str, list[tuple[str, str]]] = {}  # "group:artifact" → [(version, ref)]
        for c in bom.get("components") or []:
            ref = c.get("bom-ref") or c.get("purl") or ""
            if not ref:
                continue
            self.name[ref] = c.get("name", ref)
            key = f"{c.get('group', '')}:{c.get('name', '')}" if c.get("group") else c.get("name", "")
            self.by_key.setdefault(key, []).append((c.get("version", ""), ref))
        self.parent = self._bfs()

    @classmethod
    def from_path(cls, path) -> "DepGraph | None":
        p = Path(path)
        if not p.exists():
            return None
        try:
            return cls(json.loads(p.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError):
            return None

    def _bfs(self) -> dict[str, str | None]:
        parent: dict[str, str | None] = {self.root: None}
        q = deque([self.root])
        while q:
            n = q.popleft()
            for m in self.deps.get(n, []):
                if m not in parent:
                    parent[m] = n
                    q.append(m)
        return parent

    def _chain(self, ref: str) -> list[str]:
        out, n = [], self.parent.get(ref)
        while n is not None and n != self.root:
            out.append(self.name.get(n, n))
            n = self.parent.get(n)
        return out

    def path_for(self, package: str, version: str) -> str:
        cands = self.by_key.get(package)
        if not cands:
            return NOT_IN_BOM
        exact = [r for v, r in cands if v == version]
        ver_note = ""
        if exact:
            ref = exact[0]
        else:
            other_v, ref = sorted(cands)[0]
            ver_note = f"(버전 상이: {other_v})"
        if ref not in self.parent:
            return UNREACHED
        chain = self._chain(ref)
        if not chain:
            return f"직접{ver_note}"
        shown = chain[:MAX_HOPS]
        tail = " ← …" if len(chain) > MAX_HOPS else ""
        return f"전이{ver_note} ← " + " ← ".join(shown) + tail


def deppaths_for(findings: list[Finding], graph: DepGraph | None) -> dict[str, str]:
    out = {}
    for f in findings:
        if f.category != "sca" or f.component is None:
            continue
        out[f.id] = graph.path_for(f.component.package, f.component.version) if graph else NO_BOM
    return out
