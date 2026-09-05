"""생성기 레지스트리 — 모든 생성 문서·facts 가 한 경로로 만들어지고(write_all) 같은 경로로 재생성·비교된다(reconcile).

새 축 = Generator 한 줄 추가. 검사 누락이 구조적으로 불가능해진다(최종 리뷰 Rec 2).
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from secscan.measure import load_gt_manifest

from . import differential, evidence_readme, fidelity, gate, jar_surface, known_fp, profile_contract, reach_app, report
from ._facts import facts_text


@dataclass(frozen=True)
class Ctx:
    results: Path
    evidence_root: Path
    gt_b: Path
    gt_a: Path
    std_name: str = "a483b3b1-standard"
    deep_name: str = "a483b3b1-deep"
    jar_name: str = "a483b3b1-jar"

    @property
    def std(self) -> Path: return self.evidence_root / self.std_name
    @property
    def deep_meta(self) -> Path: return self.evidence_root / self.deep_name / "meta.json"
    @property
    def jar_raw(self) -> Path: return self.evidence_root / self.jar_name / "raw" / "trivy-rootfs.json"
    @property
    def jar_status(self) -> Path: return self.evidence_root / self.jar_name / "status.json"


@dataclass(frozen=True)
class Generator:
    doc: str  # 결과 디렉토리 안 문서 파일명(비교·보고 표시용 이름이기도 함)
    facts: str | None  # facts 파일명(없으면 None) — 항상 결과 디렉토리 안
    produce: Callable[["Ctx"], tuple[str, dict | None]]  # (문서 텍스트, facts dict)
    path: Callable[["Ctx"], Path] | None = None  # None = 결과 디렉토리 안(ctx.results/doc). 있으면 이 경로 사용(README 등, Task 13)


def _via_cli(main, args: list[str], doc_name: str, facts_name: str | None):
    with tempfile.TemporaryDirectory() as td, contextlib.redirect_stdout(io.StringIO()):
        t = Path(td)
        argv = args + ["--out", str(t / doc_name)] + (["--facts", str(t / "f.json")] if facts_name else [])
        main(argv)
        doc = (t / doc_name).read_text(encoding="utf-8")
        facts = json.loads((t / "f.json").read_text(encoding="utf-8")) if facts_name else None
    return doc, facts


def _gt_b_match(c: Ctx):
    return _via_cli(report.main, ["--evidence", str(c.std), "--gt", str(c.gt_b)], "m.md", "facts.json")


def _gt_a_diff(c: Ctx):
    return _via_cli(differential.main, ["--evidence-root", str(c.evidence_root), "--gt", str(c.gt_a)], "d.md", "facts-gta.json")


def _known_fp(c: Ctx):
    from .reconcile import _KNOWN_FP
    r = known_fp.check_known_fp((c.std / "raw" / "bom.cdx.json").read_text(encoding="utf-8"),
                                (c.std / "raw" / "trivy.json").read_text(encoding="utf-8"), **_KNOWN_FP)
    return known_fp.render(r), known_fp.collect_facts(r)


def _profile(c: Ctx):
    statuses = {s["tool"]: s["status"] for s in json.loads(c.deep_meta.read_text(encoding="utf-8"))["scanner_status"]}
    return profile_contract.render_doc(statuses), profile_contract.collect_facts(statuses)


def _surface(c: Ctx):
    ok = bool(json.loads(c.jar_status.read_text(encoding="utf-8")).get("jar_build_scan_ok", False))
    bom, jar = (c.std / "raw" / "bom.cdx.json").read_text(encoding="utf-8"), c.jar_raw.read_text(encoding="utf-8")
    m = load_gt_manifest(str(c.gt_b))
    return jar_surface.render_doc(ok, bom, jar, m), jar_surface.collect_facts(ok, bom, jar, m)


def _fidelity(c: Ctx):
    r = fidelity.check(c.std)
    return fidelity.render(r), fidelity.collect_facts(r)


def _reach_app(c: Ctx):
    r = reach_app.evaluate()
    return reach_app.render(r), reach_app.collect_facts(r)


def _gate(c: Ctx):
    from .reconcile import load_facts
    return gate.render_gate(load_facts(c.results)), None


def _readme(c: Ctx):
    return evidence_readme.render(c.evidence_root), None


GENERATORS: list[Generator] = [
    Generator("gt-b-match.md", "facts.json", _gt_b_match),
    Generator("gt-a-differential.md", "facts-gta.json", _gt_a_diff),
    Generator("known-fp.md", "facts-knownfp.json", _known_fp),
    Generator("profile-contract.md", "facts-profile.json", _profile),
    Generator("input-surface.md", "facts-surface.json", _surface),
    Generator("fidelity.md", "facts-fidelity.json", _fidelity),
    Generator("reach-app.md", "facts-reachapp.json", _reach_app),
    Generator("gate.md", None, _gate),  # 마지막: 위 facts 를 읽는다
    Generator("README.md", None, _readme, path=lambda c: c.evidence_root / "README.md"),  # 문서 위치가 evidence 루트(Rec 5)
]


def write_all(ctx: Ctx) -> list[Path]:
    from .reconcile import is_legacy_results_dir
    ctx.results.mkdir(parents=True, exist_ok=True)
    legacy = is_legacy_results_dir(ctx.results)
    written = []
    for g in GENERATORS:
        if legacy and g.doc == "README.md":
            # I1(최종 리뷰) — legacy 결과 디렉토리(플랜 1)의 README.md 는 evidence 루트에 있는
            # 손기입 운영 로그다(reconcile.regenerate 와 같은 가드, 같은 이유: Rec 5).
            continue
        doc, facts = g.produce(ctx)
        p = g.path(ctx) if g.path else ctx.results / g.doc
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(doc, encoding="utf-8"); written.append(p)
        if g.facts:
            q = ctx.results / g.facts; q.write_text(facts_text(facts), encoding="utf-8"); written.append(q)
    return written


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="tools.verify.generators")
    p.add_argument("--results", required=True); p.add_argument("--evidence-root", required=True)
    p.add_argument("--gt-b", required=True); p.add_argument("--gt-a", required=True)
    p.add_argument("--std", default="a483b3b1-standard"); p.add_argument("--deep", default="a483b3b1-deep"); p.add_argument("--jar", default="a483b3b1-jar")
    a = p.parse_args(argv)
    for w in write_all(Ctx(Path(a.results), Path(a.evidence_root), Path(a.gt_b), Path(a.gt_a), a.std, a.deep, a.jar)):
        print(w)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
