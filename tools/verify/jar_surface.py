"""입력면 교차(spec §5 축 5): 배포 jar(trivy rootfs) vs cdxgen BOM 인벤토리·버전 비교.

주의: Trivy 언어 지원표상 jar/war/ear 는 image·rootfs 모드에서만 분석된다 — `trivy fs` 는 소스 매니페스트(pom/gradle) 전용이라
빌드 산출물 디렉토리에 돌리면 "language-specific files num=0" 으로 조용히 0건이 된다(2026-09-05 실측). 보안팀 결과(Target=Java, Type=jar)와
같은 표면은 rootfs 다.

빌드·스캔은 CLI 로 실행하고(격리 env 상속), 비교는 순수 함수다.
사용: python -m tools.verify.jar_surface --repo-dir <scratch>/<sha>/repo --bom <bom.json> \
        --gt docs/verification/ground-truth/gt-b-sca.json --out <md>
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from secscan.measure import GtManifest, load_gt_manifest

from ._facts import facts_text


def inventory_from_bom(bom_json: str) -> dict[str, str]:
    inv: dict[str, str] = {}
    for c in json.loads(bom_json or "{}").get("components", []) or []:
        g, n, v = c.get("group"), c.get("name"), c.get("version")
        if not (g and n):
            purl = c.get("purl", "")
            if purl.startswith("pkg:maven/"):
                body = purl[len("pkg:maven/"):]
                gn, _, ver = body.partition("@")
                g, _, n = gn.partition("/")
                v = v or ver.split("?", 1)[0]
        if g and n and v:
            inv[f"{g}:{n}"] = v
    return inv


def inventory_from_trivy(trivy_json: str) -> dict[str, str]:
    """패키지별로 관측된 모든 버전을 모은다(덮어쓰지 않음) — 같은 jar 안에서 trivy 가

    같은 패키지를 서로 다른 버전으로 이중 보고하는 경우(예: mssql-jdbc 13.2.1 /
    13.2.1.jre11)를 감춰서는 안 된다(spec §5 축 5). 버전이 하나뿐이면 평문 문자열,
    여럿이면 정렬해 " / "로 병기한다("|"는 마크다운 표 셀 구분자와 충돌하므로 사용하지 않음).
    """
    versions: dict[str, set[str]] = {}
    for res in json.loads(trivy_json or "{}").get("Results", []) or []:
        for p in res.get("Packages") or []:
            if p.get("Name") and p.get("Version"):
                versions.setdefault(p["Name"], set()).add(p["Version"])
        for v in res.get("Vulnerabilities") or []:
            if v.get("PkgName") and v.get("InstalledVersion"):
                versions.setdefault(v["PkgName"], set()).add(v["InstalledVersion"])
    return {k: " / ".join(sorted(vs)) for k, vs in versions.items()}


def vuln_installed_versions(trivy_json: str) -> list[tuple[str, str, str]]:
    """(advisory, 패키지, InstalledVersion) — jar 표면에서 취약점이 실제로 부착된 버전(spec §5 축 5)."""
    rows: list[tuple[str, str, str]] = []
    for res in json.loads(trivy_json or "{}").get("Results", []) or []:
        for v in res.get("Vulnerabilities") or []:
            vid, pkg, ver = v.get("VulnerabilityID"), v.get("PkgName"), v.get("InstalledVersion")
            if vid and pkg and ver:
                rows.append((vid, pkg, ver))
    return sorted(rows)


def diff_inventories(a: dict[str, str], b: dict[str, str]) -> dict:
    return {
        "only_a": sorted(set(a) - set(b)),
        "only_b": sorted(set(b) - set(a)),
        "version_differs": {k: (a[k], b[k]) for k in sorted(set(a) & set(b)) if a[k] != b[k]},
    }


def compare_installed(inv: dict[str, str], manifest: GtManifest) -> list[dict]:
    rows, seen = [], set()
    for e in manifest.entries:
        if e.package in seen:
            continue
        seen.add(e.package)
        got = inv.get(e.package)
        rows.append({"package": e.package, "manifest": e.installed, "inventory": got, "match": got == e.installed})
    return rows


def collect_facts(ok: bool, bom_json: str, jar_json: str, manifest: GtManifest) -> dict:
    """정본 수치(spec §4.5, 축 5 — 입력면 교차). 문서는 이 값을 `<!-- fact:id -->` 마커와 함께 인용만 한다."""
    inv_bom = inventory_from_bom(bom_json)
    inv_jar = inventory_from_trivy(jar_json or "{}")
    diff = diff_inventories(inv_bom, inv_jar)
    gt_packages = {e.package for e in manifest.entries}
    cmp_bom = compare_installed(inv_bom, manifest)
    cmp_jar = compare_installed(inv_jar, manifest)
    vulns_for_gt = [row for row in vuln_installed_versions(jar_json or "{}") if row[1] in gt_packages]
    return {
        "surface.jar_ok": str(ok),
        "surface.bom_only": len(diff["only_a"]),
        "surface.jar_only": len(diff["only_b"]),
        "surface.version_differs": len(diff["version_differs"]),
        "surface.gt_match_bom": f"{sum(1 for r in cmp_bom if r['match'])}/{len(cmp_bom)}",
        "surface.gt_match_jar": f"{sum(1 for r in cmp_jar if r['match'])}/{len(cmp_jar)}",
        "surface.vuln_rows_gt": len(vulns_for_gt),
        "surface.jar_packages": len(inv_jar),
        "surface.bom_packages": len(inv_bom),
    }


def render(diff: dict, cmp_bom: list[dict], cmp_jar: list[dict], vulns_for_gt: list[tuple[str, str, str]]) -> str:
    L = ["## 인벤토리 차이 (BOM=a, jar=b)",
         f"- BOM 에만: {len(diff['only_a'])} — {', '.join(diff['only_a'][:30])}",
         f"- jar 에만: {len(diff['only_b'])} — {', '.join(diff['only_b'][:30])}",
         "- 버전 차이:", *(f"  - {k}: BOM {a} / jar {b}" for k, (a, b) in diff["version_differs"].items()),
         "", "## 정답지 설치버전 대조", "| 패키지 | 보안팀 | BOM | jar |", "|---|---|---|---|"]
    jar_by = {r["package"]: r for r in cmp_jar}
    for r in cmp_bom:
        j = jar_by.get(r["package"], {})
        L.append(f"| {r['package']} | {r['manifest']} | {r['inventory'] or '-'} | {j.get('inventory') or '-'} |")
    L += ["", "## jar 표면의 취약점 부착 버전(정답지 패키지만)", "| advisory | 패키지 | InstalledVersion |", "|---|---|---|"]
    L += [f"| {vid} | {pkg} | {ver} |" for vid, pkg, ver in vulns_for_gt]
    return "\n".join(L)


def build_and_scan_jar(repo_dir: Path, out_json: Path, *, run=subprocess.run) -> bool:
    """./gradlew bootJar → trivy rootfs build/libs (fat jar 의 BOOT-INF/lib 중첩 jar 포함). 실패 시 False (부분 실패 정상)."""
    r = run(["./gradlew", "bootJar", "-x", "test", "--no-daemon", "-q"], cwd=str(repo_dir),
            capture_output=True, text=True, timeout=1800)
    if r.returncode != 0:
        out_json.with_suffix(".build-error.txt").write_text((r.stderr or "")[-4000:], encoding="utf-8")
        return False
    r = run(["trivy", "rootfs", "--scanners", "vuln", "--list-all-pkgs", "--format", "json", "--quiet",
             str(repo_dir / "build" / "libs")], capture_output=True, text=True, timeout=900)
    out_json.write_text(r.stdout or "{}", encoding="utf-8")
    return r.returncode == 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="tools.verify.jar_surface")
    p.add_argument("--repo-dir", required=True)
    p.add_argument("--bom", required=True)
    p.add_argument("--gt", required=True)
    p.add_argument("--out", required=True)
    a = p.parse_args(argv)
    out = Path(a.out)
    jar_json = out.with_suffix(".trivy-fs.json")
    ok = build_and_scan_jar(Path(a.repo_dir), jar_json)
    if not jar_json.exists():
        jar_json.write_text("{}", encoding="utf-8")  # reconcile 재생성용 — 실패도 파일로 남긴다
    jar_text = jar_json.read_text(encoding="utf-8")
    out.with_name("input-surface.status.json").write_text(json.dumps({"jar_build_scan_ok": ok}) + "\n", encoding="utf-8")
    bom_text = Path(a.bom).read_text(encoding="utf-8")
    manifest = load_gt_manifest(a.gt)
    out.write_text(render_doc(ok, bom_text, jar_text, manifest), encoding="utf-8")
    out.with_name("facts-surface.json").write_text(facts_text(collect_facts(ok, bom_text, jar_text, manifest)), encoding="utf-8")
    print(out)
    return 0


def render_doc(ok: bool, bom_json: str, jar_json: str, manifest: GtManifest) -> str:
    """입력면 교차 문서 전체(생성기 — reconcile 이 같은 입력으로 재생성해 비교한다)."""
    inv_bom = inventory_from_bom(bom_json)
    inv_jar = inventory_from_trivy(jar_json or "{}")
    gt_packages = {e.package for e in manifest.entries}
    vulns_for_gt = [row for row in vuln_installed_versions(jar_json or "{}") if row[1] in gt_packages]
    return f"# 입력면 교차 — jar 빌드/스캔 {'성공' if ok else '실패(부분)'}\n\n" + render(
        diff_inventories(inv_bom, inv_jar), compare_installed(inv_bom, manifest), compare_installed(inv_jar, manifest),
        vulns_for_gt)


if __name__ == "__main__":
    raise SystemExit(main())
