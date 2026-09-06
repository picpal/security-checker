"""증거 동결 — raw 출력(비밀값 제거)·findings.json·SARIF·md·trace·meta 를 한 디렉토리에(spec §4.4)."""

from __future__ import annotations

import json
import subprocess
from dataclasses import asdict, replace
from pathlib import Path
from typing import TYPE_CHECKING

from secscan.output.json_io import to_json
from secscan.output.markdown import to_markdown
from secscan.output.sarif import to_sarif
from secscan.output.xlsx import write_workbook
from secscan.sbom import bom_cache_path

if TYPE_CHECKING:
    from secscan.models import Finding
    from secscan.scan import ScanResult, TraceSink

_VERSION_CMDS = {
    "trivy": ["trivy", "--version"],
    "cdxgen": ["cdxgen", "--version"],
    "semgrep": ["semgrep", "--version"],
    "gitleaks": ["gitleaks", "version"],
    "depscan": ["depscan", "--version"],
    "spotbugs": ["spotbugs", "-version"],
    "java": ["java", "-version"],
    "gradle": ["gradle", "--version"],
}


def redact_gitleaks(payload: str) -> str:
    try:
        data = json.loads(payload or "[]")
    except json.JSONDecodeError:
        return "[]"
    for x in data or []:
        for k in ("Secret", "Match"):
            if k in x:
                x[k] = "<redacted>"
    return json.dumps(data, indent=2, ensure_ascii=False)


def tool_versions(*, run=subprocess.run) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, argv in _VERSION_CMDS.items():
        try:
            r = run(argv, capture_output=True, text=True, timeout=30)
            text = (r.stdout or "") + (r.stderr or "")
            out[name] = " ".join(text.split())[:200] or f"exit {r.returncode}"
        except Exception as e:  # 미설치 등
            out[name] = f"unavailable: {type(e).__name__}"
    return out


def _rel(p: str, repo_root: Path) -> str:
    """`p` 가 `repo_root` 아래 절대경로면 그 루트 기준 상대경로로, 아니면 그대로(M8)."""
    if not p:
        return p
    pp = Path(p)
    if pp.is_absolute():
        try:
            return pp.relative_to(repo_root).as_posix()
        except ValueError:
            return p
    return p


def _relativize(findings: list[Finding], repo_root: Path) -> list[Finding]:
    out = []
    for f in findings:
        loc = replace(f.location, file=_rel(f.location.file, repo_root)) if f.location else f.location
        out.append(replace(f, location=loc, source=_rel(f.source, repo_root)))
    return out


def write_evidence(out_dir, *, result: ScanResult, trace: TraceSink | None, meta: dict, xlsx: bool = False,
                   repo_root: Path | None = None, target=None) -> list[Path]:
    out = Path(out_dir)
    (out / "raw").mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    findings = _relativize(result.findings, Path(repo_root)) if repo_root is not None else result.findings
    # I3(최종 리뷰) — bom-sca 가 실제로 먹인 cdxgen BOM 은 secscan.sbom.ensure_bom 의 경로해시 캐시
    # 에만 있었고, 지금까지는 사람이 손으로 raw/bom.cdx.json 으로 복사했다(known_fp·jar_surface 가
    # 정본 축 3·5 로 그 파일을 읽는다). target 이 주어지면 여기서 그 복사를 대신한다.
    if target is not None:
        cache = bom_cache_path(target)
        if cache.exists():
            p = out / "raw" / "bom.cdx.json"
            p.write_bytes(cache.read_bytes()); written.append(p)
    # I2(최종 리뷰) — 정본 직렬화는 asdict(ScannerStatus) 하나(tool/status/tool_version/duration_s/
    # message 5키). scanner_status 가 비어 있으면(트레이스 없이 만든 합성 ScanResult 등) raw_results
    # 에서 같은 5키로 재구성한다 — "error" 전용 키는 어디에도 쓰지 않는다.
    scanner_status_rows = [asdict(s) for s in result.scanner_status] or [
        {"tool": r.tool, "status": r.status, "tool_version": r.version, "duration_s": r.duration_s, "message": r.error}
        for r in result.raw_results
    ]
    for r in result.raw_results:
        if not r.payload:
            continue
        ext = "sarif" if r.format == "sarif" else "json"
        p = out / "raw" / f"{r.tool}.{ext}"
        text = redact_gitleaks(r.payload) if r.tool == "gitleaks" else r.payload
        p.write_text(text, encoding="utf-8"); written.append(p)
    p = out / "findings.json"
    p.write_text(to_json(findings, meta=meta), encoding="utf-8"); written.append(p)
    p = out / "findings.sarif"
    p.write_text(json.dumps(to_sarif(findings), indent=2, ensure_ascii=False), encoding="utf-8")
    written.append(p)
    p = out / "report.md"
    p.write_text(to_markdown(findings, target=meta.get("snapshot"),
                             meta={"scanner_status": scanner_status_rows}), encoding="utf-8")
    written.append(p)
    p = out / "trace.json"
    p.write_text(json.dumps(trace.to_dict() if trace else {}, indent=2, ensure_ascii=False), encoding="utf-8")
    written.append(p)
    full_meta = dict(meta)
    full_meta["scanner_status"] = scanner_status_rows
    full_meta["reachability"] = {"ran": result.reachability_ran, "reason": result.reachability_reason}
    full_meta["secret_policy"] = result.secret_policy
    full_meta["excluded_count"] = result.excluded_count
    if xlsx:
        wb_paths, wb_warn = write_workbook(findings, {
            **meta, "scanner_status": full_meta["scanner_status"], "reachability": full_meta["reachability"],
            "secret_policy": full_meta["secret_policy"], "run_date": meta.get("run_date", ""),
        }, out)
        written += wb_paths
        if wb_warn:
            full_meta["xlsx_warning"] = wb_warn
    p = out / "meta.json"
    p.write_text(json.dumps(full_meta, indent=2, ensure_ascii=False), encoding="utf-8"); written.append(p)
    return written
