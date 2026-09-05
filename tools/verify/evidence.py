"""증거 동결 — raw 출력(비밀값 제거)·findings.json·SARIF·md·trace·meta 를 한 디렉토리에(spec §4.4)."""

from __future__ import annotations

import json
import subprocess
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING

from secscan.output.json_io import to_json
from secscan.output.markdown import to_markdown
from secscan.output.sarif import to_sarif
from secscan.output.xlsx import write_workbook

if TYPE_CHECKING:
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


def write_evidence(out_dir, *, result: ScanResult, trace: TraceSink | None, meta: dict, xlsx: bool = False) -> list[Path]:
    out = Path(out_dir)
    (out / "raw").mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for r in result.raw_results:
        if not r.payload:
            continue
        ext = "sarif" if r.format == "sarif" else "json"
        p = out / "raw" / f"{r.tool}.{ext}"
        text = redact_gitleaks(r.payload) if r.tool == "gitleaks" else r.payload
        p.write_text(text, encoding="utf-8"); written.append(p)
    p = out / "findings.json"
    p.write_text(to_json(result.findings, meta=meta), encoding="utf-8"); written.append(p)
    p = out / "findings.sarif"
    p.write_text(json.dumps(to_sarif(result.findings), indent=2, ensure_ascii=False), encoding="utf-8")
    written.append(p)
    p = out / "report.md"
    p.write_text(to_markdown(result.findings, target=meta.get("snapshot"),
                             meta={"scanner_status": [asdict(s) for s in result.scanner_status]}), encoding="utf-8")
    written.append(p)
    p = out / "trace.json"
    p.write_text(json.dumps(trace.to_dict() if trace else {}, indent=2, ensure_ascii=False), encoding="utf-8")
    written.append(p)
    full_meta = dict(meta)
    full_meta["scanner_status"] = [
        {"tool": s.name, "status": s.status, "tool_version": s.tool_version, "duration_s": s.duration_s,
         **({"error": s.message} if s.message else {})}
        for s in result.scanner_status
    ] or [{"tool": r.tool, "status": r.status, **({"error": r.error} if r.error else {})} for r in result.raw_results]
    full_meta["reachability"] = {"ran": result.reachability_ran, "reason": result.reachability_reason}
    full_meta["secret_policy"] = result.secret_policy
    full_meta["excluded_count"] = result.excluded_count
    if xlsx:
        wb_paths, wb_warn = write_workbook(result.findings, {
            **meta, "scanner_status": full_meta["scanner_status"], "reachability": full_meta["reachability"],
            "secret_policy": full_meta["secret_policy"], "run_date": meta.get("run_date", ""),
        }, out)
        written += wb_paths
        if wb_warn:
            full_meta["xlsx_warning"] = wb_warn
    p = out / "meta.json"
    p.write_text(json.dumps(full_meta, indent=2, ensure_ascii=False), encoding="utf-8"); written.append(p)
    return written
