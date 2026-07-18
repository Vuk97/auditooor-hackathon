#!/usr/bin/env python3
"""aderyn-orchestrator.py - Run Aderyn on a Solidity workspace and emit normalized JSON.

Gap-4 fix: wire Aderyn (fast Rust-based Solidity static analyzer) into the
audit-deep-solidity pipeline. Aderyn is complementary to Slither - it runs
independently without needing the Solidity compiler installed, and covers
a different pattern corpus.

Output schema: auditooor.aderyn_results.v1
Output path: <workspace>/.auditooor/aderyn_results.json

Usage:
    python3 tools/aderyn-orchestrator.py --workspace <ws> [--src <dir>]
    python3 tools/aderyn-orchestrator.py --workspace <ws> --json

Exit codes:
    0 - Aderyn ran and output written (findings may be 0)
    1 - Aderyn not installed (graceful skip)
    2 - Runtime error
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


SCHEMA = "auditooor.aderyn_results.v1"


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _find_src_root(ws: Path) -> Path | None:
    """Find the best Solidity source root for Aderyn."""
    # Prefer foundry-based src/ layout
    for candidate in [ws / "src", ws]:
        if (candidate).is_dir() and any(candidate.glob("**/*.sol")):
            return candidate
    return None


def _run_aderyn(ws: Path, src_root: Path, out_json: Path, timeout: int = 180) -> dict:
    """Run aderyn and parse results. Returns normalized payload."""
    # Aderyn wants to run from within the project root (foundry.toml dir)
    foundry_root = ws
    if (ws / "foundry.toml").exists():
        foundry_root = ws
    else:
        # Walk up to find foundry.toml
        for p in [ws / sub for sub in ["src", ".", ".."]] + list(ws.rglob("foundry.toml")):
            if isinstance(p, Path) and p.name == "foundry.toml" and p.exists():
                foundry_root = p.parent
                break

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        tmp_out = Path(tf.name)

    try:
        cmd = [
            "aderyn",
            "--output", str(tmp_out),
            "--format", "json",
            str(src_root),
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(foundry_root),
        )
        raw_stdout = result.stdout[-8000:] if result.stdout else ""
        raw_stderr = result.stderr[-4000:] if result.stderr else ""

        findings = []
        raw_aderyn = {}
        if tmp_out.exists() and tmp_out.stat().st_size > 0:
            try:
                raw_aderyn = json.loads(tmp_out.read_text(encoding="utf-8"))
            except Exception as e:
                raw_aderyn = {"parse_error": str(e)}

        # Normalize aderyn's JSON output format
        # Aderyn v0.1.x emits: {"high_issues": [...], "low_issues": [...]}
        # Each issue: {"title": ..., "description": ..., "instances": [{...}], "severity": ...}
        for severity_key in ["critical_issues", "high_issues", "medium_issues", "low_issues", "nc_issues"]:
            sev_map = {
                "critical_issues": "Critical",
                "high_issues": "High",
                "medium_issues": "Medium",
                "low_issues": "Low",
                "nc_issues": "Informational",
            }
            sev = sev_map.get(severity_key, "Unknown")
            for issue in raw_aderyn.get(severity_key, []):
                title = issue.get("title", "Unknown")
                description = issue.get("description", "")
                for inst in issue.get("instances", []):
                    findings.append({
                        "detector": f"aderyn/{title.lower().replace(' ', '_')}",
                        "severity": sev,
                        "file": inst.get("contract_path") or inst.get("src_path") or inst.get("file") or "unknown",
                        "line": inst.get("line") or inst.get("start_line") or 0,
                        "message": f"{title}: {description[:200]}",
                        "function": inst.get("function") or inst.get("contract") or None,
                        "raw": inst,
                    })

        payload = {
            "schema": SCHEMA,
            "generated_at": _ts(),
            "workspace": str(ws),
            "src_root": str(src_root),
            "aderyn_returncode": result.returncode,
            "aderyn_version": _get_aderyn_version(),
            "files_scanned": raw_aderyn.get("files_summary", {}).get("total_source_units", 0)
                             if isinstance(raw_aderyn, dict) else 0,
            "findings_count": len(findings),
            "findings": findings,
            "per_severity_counts": {
                sev: sum(1 for f in findings if f["severity"] == sev)
                for sev in ["Critical", "High", "Medium", "Low", "Informational"]
            },
            "raw_stdout_tail": raw_stdout,
            "raw_stderr_tail": raw_stderr,
            "status": "ok" if result.returncode == 0 else f"aderyn_rc_{result.returncode}",
        }
        return payload

    finally:
        tmp_out.unlink(missing_ok=True)


def _get_aderyn_version() -> str:
    try:
        r = subprocess.run(["aderyn", "--version"], capture_output=True, text=True, timeout=10)
        return (r.stdout + r.stderr).strip().split("\n")[0]
    except Exception:
        return "unknown"


def main() -> int:
    parser = argparse.ArgumentParser(description="Aderyn orchestrator for audit-deep-solidity")
    parser.add_argument("--workspace", required=True, help="Workspace root")
    parser.add_argument("--src", default=None, help="Solidity source dir (auto-detected if omitted)")
    parser.add_argument("--output", default=None, help="Override output path")
    parser.add_argument("--timeout", type=int, default=180, help="Aderyn timeout in seconds")
    parser.add_argument("--json", action="store_true", dest="json_only", help="Print JSON to stdout")
    args = parser.parse_args()

    ws = Path(args.workspace).resolve()
    if not ws.is_dir():
        print(f"[aderyn-orchestrator] ERROR: workspace not found: {ws}", file=sys.stderr)
        return 2

    # Check aderyn is available
    aderyn_bin = None
    for candidate in ["aderyn", os.path.expanduser("~/.cargo/bin/aderyn")]:
        try:
            subprocess.run([candidate, "--version"], capture_output=True, timeout=5)
            aderyn_bin = candidate
            break
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    out_path = Path(args.output) if args.output else ws / ".auditooor" / "aderyn_results.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if aderyn_bin is None:
        skip_payload = {
            "schema": SCHEMA,
            "generated_at": _ts(),
            "workspace": str(ws),
            "status": "skipped_not_installed",
            "findings_count": 0,
            "findings": [],
            "per_severity_counts": {},
        }
        out_path.write_text(json.dumps(skip_payload, indent=2) + "\n", encoding="utf-8")
        print("[aderyn-orchestrator] aderyn not found on PATH - skipped (install: cargo install aderyn)")
        if args.json_only:
            print(json.dumps(skip_payload, indent=2))
        return 1  # graceful skip (not failure)

    src_root = Path(args.src).resolve() if args.src else _find_src_root(ws)
    if src_root is None:
        skip_payload = {
            "schema": SCHEMA,
            "generated_at": _ts(),
            "workspace": str(ws),
            "status": "skipped_no_sol_src",
            "findings_count": 0,
            "findings": [],
            "per_severity_counts": {},
        }
        out_path.write_text(json.dumps(skip_payload, indent=2) + "\n", encoding="utf-8")
        print("[aderyn-orchestrator] no Solidity source found - skipped")
        if args.json_only:
            print(json.dumps(skip_payload, indent=2))
        return 0

    print(f"[aderyn-orchestrator] running aderyn on {src_root} (timeout={args.timeout}s)")
    try:
        payload = _run_aderyn(ws, src_root, out_path, timeout=args.timeout)
    except subprocess.TimeoutExpired:
        payload = {
            "schema": SCHEMA,
            "generated_at": _ts(),
            "workspace": str(ws),
            "status": "timeout",
            "findings_count": 0,
            "findings": [],
            "per_severity_counts": {},
        }
    except Exception as e:
        payload = {
            "schema": SCHEMA,
            "generated_at": _ts(),
            "workspace": str(ws),
            "status": f"error: {e}",
            "findings_count": 0,
            "findings": [],
            "per_severity_counts": {},
        }

    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    count = payload.get("findings_count", 0)
    status = payload.get("status", "?")
    print(f"[aderyn-orchestrator] status={status} findings={count} -> {out_path}")

    if args.json_only:
        print(json.dumps(payload, indent=2))

    return 0


if __name__ == "__main__":
    sys.exit(main())
