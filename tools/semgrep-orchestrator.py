#!/usr/bin/env python3
"""semgrep-orchestrator.py - Run Semgrep on a Solidity workspace with curated rules.

Gap-4 fix: wire Semgrep (multi-language semantic pattern matcher) into the
audit-deep-solidity pipeline. Uses the public Solidity smart contract
security ruleset as baseline.

Output schema: auditooor.semgrep_results.v1
Output path: <workspace>/.auditooor/semgrep_results.json

Usage:
    python3 tools/semgrep-orchestrator.py --workspace <ws>
    python3 tools/semgrep-orchestrator.py --workspace <ws> --json

Exit codes:
    0 - Semgrep ran and output written
    1 - Semgrep not installed (graceful skip)
    2 - Runtime error
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


SCHEMA = "auditooor.semgrep_results.v1"

# Public Semgrep rule registries for Solidity smart-contract security.
# These are curated to match common Solidity vulnerability patterns.
DEFAULT_RULESETS = [
    "p/solidity",
    "p/smart-contracts",
]

# Auditooor custom rules dir (Phase III - populated later)
CUSTOM_RULES_DIR = Path(__file__).resolve().parent.parent / "detectors" / "semgrep_rules"


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _get_semgrep_version() -> str:
    try:
        r = subprocess.run(["semgrep", "--version"], capture_output=True, text=True, timeout=10)
        return (r.stdout + r.stderr).strip().split("\n")[0]
    except Exception:
        return "unknown"


def _find_sol_files(ws: Path) -> list[Path]:
    """Find in-scope Solidity files (excluding vendor/test dirs)."""
    EXCLUDE = {"node_modules", "lib", "out", "cache", "broadcast", "artifacts",
               "forge-std", ".git", "poc-tests", "poc_execution"}
    result = []
    for f in ws.rglob("*.sol"):
        parts = set(f.parts)
        if parts & EXCLUDE:
            continue
        result.append(f)
    return result


def _run_semgrep(ws: Path, timeout: int = 180) -> dict:
    """Run semgrep and return normalized payload."""
    sol_files = _find_sol_files(ws)
    if not sol_files:
        return {
            "schema": SCHEMA,
            "generated_at": _ts(),
            "workspace": str(ws),
            "status": "skipped_no_sol_src",
            "findings_count": 0,
            "findings": [],
            "per_severity_counts": {},
        }

    # Build config list: start with public rulesets, add custom if dir exists
    configs = list(DEFAULT_RULESETS)
    if CUSTOM_RULES_DIR.is_dir() and any(CUSTOM_RULES_DIR.glob("*.yaml")):
        configs.append(str(CUSTOM_RULES_DIR))

    # Build target list - pass the workspace src dirs
    targets = []
    for sub in ["src", "contracts"]:
        d = ws / sub
        if d.is_dir() and any(d.glob("**/*.sol")):
            targets.append(str(d))
    if not targets:
        targets = [str(ws)]

    cmd = [
        "semgrep",
        "--json",
        "--no-git-ignore",
        "--timeout", str(min(timeout, 120)),  # per-rule timeout
        "--max-target-bytes", "5000000",  # 5MB per file limit
        "--exclude", "node_modules",
        "--exclude", "lib",
        "--exclude", "out",
        "--exclude", "cache",
        "--exclude", ".git",
        "--exclude", "forge-std",
    ]
    for cfg in configs:
        cmd += ["--config", cfg]
    cmd += targets

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 60,  # outer timeout is larger than per-rule
            cwd=str(ws),
            env={**os.environ, "SEMGREP_SEND_METRICS": "off"},
        )
    except subprocess.TimeoutExpired:
        return {
            "schema": SCHEMA,
            "generated_at": _ts(),
            "workspace": str(ws),
            "status": "timeout",
            "findings_count": 0,
            "findings": [],
            "per_severity_counts": {},
            "configs": configs,
        }

    raw_stdout = result.stdout
    raw_stderr = result.stderr[-4000:]

    findings = []
    semgrep_results = {}
    try:
        semgrep_results = json.loads(raw_stdout)
    except json.JSONDecodeError:
        # Semgrep may emit warnings before the JSON; try to find JSON start
        if "{" in raw_stdout:
            try:
                json_start = raw_stdout.index("{")
                semgrep_results = json.loads(raw_stdout[json_start:])
            except Exception:
                pass

    # Normalize semgrep output
    # Semgrep JSON: {"results": [...], "errors": [...]}
    # Each result: {"check_id": ..., "path": ..., "start": {"line": ...}, "end": {...},
    #               "extra": {"message": ..., "severity": ..., "metadata": ...}}
    for item in semgrep_results.get("results", []):
        extra = item.get("extra", {})
        severity_raw = extra.get("severity", "").upper()
        sev_map = {
            "ERROR": "High",
            "WARNING": "Medium",
            "INFO": "Informational",
            "HIGH": "High",
            "MEDIUM": "Medium",
            "LOW": "Low",
        }
        sev = sev_map.get(severity_raw, "Informational")
        findings.append({
            "detector": f"semgrep/{item.get('check_id', 'unknown')}",
            "severity": sev,
            "file": item.get("path", "unknown"),
            "line": item.get("start", {}).get("line", 0),
            "message": extra.get("message", "")[:300],
            "function": None,
            "rule_id": item.get("check_id", ""),
        })

    return {
        "schema": SCHEMA,
        "generated_at": _ts(),
        "workspace": str(ws),
        "semgrep_version": _get_semgrep_version(),
        "configs": configs,
        "targets": targets,
        "files_scanned": len(sol_files),
        "semgrep_returncode": result.returncode,
        "findings_count": len(findings),
        "findings": findings,
        "per_severity_counts": {
            sev: sum(1 for f in findings if f["severity"] == sev)
            for sev in ["High", "Medium", "Low", "Informational"]
        },
        "errors": semgrep_results.get("errors", [])[:10],  # cap error list
        "raw_stderr_tail": raw_stderr,
        "status": "ok" if result.returncode in (0, 1) else f"semgrep_rc_{result.returncode}",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Semgrep orchestrator for audit-deep-solidity")
    parser.add_argument("--workspace", required=True, help="Workspace root")
    parser.add_argument("--timeout", type=int, default=180, help="Timeout in seconds")
    parser.add_argument("--output", default=None, help="Override output path")
    parser.add_argument("--json", action="store_true", dest="json_only", help="Print JSON to stdout")
    args = parser.parse_args()

    ws = Path(args.workspace).resolve()
    if not ws.is_dir():
        print(f"[semgrep-orchestrator] ERROR: workspace not found: {ws}", file=sys.stderr)
        return 2

    out_path = Path(args.output) if args.output else ws / ".auditooor" / "semgrep_results.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Check semgrep is available
    semgrep_available = False
    try:
        subprocess.run(["semgrep", "--version"], capture_output=True, timeout=10)
        semgrep_available = True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    if not semgrep_available:
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
        print("[semgrep-orchestrator] semgrep not found on PATH - skipped (install: pip install semgrep)")
        if args.json_only:
            print(json.dumps(skip_payload, indent=2))
        return 1  # graceful skip

    print(f"[semgrep-orchestrator] running semgrep on {ws} (timeout={args.timeout}s)")
    payload = _run_semgrep(ws, timeout=args.timeout)

    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    count = payload.get("findings_count", 0)
    status = payload.get("status", "?")
    print(f"[semgrep-orchestrator] status={status} findings={count} -> {out_path}")

    if args.json_only:
        print(json.dumps(payload, indent=2))

    return 0


if __name__ == "__main__":
    sys.exit(main())
