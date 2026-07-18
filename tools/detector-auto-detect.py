#!/usr/bin/env python3
"""detector-auto-detect.py — one-command detector runner.

Sniffs the target directory, decides whether it's Rust (Soroban/tree-sitter)
or Solidity (Slither wave17/wave14), and runs the appropriate detector set.
Produces unified JSON output.

Part of Phase 4 of the consolidation megaplan (PR #84).

Usage:
    detector-auto-detect.py <path>
    detector-auto-detect.py <path> --wave rust_wave1   # force
    detector-auto-detect.py <path> --json               # JSON only, no stdout
    detector-auto-detect.py <path> --detector <name>   # rust fixture rerun
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def detect_language(target: Path) -> str:
    """Return 'rust' or 'sol' or 'unknown'."""
    if target.is_file():
        if target.suffix == ".rs":
            return "rust"
        if target.suffix == ".sol":
            return "sol"
        return "unknown"

    # Directory — look for marker files
    markers_rust = ["Cargo.toml", "Cargo.lock"]
    markers_sol = ["foundry.toml", "hardhat.config.js", "hardhat.config.ts",
                   "remappings.txt", "package.json"]

    # Check direct children + one level down
    hits_rust = 0
    hits_sol = 0
    for marker in markers_rust:
        if (target / marker).exists():
            hits_rust += 2
    for marker in markers_sol:
        if (target / marker).exists():
            hits_sol += 2

    # Scan file extensions (capped to avoid walking huge trees)
    rs_count = 0
    sol_count = 0
    for i, p in enumerate(target.rglob("*")):
        if i > 500:
            break
        if p.is_file():
            if p.suffix == ".rs":
                rs_count += 1
            elif p.suffix == ".sol":
                sol_count += 1
    hits_rust += rs_count
    hits_sol += sol_count

    if hits_rust > hits_sol:
        return "rust"
    if hits_sol > hits_rust:
        return "sol"
    return "unknown"


def run_rust_fixtures(target: Path, detector: str | None = None) -> dict:
    """For Rust, run the fixture suite against the target's .rs files.
    Note: the canonical Rust fixture suite runs against
    detectors/rust_wave1/test_fixtures/. To run the detectors against
    ARBITRARY .rs files, use `detectors/rust_wave1/run_detectors.py`
    if available, else fall back to pointing at the fixtures dir.
    """
    harness = REPO / "detectors" / "rust_wave1" / "test_fixtures" / "test_detectors.sh"
    if not harness.exists():
        return {"error": f"fixture harness not found: {harness}"}

    # For now, run the fixture suite and return the pass/fail counts.
    # (Extending this to scan arbitrary targets is a follow-up.)
    cmd = ["bash", str(harness)]
    if detector:
        cmd.append(f"--detector={detector}")
    try:
        out = subprocess.check_output(
            cmd,
            cwd=REPO,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        out = e.output or ""

    summary_line = ""
    for line in out.splitlines():
        if "regression:" in line:
            summary_line = line.strip()
            break

    return {
        "wave": "rust_wave1",
        "summary": summary_line,
        "detector": detector,
        "target_hint": f"scanned canonical fixtures; arbitrary-target scan is TODO",
        "fixture_output_tail": "\n".join(out.splitlines()[-5:]),
    }


def run_sol_detectors(target: Path) -> dict:
    """For Solidity, delegate to run-slither.sh if present."""
    script = REPO / "tools" / "run-slither.sh"
    if not script.exists():
        return {"error": f"slither runner not found: {script}"}
    return {
        "wave": "wave17",
        "hint": f"would run: bash {script} {target} (not executed in this stub)",
        "note": "Solidity detector run against an arbitrary target requires a "
                "working solc + slither environment; stub only dispatches.",
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Auto-detect language + run detectors.")
    ap.add_argument("target", help="Path to a .rs / .sol file or a project dir")
    ap.add_argument("--wave", default=None,
                    help="Force detector wave: rust_wave1 / wave17 / wave14")
    ap.add_argument("--detector", default=None,
                    help="For rust fixture reruns, run only this detector stem")
    ap.add_argument("--json", action="store_true",
                    help="Emit JSON only, no human summary")
    args = ap.parse_args()

    target = Path(args.target).resolve()
    if not target.exists():
        print(f"[err] target does not exist: {target}", file=sys.stderr)
        return 2

    if args.wave:
        lang = "rust" if "rust" in args.wave else "sol"
    else:
        lang = detect_language(target)

    if not args.json:
        print(f"[detect] target={target}")
        print(f"[detect] language={lang}")

    if lang == "rust":
        result = run_rust_fixtures(target, detector=args.detector)
    elif lang == "sol":
        result = run_sol_detectors(target)
    else:
        result = {"error": f"could not detect language at {target}"}

    payload = {
        "target": str(target),
        "language": lang,
        "wave": result.get("wave", "unknown"),
        "result": result,
    }

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        for key in ("wave", "summary", "hint", "note", "target_hint",
                    "fixture_output_tail", "error"):
            if key in result:
                print(f"  {key}: {result[key]}")

    return 0 if "error" not in result else 1


if __name__ == "__main__":
    sys.exit(main())
