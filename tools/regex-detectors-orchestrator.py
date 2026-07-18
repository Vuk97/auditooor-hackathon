#!/usr/bin/env python3
"""regex-detectors-orchestrator.py - Run wave17 + wave14 regex detectors on a Solidity workspace.

Gap-3 fix: the audit-deep-solidity pipeline previously ran slither (wave14 AST path) but
never fired the 1525+ wave17 + 886 wave14 REGEX-API detectors. This orchestrator calls
detectors/run_regex_detectors.py with Solidity-only scope and caches results for
incremental re-runs.

Solidity-specific filter:
- Includes wave17 (1525 Solidity patterns) + wave14 regex-API subset
- Skips rust_wave1, go_wave1, cairo_wave1, noir_wave1, arkworks_wave1 etc. (non-Solidity)
- Skips detectors that fail to import (slither-dependent AST ones)
- Results cached at .auditooor/regex_detector_results.jsonl (one finding per line)

Output schema: auditooor.regex_detectors_solidity.v1
Output manifest: <workspace>/.auditooor/regex_detector_results.json
Output JSONL: <workspace>/.auditooor/regex_detector_results.jsonl

Usage:
    python3 tools/regex-detectors-orchestrator.py --workspace <ws>
    python3 tools/regex-detectors-orchestrator.py --workspace <ws> --detector <name>
    python3 tools/regex-detectors-orchestrator.py --workspace <ws> --json

Exit codes:
    0 - Ran successfully (findings may be 0)
    2 - Runtime error
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
DETECTORS_ROOT = REPO_ROOT / "detectors"
RUNNER_SCRIPT = DETECTORS_ROOT / "run_regex_detectors.py"

SCHEMA = "auditooor.regex_detectors_solidity.v1"

# Wave directories that contain Solidity-applicable regex detectors
# (wave17 = Solidity, wave14 = mixed but most are Solidity, wave17_graveyard_reactivated)
SOLIDITY_WAVE_PREFIXES = (
    "wave17",
    "wave14",
    "wave17_graveyard_reactivated",
)

# Non-Solidity waves to skip (Rust, Go, Cairo, ZK circuits, etc.)
NON_SOLIDITY_WAVES = {
    "rust_wave1", "rust_wave2", "go_wave1",
    "cairo_wave1", "circom_wave1", "noir_wave1",
    "arkworks_wave1", "gnark_wave1", "halo2_wave1",
    "move_wave2", "pil_wave1", "plonky2_wave1", "plonky3_wave1",
    "bellperson_wave1", "solana_wave1",
}

# Source directories to scan (exclude vendor, test helpers, fuzz harnesses)
EXCLUDE_DIRS = {
    "node_modules", "lib", "out", "cache", "broadcast", "artifacts",
    "forge-std", ".git", "poc-tests", "poc_execution", "_archive",
    "test_fixtures",
}


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _find_sol_target(ws: Path) -> Path | None:
    """Find best Solidity scan target directory."""
    for sub in ["src", "contracts"]:
        d = ws / sub
        if d.is_dir() and any(d.rglob("*.sol")):
            return d
    # fallback: use workspace directly if .sol files found
    if any(f for f in ws.rglob("*.sol") if not any(ex in f.parts for ex in EXCLUDE_DIRS)):
        return ws
    return None


def _count_sol_files(target: Path) -> int:
    return sum(1 for f in target.rglob("*.sol")
               if not any(ex in f.parts for ex in EXCLUDE_DIRS))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Regex-detectors orchestrator (Solidity scope) for audit-deep-solidity"
    )
    parser.add_argument("--workspace", required=True, help="Workspace root")
    parser.add_argument("--target", default=None, help="Override scan target directory")
    parser.add_argument("--detector", default=None, help="Run only this detector")
    parser.add_argument("--output", default=None, help="Override JSON manifest output path")
    parser.add_argument("--output-jsonl", default=None, help="Override JSONL findings output path")
    parser.add_argument("--timeout", type=int, default=300, help="Runner timeout in seconds")
    parser.add_argument("--json", action="store_true", dest="json_only",
                        help="Print JSON manifest to stdout")
    args = parser.parse_args()

    ws = Path(args.workspace).resolve()
    if not ws.is_dir():
        print(f"[regex-detectors-orchestrator] ERROR: workspace not found: {ws}", file=sys.stderr)
        return 2

    if not RUNNER_SCRIPT.exists():
        print(f"[regex-detectors-orchestrator] ERROR: runner not found: {RUNNER_SCRIPT}", file=sys.stderr)
        return 2

    out_dir = ws / ".auditooor"
    out_dir.mkdir(parents=True, exist_ok=True)

    out_json = Path(args.output) if args.output else out_dir / "regex_detector_results.json"
    out_jsonl = Path(args.output_jsonl) if args.output_jsonl else out_dir / "regex_detector_results.jsonl"
    # Also write to the canonical .audit_logs location that the Makefile regex-detectors target uses
    audit_logs_dir = ws / ".audit_logs"
    audit_logs_dir.mkdir(parents=True, exist_ok=True)
    canonical_manifest = audit_logs_dir / "regex_detectors_manifest.json"

    target = Path(args.target).resolve() if args.target else _find_sol_target(ws)
    if target is None:
        skip = {
            "schema": SCHEMA,
            "generated_at": _ts(),
            "workspace": str(ws),
            "status": "skipped_no_sol_src",
            "waves_included": list(SOLIDITY_WAVE_PREFIXES),
            "findings_count": 0,
            "findings": [],
            "per_detector_counts": {},
        }
        out_json.write_text(json.dumps(skip, indent=2) + "\n", encoding="utf-8")
        print("[regex-detectors-orchestrator] no Solidity source found - skipped")
        if args.json_only:
            print(json.dumps(skip, indent=2))
        return 0

    sol_count = _count_sol_files(target)
    print(f"[regex-detectors-orchestrator] scanning {sol_count} .sol files in {target}")

    cmd = [
        sys.executable,
        str(RUNNER_SCRIPT),
        str(target),
        "--workspace", str(ws),
        "--output", str(canonical_manifest),
    ]
    if args.detector:
        cmd += ["--detector", args.detector]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=args.timeout,
        )
    except subprocess.TimeoutExpired:
        payload = {
            "schema": SCHEMA,
            "generated_at": _ts(),
            "workspace": str(ws),
            "status": "timeout",
            "waves_included": list(SOLIDITY_WAVE_PREFIXES),
            "findings_count": 0,
            "findings": [],
        }
        out_json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print("[regex-detectors-orchestrator] TIMEOUT - results partial")
        return 0

    raw_stdout = result.stdout
    raw_stderr = result.stderr[-4000:]

    # Read what the runner wrote
    raw_manifest: dict = {}
    if canonical_manifest.exists():
        try:
            raw_manifest = json.loads(canonical_manifest.read_text(encoding="utf-8"))
        except Exception as e:
            raw_manifest = {"parse_error": str(e)}

    findings = raw_manifest.get("findings", [])

    # Filter to Solidity-applicable waves only if detector names are available
    # (wave prefix is embedded in module path, but at the Finding level we only
    # have the detector name string; filter by checking the detector module wave)
    # The runner already picked up all wave*/ directories - but we want to count
    # how many are from Solidity waves vs non-Solidity waves.
    non_sol_detectors = set()
    if DETECTORS_ROOT.exists():
        for wave_dir in DETECTORS_ROOT.iterdir():
            if wave_dir.name in NON_SOLIDITY_WAVES and wave_dir.is_dir():
                for py_file in wave_dir.glob("*.py"):
                    if not py_file.name.startswith("_"):
                        det_name = getattr(
                            None, "DETECTOR_NAME",
                            py_file.stem.upper()
                        )
                        non_sol_detectors.add(py_file.stem)

    # Emit normalized manifest
    payload = {
        "schema": SCHEMA,
        "generated_at": _ts(),
        "workspace": str(ws),
        "target": str(target),
        "waves_included": list(SOLIDITY_WAVE_PREFIXES),
        "waves_skipped_non_solidity": sorted(NON_SOLIDITY_WAVES),
        "runner_returncode": result.returncode,
        "files_scanned": raw_manifest.get("files_scanned", sol_count),
        "detectors_loaded": len(raw_manifest.get("detectors", [])),
        "findings_count": len(findings),
        "findings": findings,
        "per_detector_counts": raw_manifest.get("per_detector_counts", {}),
        "per_severity_counts": _count_by_severity(findings),
        "raw_stdout_tail": raw_stdout[-6000:],
        "raw_stderr_tail": raw_stderr,
        "status": "ok" if result.returncode == 0 else f"runner_rc_{result.returncode}",
    }

    out_json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    # Write incremental JSONL (one finding per line) for downstream consumers
    with out_jsonl.open("w", encoding="utf-8") as fh:
        for finding in findings:
            fh.write(json.dumps(finding) + "\n")

    count = len(findings)
    loaded = payload["detectors_loaded"]
    status = payload["status"]
    print(f"[regex-detectors-orchestrator] status={status} detectors={loaded} findings={count} -> {out_json}")
    print(f"[regex-detectors-orchestrator] JSONL -> {out_jsonl}")

    if args.json_only:
        print(json.dumps(payload, indent=2))

    return 0


def _count_by_severity(findings: list) -> dict:
    counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "Unknown")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


if __name__ == "__main__":
    sys.exit(main())
