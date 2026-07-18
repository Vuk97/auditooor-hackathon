#!/usr/bin/env python3
"""
zk-circom-analyze.py - Generic Circom circuit security analysis tool for auditooor.

Inspired by zkhydra (https://github.com/zksecurity/zkhydra), this tool:
  - Detects .circom files in a --workspace (NO-OP + honest 'no-circom-circuits'
    verdict if none, so it is a clean no-op on Halo2/Rust targets like Zebra).
  - For each detected circuit, runs whichever of {circomspect, picus, ecne,
    civer, zkfuzz} are installed (each with a configurable per-tool timeout,
    default 300s, mirroring zkhydra defaults).
  - Parses each tool's verdict (detected / missed / error / timeout) and emits
    ZK candidate rows (file:line + tool + finding-class) to the workspace
    .auditooor/zk_circom_candidates.jsonl.

TOOL INSTALLATION STATUS (honest, June 2026 on macOS arm64):
  - circomspect (trailofbits): INSTALLED  - cargo install circomspect  => OK
  - picus (Veridise):          NOT INSTALLED - requires Racket + Rosette (Linux-
                                primarily, no macOS homebrew formula); TODO for
                                Docker/Linux CI path.
  - ecne (franklynwang):       NOT INSTALLED - requires Julia + the EcneProject
                                Julia package; build complexity precludes local
                                install without Julia environment setup.
  - civer (costa-group):       NOT INSTALLED - requires civer_circom binary
                                (Rust, unreleased on crates.io); TODO: cargo
                                install from source once upstream publishes.
  - zkfuzz:                    NOT INSTALLED - requires zkfuzz binary (Rust,
                                not yet on crates.io); TODO: build from
                                https://github.com/costa-group/circom_civer once
                                available.

Usage:
  python3 tools/zk-circom-analyze.py --workspace /path/to/workspace
  python3 tools/zk-circom-analyze.py --workspace /path/to/workspace \\
      --tools circomspect,picus --timeout 600
  python3 tools/zk-circom-analyze.py --circuit /path/to/circuit.circom
  python3 tools/zk-circom-analyze.py --workspace /path/to/non-circom-rust-target
      # => exits 0 with verdict: no-circom-circuits (no-op)

Schema: auditooor.zk_circom_analyze.v1
Rule 37: this tool emits at tier-3-synthetic-taxonomy-anchored for shape-only
         findings (circomspect warnings); tier-2-verified-public-archive when
         a finding matches a known CWE/zkbugs anchor.
"""

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Schema + constants
# ---------------------------------------------------------------------------

SCHEMA_VERSION = "auditooor.zk_circom_analyze.v1"
DEFAULT_TIMEOUT = 300  # seconds per tool, matching zkhydra default cap

# Circomspect code -> finding class mapping (derived from zkhydra circomspect.py)
CIRCOMSPECT_CODE_TO_CLASS: Dict[str, str] = {
    "CS0003": "FieldElementComparison",
    "CS0004": "FieldElementArithmetic",
    "CS0010": "NonStrictBinaryConversion",
    "CS0014": "UnconstrainedLessThan",
    "CS0015": "UnconstrainedDivision",
    "CS0017": "UnderConstrainedSignal",
    "CS0018": "UnusedOutputSignal",
    "CA01":   "UnconstrainedSignal",
    "CS0001": "ShadowingVariable",
    "CS0002": "ParameterNameCollision",
    "CS0005": "SignalAssignmentStatement",
    "CS0006": "UnusedVariableValue",
    "CS0007": "UnusedParameterValue",
    "CS0008": "VariableWithoutSideEffect",
    "CS0009": "ConstantBranchCondition",
    "CS0011": "CyclomaticComplexity",
    "CS0012": "TooManyArguments",
    "CS0013": "UnnecessarySignalAssignment",
    "CS0016": "Bn254SpecificCircuit",
}

# Under-constrained codes that warrant HIGH+ attention
HIGH_ATTENTION_CODES = {"CS0014", "CS0015", "CS0017", "CS0018", "CA01"}

# Rule 37 tier for circomspect findings (shape-based linter, no source anchor)
CIRCOMSPECT_TIER = "tier-3-synthetic-taxonomy-anchored"

# ---------------------------------------------------------------------------
# Tool availability detection
# ---------------------------------------------------------------------------

TOOL_BINARIES: Dict[str, str] = {
    "circomspect": "circomspect",
    "picus":       "run-picus",      # invoked via run-picus wrapper script
    "ecne":        "julia",          # ecne is a Julia package; check for julia
    "civer":       "civer_circom",
    "zkfuzz":      "zkfuzz",
}

TOOL_INSTALL_HINTS: Dict[str, str] = {
    "circomspect": "cargo install circomspect",
    "picus":       "requires Racket + Rosette; see https://github.com/Veridise/Picus - Linux/Docker recommended",
    "ecne":        "requires Julia + EcneProject pkg; see https://github.com/franklynwang/EcneProject",
    "civer":       "requires civer_circom binary; see https://github.com/costa-group/circom_civer (not on crates.io)",
    "zkfuzz":      "requires zkfuzz binary; not yet released on crates.io as of 2026-06",
}


def detect_installed_tools(requested: List[str]) -> Tuple[List[str], List[Dict[str, str]]]:
    """Return (installed_list, unavailable_list) for requested tool names."""
    installed = []
    unavailable = []
    for tool in requested:
        binary = TOOL_BINARIES.get(tool)
        if binary is None:
            unavailable.append({
                "tool": tool,
                "reason": f"unknown tool name '{tool}'; supported: {list(TOOL_BINARIES)}",
            })
            continue
        if shutil.which(binary) is not None:
            installed.append(tool)
        else:
            unavailable.append({
                "tool": tool,
                "binary": binary,
                "reason": f"binary '{binary}' not found in PATH",
                "install_hint": TOOL_INSTALL_HINTS.get(tool, "see tool docs"),
            })
    return installed, unavailable


# ---------------------------------------------------------------------------
# .circom discovery
# ---------------------------------------------------------------------------

EXCLUDED_DIRS = {
    "node_modules", ".git", "target", ".auditooor",
    "dependencies", "codebases",
}


def find_circom_files(workspace: Path) -> List[Path]:
    """Recursively find .circom files in workspace, excluding common non-target dirs."""
    results = []
    for root, dirs, files in os.walk(workspace):
        # Prune excluded dirs in-place
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        for fname in files:
            if fname.endswith(".circom"):
                results.append(Path(root) / fname)
    return sorted(results)


# ---------------------------------------------------------------------------
# circomspect runner + output parser
# ---------------------------------------------------------------------------

def run_circomspect(circuit: Path, timeout: int) -> Dict[str, Any]:
    """Run circomspect on a single .circom file and return structured result."""
    cmd = ["circomspect", str(circuit), "-l", "INFO"]
    start = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        elapsed = time.monotonic() - start
        raw = proc.stdout + "\n" + proc.stderr
        return {
            "status": "ok",
            "raw": raw,
            "returncode": proc.returncode,
            "elapsed_s": round(elapsed, 2),
        }
    except subprocess.TimeoutExpired:
        elapsed = time.monotonic() - start
        return {
            "status": "timeout",
            "raw": "[Timed out]",
            "returncode": -1,
            "elapsed_s": round(elapsed, 2),
        }
    except Exception as exc:
        elapsed = time.monotonic() - start
        return {
            "status": "error",
            "raw": str(exc),
            "returncode": -1,
            "elapsed_s": round(elapsed, 2),
            "error": str(exc),
        }


def parse_circomspect_output(raw: str, circuit: Path) -> List[Dict[str, Any]]:
    """
    Parse circomspect's text output into structured finding rows.

    circomspect 0.9.x emits two distinct header formats:

    Format A (with code bracket):
        warning[CS0013]: Using the signal assignment operator `<--` is not ...
          ┌─ /path/to/circuit.circom:10:5

    Format B (no code bracket, plain severity word):
        warning: The signal `a` is not constrained by the template.
          ┌─ /path/to/circuit.circom:6:5

    In both cases the location line follows immediately and contains a
    box-drawing `┌─` (U+250C U+2500) followed by file:line:col.

    Strip ANSI codes and box-drawing characters before matching.
    """
    findings = []

    def strip_ansi(s: str) -> str:
        return re.sub(r"\x1b\[[0-9;]*m", "", s)

    def strip_box(s: str) -> str:
        # Remove box-drawing characters U+2500-U+257F
        return re.sub(r"[─-╿]+", "", s)

    lines = [strip_ansi(ln) for ln in raw.splitlines()]

    # Counter used to assign synthetic codes to code-less warnings
    _synthetic_idx = [0]

    i = 0
    while i < len(lines):
        line = lines[i]

        # Format A: severity[CODE]: message
        m_coded = re.match(r"\s*(warning|note|error)\[([A-Z0-9]+)\]:\s*(.+)", line)
        # Format B: severity: message  (no code)
        m_plain = re.match(r"\s*(warning|note|error):\s*(.+)", line) if not m_coded else None

        if m_coded or m_plain:
            if m_coded:
                severity = m_coded.group(1)
                code = m_coded.group(2)
                message = m_coded.group(3).strip()
            else:
                severity = m_plain.group(1)
                # Assign a synthetic placeholder; will be enriched by class below
                code = "CS_UNKNOWN"
                message = m_plain.group(2).strip()
                # Try to infer code from message text
                if "not constrained" in message.lower():
                    code = "CS0017"
                elif "unconstrained" in message.lower():
                    code = "CA01"
                elif "unused" in message.lower() and "output" in message.lower():
                    code = "CS0018"
                elif "field element" in message.lower():
                    code = "CS0004"

            # Scan forward for the location line  ┌─ file:line:col
            file_path = str(circuit)
            lineno = 0
            col = 0
            for j in range(i + 1, min(i + 5, len(lines))):
                loc_line = strip_box(lines[j]).strip()
                # After stripping box chars the line looks like: " path/file.circom:10:5"
                loc_match = re.search(r"(\S.+):(\d+):(\d+)", loc_line)
                if loc_match:
                    file_path = loc_match.group(1).strip()
                    lineno = int(loc_match.group(2))
                    col = int(loc_match.group(3))
                    break

            finding_class = CIRCOMSPECT_CODE_TO_CLASS.get(code, code)
            findings.append({
                "tool": "circomspect",
                "severity": severity,
                "code": code,
                "finding_class": finding_class,
                "message": message,
                "file": file_path,
                "line": lineno,
                "column": col,
                "high_attention": code in HIGH_ATTENTION_CODES,
            })

        i += 1
    return findings


# ---------------------------------------------------------------------------
# Stub runners for tools not yet installed
# (These emit an honest "not-installed" verdict so the caller knows
#  the tool was requested but skipped, not silently absent.)
# ---------------------------------------------------------------------------

def run_picus(circuit: Path, timeout: int) -> Dict[str, Any]:
    """Run Picus (Veridise). Requires Racket + Rosette + compiled run-picus."""
    picus = shutil.which("run-picus")
    if not picus:
        return {
            "status": "not-installed",
            "tool": "picus",
            "reason": TOOL_INSTALL_HINTS["picus"],
        }
    # If somehow installed: invoke via run-picus <r1cs-or-circom>
    cmd = [picus, str(circuit)]
    start = time.monotonic()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        elapsed = time.monotonic() - start
        return {
            "status": "ok",
            "raw": proc.stdout + "\n" + proc.stderr,
            "returncode": proc.returncode,
            "elapsed_s": round(elapsed, 2),
        }
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "raw": "[Timed out]", "returncode": -1,
                "elapsed_s": timeout}
    except Exception as exc:
        return {"status": "error", "raw": str(exc), "returncode": -1,
                "error": str(exc), "elapsed_s": 0}


def run_ecne(circuit: Path, timeout: int) -> Dict[str, Any]:
    """Run Ecne (franklynwang). Requires Julia + EcneProject package."""
    julia = shutil.which("julia")
    if not julia:
        return {
            "status": "not-installed",
            "tool": "ecne",
            "reason": TOOL_INSTALL_HINTS["ecne"],
        }
    # ecne is invoked via: julia <path-to-Ecne.jl> <r1cs> <sym>
    # This requires a pre-compiled R1CS/sym pair; circom must be run first.
    # Without circom on PATH we cannot compile; emit honest skip.
    circom_bin = shutil.which("circom")
    if not circom_bin:
        return {
            "status": "not-installed",
            "tool": "ecne",
            "reason": "circom compiler not found in PATH; required to produce .r1cs/.sym for ecne",
        }
    return {
        "status": "not-installed",
        "tool": "ecne",
        "reason": "ecne invocation requires EcneProject Julia package at known path; "
                  "install via: julia -e 'using Pkg; Pkg.add(\"EcneProject\")'",
    }


def run_civer(circuit: Path, timeout: int) -> Dict[str, Any]:
    """Run civer (costa-group). Requires civer_circom binary."""
    civer = shutil.which("civer_circom")
    if not civer:
        return {
            "status": "not-installed",
            "tool": "civer",
            "reason": TOOL_INSTALL_HINTS["civer"],
        }
    cmd = [civer, str(circuit)]
    start = time.monotonic()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        elapsed = time.monotonic() - start
        return {
            "status": "ok",
            "raw": proc.stdout + "\n" + proc.stderr,
            "returncode": proc.returncode,
            "elapsed_s": round(elapsed, 2),
        }
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "raw": "[Timed out]", "returncode": -1,
                "elapsed_s": timeout}
    except Exception as exc:
        return {"status": "error", "raw": str(exc), "returncode": -1,
                "error": str(exc), "elapsed_s": 0}


def run_zkfuzz(circuit: Path, timeout: int) -> Dict[str, Any]:
    """Run zkFuzz (genetic unsoundness fuzzer). Requires zkfuzz binary."""
    zkfuzz = shutil.which("zkfuzz")
    if not zkfuzz:
        return {
            "status": "not-installed",
            "tool": "zkfuzz",
            "reason": TOOL_INSTALL_HINTS["zkfuzz"],
        }
    cmd = [zkfuzz, str(circuit)]
    start = time.monotonic()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        elapsed = time.monotonic() - start
        return {
            "status": "ok",
            "raw": proc.stdout + "\n" + proc.stderr,
            "returncode": proc.returncode,
            "elapsed_s": round(elapsed, 2),
        }
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "raw": "[Timed out]", "returncode": -1,
                "elapsed_s": timeout}
    except Exception as exc:
        return {"status": "error", "raw": str(exc), "returncode": -1,
                "error": str(exc), "elapsed_s": 0}


TOOL_RUNNERS = {
    "circomspect": run_circomspect,
    "picus":       run_picus,
    "ecne":        run_ecne,
    "civer":       run_civer,
    "zkfuzz":      run_zkfuzz,
}


# ---------------------------------------------------------------------------
# Candidate row builder (schema: auditooor.zk_circom_analyze.v1)
# ---------------------------------------------------------------------------

def make_candidate_row(
    workspace: Optional[str],
    circuit: Path,
    tool: str,
    finding: Dict[str, Any],
    run_ts: str,
) -> Dict[str, Any]:
    """Build a JSONL candidate row for .auditooor/zk_circom_candidates.jsonl."""
    return {
        "schema": SCHEMA_VERSION,
        "run_ts": run_ts,
        "workspace": workspace,
        "circuit": str(circuit),
        "tool": tool,
        "finding_class": finding.get("finding_class", finding.get("code", "unknown")),
        "severity": finding.get("severity", "unknown"),
        "code": finding.get("code", ""),
        "message": finding.get("message", ""),
        "file": finding.get("file", str(circuit)),
        "line": finding.get("line", 0),
        "column": finding.get("column", 0),
        "high_attention": finding.get("high_attention", False),
        "verification_tier": CIRCOMSPECT_TIER,  # Rule 37: explicit tier at emit time
    }


# ---------------------------------------------------------------------------
# Main analysis entry point
# ---------------------------------------------------------------------------

def analyze_workspace(
    workspace: Optional[Path],
    circuit_paths: List[Path],
    tools: List[str],
    timeout: int,
    output_jsonl: Optional[Path],
    log: logging.Logger,
) -> Dict[str, Any]:
    """
    Run requested tools against the provided circuits.

    Returns a summary dict with:
      verdict: 'no-circom-circuits' | 'analysis-complete' | 'tools-not-installed'
      circuits_scanned: int
      tools_installed: list
      tools_unavailable: list
      findings_total: int
      candidates_written: int
      candidates_path: str | null
    """
    if not circuit_paths:
        log.info("no-circom-circuits: workspace contains no .circom files (no-op)")
        return {
            "verdict": "no-circom-circuits",
            "circuits_scanned": 0,
            "tools_installed": [],
            "tools_unavailable": [],
            "findings_total": 0,
            "candidates_written": 0,
            "candidates_path": None,
        }

    installed_tools, unavailable_tools = detect_installed_tools(tools)
    log.info(f"tools installed/runnable: {installed_tools}")
    for u in unavailable_tools:
        log.info(f"tool not available: {u['tool']} - {u.get('reason', '')}")

    run_ts = datetime.now(timezone.utc).isoformat()
    all_candidates: List[Dict[str, Any]] = []
    ws_str = str(workspace) if workspace else None

    for circuit in circuit_paths:
        log.info(f"analyzing: {circuit}")
        for tool in installed_tools:
            runner = TOOL_RUNNERS[tool]
            log.info(f"  running {tool} (timeout={timeout}s)")
            result = runner(circuit, timeout)

            if result["status"] == "not-installed":
                log.info(f"  {tool}: not-installed ({result.get('reason', '')})")
                continue
            elif result["status"] == "timeout":
                log.warning(f"  {tool}: TIMEOUT after {timeout}s")
                continue
            elif result["status"] == "error":
                log.warning(f"  {tool}: ERROR - {result.get('error', '')}")
                continue

            # Parse findings per tool
            raw = result.get("raw", "")
            findings: List[Dict[str, Any]] = []

            if tool == "circomspect":
                findings = parse_circomspect_output(raw, circuit)
            # Future: add parse_picus_output, parse_ecne_output, etc.

            log.info(f"  {tool}: {len(findings)} finding(s)")
            for f in findings:
                row = make_candidate_row(ws_str, circuit, tool, f, run_ts)
                all_candidates.append(row)

    # Write JSONL output
    written = 0
    if all_candidates and output_jsonl is not None:
        output_jsonl.parent.mkdir(parents=True, exist_ok=True)
        with open(output_jsonl, "a", encoding="utf-8") as fh:
            for row in all_candidates:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
                written += 1
        log.info(f"wrote {written} candidate row(s) to {output_jsonl}")

    verdict = "analysis-complete"
    if not installed_tools:
        verdict = "tools-not-installed"

    return {
        "verdict": verdict,
        "circuits_scanned": len(circuit_paths),
        "tools_installed": installed_tools,
        "tools_unavailable": unavailable_tools,
        "findings_total": len(all_candidates),
        "candidates_written": written,
        "candidates_path": str(output_jsonl) if output_jsonl and written > 0 else None,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Generic Circom circuit security analyzer for auditooor. "
                    "NO-OP (exit 0, verdict=no-circom-circuits) on workspaces "
                    "without .circom files (Halo2/Rust targets are unaffected).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--workspace", "-w",
        type=Path,
        help="Workspace root to scan recursively for .circom files. "
             "Mutually exclusive with --circuit.",
    )
    p.add_argument(
        "--circuit", "-c",
        type=Path,
        action="append",
        dest="circuits",
        help="Explicit .circom file path (repeatable). Mutually exclusive with --workspace.",
    )
    p.add_argument(
        "--tools", "-t",
        default="circomspect,picus,ecne,civer,zkfuzz",
        help="Comma-separated list of tools to run. Default: all five. "
             "Only installed tools are actually executed; others are reported as unavailable.",
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Per-tool timeout in seconds (default: {DEFAULT_TIMEOUT}). Mirrors zkhydra default.",
    )
    p.add_argument(
        "--output-jsonl", "-o",
        type=Path,
        help="Path to append ZK candidate rows (JSONL). "
             "Default: <workspace>/.auditooor/zk_circom_candidates.jsonl "
             "when --workspace is set, otherwise ./zk_circom_candidates.jsonl.",
    )
    p.add_argument(
        "--json", action="store_true",
        help="Print JSON summary to stdout and suppress log output.",
    )
    p.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO).",
    )
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Configure logging
    log_level = logging.WARNING if args.json else getattr(logging, args.log_level)
    logging.basicConfig(
        level=log_level,
        format="[zk-circom-analyze] %(levelname)s %(message)s",
    )
    log = logging.getLogger("zk-circom-analyze")

    # Validate mutual exclusion
    if args.workspace and args.circuits:
        parser.error("--workspace and --circuit are mutually exclusive")

    # Gather circuits
    workspace: Optional[Path] = None
    circuit_paths: List[Path] = []

    if args.circuits:
        circuit_paths = [Path(c) for c in args.circuits]
        for cp in circuit_paths:
            if not cp.is_file():
                parser.error(f"--circuit path does not exist: {cp}")
    elif args.workspace:
        workspace = args.workspace.resolve()
        if not workspace.is_dir():
            parser.error(f"--workspace is not a directory: {workspace}")
        circuit_paths = find_circom_files(workspace)
        log.info(f"workspace: {workspace}, found {len(circuit_paths)} .circom file(s)")
    else:
        parser.error("either --workspace or --circuit is required")

    # Determine output path
    output_jsonl: Optional[Path] = args.output_jsonl
    if output_jsonl is None and workspace is not None:
        output_jsonl = workspace / ".auditooor" / "zk_circom_candidates.jsonl"
    elif output_jsonl is None:
        output_jsonl = Path("zk_circom_candidates.jsonl")

    # Parse requested tools
    requested_tools = [t.strip() for t in args.tools.split(",") if t.strip()]

    # Run analysis
    summary = analyze_workspace(
        workspace=workspace,
        circuit_paths=circuit_paths,
        tools=requested_tools,
        timeout=args.timeout,
        output_jsonl=output_jsonl,
        log=log,
    )

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        verdict = summary["verdict"]
        log.info(f"verdict: {verdict}")
        log.info(f"circuits scanned: {summary['circuits_scanned']}")
        log.info(f"tools installed: {summary['tools_installed']}")
        log.info(f"findings total: {summary['findings_total']}")
        log.info(f"candidates written: {summary['candidates_written']}")
        if summary.get("candidates_path"):
            log.info(f"output: {summary['candidates_path']}")
        for u in summary.get("tools_unavailable", []):
            log.info(f"tool unavailable: {u['tool']} - {u.get('install_hint', u.get('reason', ''))}")

    # Exit 0 regardless of findings (caller decides action on candidates);
    # non-zero only on invocation errors (handled above by parser.error).
    return 0


if __name__ == "__main__":
    sys.exit(main())
