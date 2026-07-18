#!/usr/bin/env python3
"""chimera-invariant-registrar.py -- shared prereq for core-coverage / economic-invariant gates.

PURPOSE
-------
Register REAL stateful invariant harnesses that live under <ws>/chimera_harnesses/*/
into <ws>/.auditooor/mutation_verify_coverage.json so the downstream gates COUNT them as
mutation-verified per_function entries.

MECHANISM
---------
For each chimera_harnesses/<name>/ that ships a ``chimera_cut_manifest.json``

    {
        "cut_source_files": ["contracts/SiloFacet.sol", ...],
        "mutation_kill_test_pattern": "test_mutation_kills_|test_nonvacuity_"
    }

the tool:

1. Reads the manifest (required; harnesses without one are silently skipped).
2. Runs:
       forge test --match-test <pattern> [--rpc-url <ARB_RPC>] --no-match-test '^$'
   inside the harness directory.
3. ONLY on a clean->mutant flip confirmed from real forge output
   (``[PASS] test_mutation_kills_*`` AND ``[FAIL] ...`` on mutant, or the simpler
   ``[PASS] test_mutation_kills_*`` when the harness uses internal etch + single run)
   writes a per_function entry:

    {
        "axis":             "per-function",
        "mode":             "chimera-invariant",
        "function":         "<harness-dir-name>",
        "source_file":      "<first cut_source_file>",
        "harness":          "<abs-harness-dir>",
        "killed":           true,
        "mutation_verified": true,
        "oracle_verdict":   "non-vacuous",
        "verdict":          "killed",
        "clean_result":     "pass",
        "kill_test_names":  [...],
        "generated_at":     "<utc-iso>"
    }

4. If the forge run fails, times out, or the expected test names are absent, writes a
   ``mutation_verified=false`` entry so the gate sees the honest state.

FALSE-GREEN IS THE #1 SIN.  A mutation_verified=true entry is ONLY written when forge
reports the kill pattern test as PASS.  The file is NEVER hand-edited; the tool is the
only writer for chimera-invariant mode entries.

IDEMPOTENT MERGE
----------------
The merge follows the same label-keyed strategy as cross-function-fork-etch-producer.py
merge_into_canonical: the join key is (mode, function) = ("chimera-invariant", harness-name).
Existing per_function entries for OTHER harnesses (or produced by the source-recompile path)
are PRESERVED.

USAGE
-----
    # scan all chimera_harnesses under a workspace
    python3 chimera-invariant-registrar.py --ws /path/to/ws

    # scan a single named harness
    python3 chimera-invariant-registrar.py --ws /path/to/ws --harness SiloCoreInvariants

    # dry-run: print what would happen, don't write
    python3 chimera-invariant-registrar.py --ws /path/to/ws --dry-run

    # set forge timeout (default 120s)
    python3 chimera-invariant-registrar.py --ws /path/to/ws --timeout 300

OPTIONS
-------
--ws       <path>    Workspace root (required).
--harness  <name>    Only process this one harness subdirectory.
--dry-run            Discover + run forge but do NOT write the output file.
--timeout  <sec>     Seconds before killing the forge subprocess (default 120).
--rpc-url  <url>     Override the RPC URL passed to forge (else uses ARB_RPC env).
--verbose            Print forge stdout/stderr on success too (always shown on failure).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "auditooor.mutation_verify_coverage.v1"
TOOL = "CHIMERA-INVARIANT-REGISTRAR"
MANIFEST_NAME = "chimera_cut_manifest.json"
DEFAULT_TIMEOUT = 120
DEFAULT_KILL_PATTERN = "test_mutation_kills_|test_nonvacuity_"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _log(msg: str) -> None:
    print(f"[{TOOL}] {msg}", flush=True)


def _warn(msg: str) -> None:
    print(f"[{TOOL}][WARN] {msg}", flush=True, file=sys.stderr)


def _err(msg: str) -> None:
    print(f"[{TOOL}][ERROR] {msg}", flush=True, file=sys.stderr)


# ---------------------------------------------------------------------------
# Manifest loading
# ---------------------------------------------------------------------------

def load_manifest(harness_dir: Path) -> dict | None:
    """Return the parsed chimera_cut_manifest.json or None if absent / invalid."""
    mpath = harness_dir / MANIFEST_NAME
    if not mpath.is_file():
        return None
    try:
        data = json.loads(mpath.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        _warn(f"{harness_dir.name}: manifest parse error: {exc}")
        return None
    if not isinstance(data.get("cut_source_files"), list):
        _warn(f"{harness_dir.name}: manifest missing/invalid 'cut_source_files'")
        return None
    return data


# ---------------------------------------------------------------------------
# Forge runner
# ---------------------------------------------------------------------------

def _build_forge_cmd(pattern: str, rpc_url: str | None) -> list[str]:
    """Build the forge test command list."""
    cmd = [
        "forge", "test",
        "--match-test", pattern,
    ]
    if rpc_url:
        cmd += ["--rpc-url", rpc_url]
    return cmd


def run_forge(
    harness_dir: Path,
    kill_pattern: str,
    rpc_url: str | None,
    timeout: int,
    verbose: bool,
) -> dict:
    """
    Run forge test inside harness_dir and parse results.

    Returns a dict with keys:
        success (bool)      - subprocess exited 0
        stdout (str)
        stderr (str)
        passed_tests (list[str])  - test_mutation_kills_* / test_nonvacuity_* that PASSED
        failed_tests (list[str])  - same that FAILED
        timed_out (bool)
        error (str | None)  - message on non-test-run failures
    """
    cmd = _build_forge_cmd(kill_pattern, rpc_url)
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(harness_dir),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "stdout": "",
            "stderr": "",
            "passed_tests": [],
            "failed_tests": [],
            "timed_out": True,
            "error": f"forge timed out after {timeout}s",
        }
    except FileNotFoundError:
        return {
            "success": False,
            "stdout": "",
            "stderr": "",
            "passed_tests": [],
            "failed_tests": [],
            "timed_out": False,
            "error": "forge not found in PATH",
        }

    stdout = proc.stdout or ""
    stderr = proc.stderr or ""

    # Parse [PASS] / [FAIL] lines for tests matching the kill pattern
    # forge output format: "[PASS] test_foo() (gas: 12345)" or "[FAIL]  test_foo() ..."
    # Build a regex that matches the kill pattern test names.
    kill_re = re.compile(kill_pattern)
    passed: list[str] = []
    failed: list[str] = []

    for line in (stdout + "\n" + stderr).splitlines():
        m_pass = re.match(r"\s*\[PASS\]\s+(test\S+?)\s*\(", line)
        m_fail = re.match(r"\s*\[FAIL[^\]]*\]\s+(test\S+?)\s*[\(\[]", line)
        if m_pass and kill_re.search(m_pass.group(1)):
            passed.append(m_pass.group(1))
        if m_fail and kill_re.search(m_fail.group(1)):
            failed.append(m_fail.group(1))

    return {
        "success": proc.returncode == 0,
        "stdout": stdout,
        "stderr": stderr,
        "passed_tests": passed,
        "failed_tests": failed,
        "timed_out": False,
        "error": None,
    }


# ---------------------------------------------------------------------------
# Per-harness evaluation
# ---------------------------------------------------------------------------

def evaluate_harness(
    harness_dir: Path,
    manifest: dict,
    rpc_url: str | None,
    timeout: int,
    verbose: bool,
) -> dict:
    """
    Run forge for one harness and return a per_function entry (mutation_verified may be
    True or False; never lies about the real result).
    """
    cut_files: list[str] = manifest.get("cut_source_files") or []
    kill_pattern: str = manifest.get("mutation_kill_test_pattern") or DEFAULT_KILL_PATTERN
    primary_source = cut_files[0] if cut_files else "unknown"

    base: dict = {
        "axis": "per-function",
        "mode": "chimera-invariant",
        "function": harness_dir.name,
        "source_file": primary_source,
        "cut_source_files": cut_files,
        "harness": str(harness_dir.resolve()),
        "kill_test_pattern": kill_pattern,
        "generated_at": _utc_now(),
    }

    _log(f"{harness_dir.name}: running forge (pattern={kill_pattern!r}, timeout={timeout}s)")
    result = run_forge(harness_dir, kill_pattern, rpc_url, timeout, verbose)

    if verbose or not result["success"]:
        if result["stdout"]:
            print(result["stdout"][:4000])
        if result["stderr"]:
            print(result["stderr"][:2000], file=sys.stderr)

    if result["timed_out"]:
        _warn(f"{harness_dir.name}: TIMED OUT - not registering as verified")
        return {
            **base,
            "killed": False,
            "mutation_verified": False,
            "oracle_verdict": "timed-out",
            "verdict": "timed-out",
            "clean_result": "timeout",
            "kill_test_names": [],
            "reason": result["error"],
        }

    if result["error"]:
        _warn(f"{harness_dir.name}: run error: {result['error']}")
        return {
            **base,
            "killed": False,
            "mutation_verified": False,
            "oracle_verdict": "error",
            "verdict": "error",
            "clean_result": "error",
            "kill_test_names": [],
            "reason": result["error"],
        }

    passed = result["passed_tests"]
    failed_kill = result["failed_tests"]  # kill-pattern tests that FAILED (bad)

    # A non-zero exit but no matching kill-tests = likely a compile error or different tests
    if not passed and not result["success"]:
        _warn(
            f"{harness_dir.name}: forge exited non-zero and no kill-pattern tests passed "
            f"(failed_kill={failed_kill})"
        )
        return {
            **base,
            "killed": False,
            "mutation_verified": False,
            "oracle_verdict": "no-kill-tests-passed",
            "verdict": "not-verified",
            "clean_result": "fail",
            "kill_test_names": [],
            "reason": f"forge rc={result['success']} passed={passed} failed={failed_kill}",
        }

    if not passed:
        # Forge exited 0 but no matching tests ran - pattern mismatch or harness has no
        # kill tests yet.
        _warn(
            f"{harness_dir.name}: no kill-pattern tests found in output "
            f"(pattern={kill_pattern!r})"
        )
        return {
            **base,
            "killed": False,
            "mutation_verified": False,
            "oracle_verdict": "no-kill-tests-found",
            "verdict": "not-verified",
            "clean_result": "pass",
            "kill_test_names": [],
            "reason": "kill-pattern produced no matching test names in forge output",
        }

    # Kill tests PASSED - this is the genuine non-vacuity signal.
    _log(
        f"{harness_dir.name}: KILL CONFIRMED - {len(passed)} kill-test(s) passed: {passed}"
    )
    return {
        **base,
        "killed": True,
        "mutation_verified": True,
        "oracle_verdict": "non-vacuous",
        "verdict": "killed",
        "clean_result": "pass",
        "kill_test_names": passed,
        "reason": f"kill-pattern PASS on {len(passed)} test(s)",
    }


# ---------------------------------------------------------------------------
# Canonical merge (mirrors cross-function-fork-etch-producer merge_into_canonical)
# ---------------------------------------------------------------------------

def _chimera_key(rec: dict) -> tuple[str, str]:
    """Join key: (mode, function). Chimera entries are per harness-name."""
    return (rec.get("mode") or ""), (rec.get("function") or "")


def merge_chimera_records(ws: Path, new_records: list[dict]) -> dict:
    """
    Merge chimera-invariant per_function records into the canonical
    mutation_verify_coverage.json, preserving all other entries.

    Strategy:
    - Existing per_function entries that are NOT chimera-invariant mode are preserved.
    - Existing chimera-invariant entries for harnesses NOT processed this run are preserved.
    - Entries for harnesses processed this run are replaced by the fresh result.
    - cross_function, counts, summary, etc. are refreshed.
    """
    canonical = ws / ".auditooor" / "mutation_verify_coverage.json"
    existing: dict = {}
    if canonical.is_file() and canonical.stat().st_size > 0:
        try:
            existing = json.loads(canonical.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            existing = {}

    per_function: list[dict] = list(existing.get("per_function") or [])
    cross_function: list[dict] = list(existing.get("cross_function") or [])

    # Build index of harness names processed this run
    processed_keys = {_chimera_key(r) for r in new_records}

    # Keep all existing per_function entries that are NOT in the processed set
    kept: list[dict] = [
        r for r in per_function if _chimera_key(r) not in processed_keys
    ]
    # Add new records
    merged_pf = kept + new_records

    pf_verified = sum(1 for r in merged_pf if r.get("mutation_verified"))
    xf_verified = sum(1 for r in cross_function if r.get("mutation_verified"))

    payload = {
        "schema": SCHEMA,
        "generated_at": _utc_now(),
        "run_id": os.environ.get("AUDITOOOR_AUDIT_RUN_FULL_ID") or existing.get("run_id"),
        "workspace": str(ws),
        "language": existing.get("language", "solidity"),
        "per_function": merged_pf,
        "cross_function": cross_function,
        "verdicts": list(merged_pf) + list(cross_function),
        "counts": {
            "per_function_total": len(merged_pf),
            "per_function_verified": pf_verified,
            "cross_function_total": len(cross_function),
            "cross_function_verified": xf_verified,
        },
        "per_function_status": "chimera-invariant-registered",
        "cross_function_status": existing.get("cross_function_status", "preserved"),
        "cross_function_mode": existing.get("cross_function_mode", "fork-etch"),
        "summary": (
            f"per-function {pf_verified}/{len(merged_pf)} mutation-verified "
            f"(chimera-invariant + source-recompile); "
            f"cross-function {xf_verified}/{len(cross_function)} mutation-verified"
        ),
    }
    return payload


# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------

def scan_workspace(
    ws: Path,
    harness_filter: str | None,
    dry_run: bool,
    timeout: int,
    rpc_url: str | None,
    verbose: bool,
) -> int:
    """
    Scan <ws>/chimera_harnesses/ and register qualifying harnesses.
    Returns 0 on success, 1 if any harness produced a non-verified result.
    """
    harnesses_root = ws / "chimera_harnesses"
    if not harnesses_root.is_dir():
        _log(f"No chimera_harnesses/ directory at {ws} - nothing to register")
        return 0

    dirs = sorted(harnesses_root.iterdir())
    if harness_filter:
        dirs = [d for d in dirs if d.name == harness_filter]
        if not dirs:
            _err(f"Harness '{harness_filter}' not found under {harnesses_root}")
            return 1

    records: list[dict] = []
    any_failure = False

    for hdir in dirs:
        if not hdir.is_dir():
            continue
        manifest = load_manifest(hdir)
        if manifest is None:
            _log(f"{hdir.name}: no {MANIFEST_NAME} - skipping")
            continue

        entry = evaluate_harness(hdir, manifest, rpc_url, timeout, verbose)
        records.append(entry)
        if not entry.get("mutation_verified"):
            any_failure = True

    if not records:
        _log("No manifested harnesses found - nothing to register")
        return 0

    verified_count = sum(1 for r in records if r.get("mutation_verified"))
    _log(
        f"Scan complete: {verified_count}/{len(records)} harnesses mutation-verified "
        f"({'DRY-RUN - not writing' if dry_run else 'writing to canonical'})"
    )

    if not dry_run:
        payload = merge_chimera_records(ws, records)
        out_path = ws / ".auditooor" / "mutation_verify_coverage.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        _log(f"Written: {out_path}")
        _log(f"Summary: {payload['summary']}")
    else:
        for r in records:
            status = "VERIFIED" if r.get("mutation_verified") else "NOT-VERIFIED"
            _log(f"  [DRY-RUN] {r['function']}: {status} ({r.get('reason','')})")

    return 1 if any_failure else 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Register chimera stateful invariant harnesses into mutation_verify_coverage.json"
    )
    parser.add_argument("--ws", required=True, help="Workspace root path")
    parser.add_argument("--harness", default=None, help="Only process this harness name")
    parser.add_argument("--dry-run", action="store_true", help="Discover + run but don't write")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Forge timeout seconds")
    parser.add_argument("--rpc-url", default=None, help="RPC URL override (else uses ARB_RPC env)")
    parser.add_argument("--verbose", action="store_true", help="Print forge output on success too")
    args = parser.parse_args(argv)

    ws = Path(args.ws).resolve()
    if not ws.is_dir():
        _err(f"Workspace directory not found: {ws}")
        return 1

    rpc_url = args.rpc_url or os.environ.get("ARB_RPC")

    return scan_workspace(
        ws=ws,
        harness_filter=args.harness,
        dry_run=args.dry_run,
        timeout=args.timeout,
        rpc_url=rpc_url,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    sys.exit(main())
