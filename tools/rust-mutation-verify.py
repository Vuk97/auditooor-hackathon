#!/usr/bin/env python3
"""Rust CUT-mutant kill oracle (R80/R81 complement for Rust workspaces).

PURPOSE
-------
`mutation-verify-coverage.py` has a Rust arm (`cargo test --quiet`) but it
runs a WHOLE-workspace test suite rather than a per-function targeted harness.
That coarse runner cannot attribute a kill to a specific function's harness -
so `per_function_verified` in `mutation_verify_coverage.json` stays 0 for
Rust workspaces (the monero-oxide diagnosis).

This tool is the Rust-specific oracle that closes that gap.  Given:
  - a Rust SOURCE FILE containing the function-under-test (CUT)
  - a TARGET FUNCTION name (or `file:line`)
  - a TEST FILTER (a `cargo test` test-name filter, or a path to an inline
    test module / a test that lives in the same source file)

it:
  1. calls `tools/mutation-engine.py` to generate semantic mutants of the
     function body (flip comparisons, replace + with -, negate booleans, etc.)
  2. for each mutant: APPLY the mutant in-place, run `cargo test [filter]`
     under the workspace, record PASS/FAIL, RESTORE the original (always,
     even on interrupt/crash)
  3. emits a JSON verdict:
       killed   - the harness FAILED on >=1 mutant (non-vacuous coverage)
       survived - the harness PASSED on ALL mutants (vacuous coverage)
       no_baseline - the harness fails on clean code (not a valid oracle)
       no_mutants  - no mutable operators found (inconclusive)
       error       - tool/build problem

DESIGN CHOICES
--------------
- The tool DOES NOT create a temporary Cargo project.  It operates DIRECTLY on
  the source file inside the real workspace so that real imports, types, and
  `#[cfg(test)]` blocks are intact.  Mutation is applied in-place with an
  in-memory backup for safe restoration (identical to how mutation-verify-
  coverage.py handles Solidity via forge).

- When the test filter is a path to a `.rs` file that contains `#[test]`
  functions, we derive a filter by extracting test function names from it.
  When the filter is a bare string we pass it to `cargo test -- --filter
  <filter>` (exact substring match).

- A SIGINT/SIGTERM handler and a try/finally guarantee restoration.  The tool
  is safe to kill mid-run.

- Generic: no workspace name is hardcoded.  Pass --workspace for any Rust
  project.

INTEGRATION WITH mutation-verify-coverage.py
--------------------------------------------
`mutation-verify-coverage.py`'s Rust default runner is:
    ["cargo", "test", "--quiet"]
That whole-workspace invocation is too coarse for per-function attribution.
To use this tool instead, call mutation-verify-coverage.py with:
    --harness "python3 tools/rust-mutation-verify.py \\
               --source <file> --function <fn> \\
               --workspace <ws> --filter <test_name>"
OR set the env hook:
    AUDITOOOR_MVC_RUNNER_RUST="python3 tools/rust-mutation-verify.py \
        --source {workspace}/path/to/file.rs --function myfn \
        --workspace {workspace} --filter my_test_fn"

However, the most ergonomic integration is via the `run_for_mvc()` Python API
that mutation-verify-coverage.py calls for language=rust when this module is
importable:

    from rust_mutation_verify import run_for_mvc
    killed, survived, details = run_for_mvc(
        workspace=ws, source_file=src, function=fn, test_filter=flt,
        max_mutants=N, timeout=T)

OUTPUT (JSON via --json or return value)
-----------------------------------------
{
  "schema": "auditooor.rust_mutation_verify.v1",
  "workspace": "...",
  "source_file": "...",
  "function": "...",
  "test_filter": "...",
  "verdict": "killed|survived|no_baseline|no_mutants|error",
  "killed_count": N,
  "survived_count": N,
  "mutant_count": N,
  "baseline": {"status": "pass|fail|no-execution|error", "exit_code": N, "output_tail": "..."},
  "mutant_results": [
    {
      "mutant_id": "...",
      "operator": "...",
      "operator_class": "...",
      "line": N,
      "label": "...",
      "original_line": "...",
      "mutated_line": "...",
      "killed": true|false,
      "exit_code": N,
      "output_tail": "..."
    },
    ...
  ]
}

The `per_function` entry shape is compatible with what `_corroborated_genuine_count()`
in `audit-honesty-check.py` reads:
  {mutation_verified: true, oracle_verdict: "non-vacuous", killed: true}

RELATED TOOLS (tool-dedup rule, codified 2026-05-28)
----------------------------------------------------
- tools/mutation-engine.py: GENERATOR - produces mutants. Used here via direct
  import (not reimplemented).
- tools/mutation-verify-coverage.py: ORACLE - the language-generic runner. For
  Rust, its default runner is coarse (whole-workspace cargo test). This module
  provides the targeted per-function runner and exposes `run_for_mvc()` so
  mutation-verify-coverage.py can delegate to it when language=rust.
- tools/audit-honesty-check.py: CONSUMER - reads mutation_verify_coverage.json.
  This module's output is shaped to populate the per_function list it reads.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import shlex
import signal
import subprocess
import sys
from pathlib import Path

SCHEMA = "auditooor.rust_mutation_verify.v1"

_HERE = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# Load tools/mutation-engine.py (hyphen-named -> load by spec)
# ---------------------------------------------------------------------------
def _load_engine():
    tool = _HERE / "mutation-engine.py"
    if not tool.is_file():
        raise FileNotFoundError(f"mutation-engine.py not found at {tool}")
    spec = importlib.util.spec_from_file_location("mutation_engine", str(tool))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Cargo binary resolution (respects $PATH, ~/.cargo/bin)
# ---------------------------------------------------------------------------
def _cargo_bin() -> str:
    env_override = os.environ.get("AUDITOOOR_RUST_CARGO_BIN")
    if env_override:
        return env_override
    import shutil
    found = shutil.which("cargo")
    if found:
        return found
    # Common home-install location
    cand = Path.home() / ".cargo" / "bin" / "cargo"
    if cand.is_file():
        return str(cand)
    return "cargo"


# ---------------------------------------------------------------------------
# Derive test-function names from a .rs test file (extracts #[test] fns).
# Returns None when no tests are found (caller falls back to raw filter).
# ---------------------------------------------------------------------------
_TEST_FN_RE = re.compile(r"#\s*\[\s*test\s*\]\s*(?:\n[^\n]*)*?\bfn\s+(\w+)\s*\(", re.MULTILINE)


def _extract_test_names(path: Path) -> list[str]:
    try:
        src = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    return _TEST_FN_RE.findall(src)


# ---------------------------------------------------------------------------
# Classify cargo-test output into pass/fail/no-execution/error.
# Mirrors _classify() in mutation-verify-coverage.py (same token set).
# ---------------------------------------------------------------------------
_FAIL_TOKENS = (
    "test result: failed",
    "failures:",
    "panicked at",
    "assertion failed",
    "assertion `left == right` failed",
    "thread '",          # "thread 'test_foo' panicked" pattern
    "--- fail:",
    "[fail]",
    "error[e",           # compiler error "error[E0..." - mutant may not compile
    "error: could not compile",
    "could not compile",
)
_PASS_TOKENS = (
    "test result: ok",
    "running 0 tests",   # no tests matched filter - treated specially below
    "test result: ok. 0",
)
_NO_TESTS_TOKEN = "running 0 tests"


def _classify(rc: int, out: str) -> tuple[str, bool]:
    """Return (status, passed). status: pass | fail | no-execution | error."""
    low = out.lower()
    failed = any(t in low for t in _FAIL_TOKENS)
    if failed:
        return "fail", False
    if rc == 0:
        # Distinguish "0 tests ran" from a real pass.
        if _NO_TESTS_TOKEN in low:
            return "no-execution", False
        passed_token = any(t in low for t in _PASS_TOKENS)
        if not passed_token:
            return "no-execution", False
        return "pass", True
    return "error", False


def _tail(s: str, n: int = 1200) -> str:
    s = s.strip()
    return s[-n:] if len(s) > n else s


# ---------------------------------------------------------------------------
# Run a cargo test command; capture combined output.
# ---------------------------------------------------------------------------
def _run_cargo(cmd: list[str], cwd: Path, timeout: int) -> tuple[int, str]:
    try:
        p = subprocess.run(
            cmd, cwd=str(cwd), capture_output=True, text=True, timeout=timeout
        )
        return p.returncode, (p.stdout or "") + "\n" + (p.stderr or "")
    except subprocess.TimeoutExpired as e:
        return 124, f"TIMEOUT after {timeout}s\n{e.stdout or ''}\n{e.stderr or ''}"
    except FileNotFoundError as e:
        return 127, f"cargo-not-found: {e}"
    except Exception as e:  # noqa: BLE001
        return 1, f"runner-error: {e}"


# ---------------------------------------------------------------------------
# Build the cargo test command for a given filter.
# filter_spec is either:
#   - a bare test-function name / substring (passed to `cargo test -- <filter>`)
#   - a path to a .rs file (we extract #[test] names from it)
#   - None (run all tests in the workspace)
# ---------------------------------------------------------------------------
def _build_cargo_cmd(
    cargo: str,
    workspace: Path,
    source_file: Path,
    filter_spec: str | None,
) -> tuple[list[str], list[str]]:
    """Return (base_cmd, test_name_args) where the full command is base_cmd + test_name_args.

    base_cmd includes everything before any `--` separator.
    test_name_args is empty when no filter is given.
    """
    # Determine which package contains source_file.
    pkg_arg: list[str] = []
    cargo_toml = _find_cargo_toml(workspace, source_file)
    if cargo_toml and cargo_toml.parent != workspace:
        # Use -p <package-name> if we can determine it.
        pkg = _cargo_pkg_name(cargo_toml)
        if pkg:
            pkg_arg = ["-p", pkg]

    base = [cargo, "test", "--quiet"] + pkg_arg

    # Resolve filter names.
    test_names: list[str] = []
    if filter_spec:
        p = Path(filter_spec)
        if p.suffix == ".rs" and p.is_file():
            names = _extract_test_names(p)
            test_names = names if names else [filter_spec]
        else:
            test_names = [filter_spec]

    if test_names:
        # cargo test [filter] -- --exact  (run tests matching the filter).
        # Use the first name as the filter; exact matching works well for named tests.
        return base + [test_names[0], "--", "--exact"], []
    return base, []


def _find_cargo_toml(workspace: Path, source_file: Path) -> Path | None:
    """Walk from source_file upward to workspace looking for Cargo.toml."""
    target = source_file.resolve()
    ws = workspace.resolve()
    current = target.parent
    for _ in range(10):
        cand = current / "Cargo.toml"
        if cand.is_file():
            return cand
        if current == ws or current == current.parent:
            break
        current = current.parent
    # Fall back to workspace root
    cand = ws / "Cargo.toml"
    return cand if cand.is_file() else None


def _cargo_pkg_name(cargo_toml: Path) -> str | None:
    """Extract `name` from [package] section without a TOML parser."""
    try:
        text = cargo_toml.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    in_package = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "[package]":
            in_package = True
        elif stripped.startswith("[") and stripped != "[package]":
            in_package = False
        elif in_package and stripped.startswith("name"):
            m = re.search(r'name\s*=\s*"([^"]+)"', stripped)
            if m:
                return m.group(1)
    return None


# ---------------------------------------------------------------------------
# Parse `--function` arg: name or file:line or bare line.
# ---------------------------------------------------------------------------
def _parse_fn_arg(arg: str) -> tuple[str | None, int | None]:
    if ":" in arg:
        _, _, tail = arg.rpartition(":")
        if tail.isdigit():
            return None, int(tail)
    if arg.isdigit():
        return None, int(arg)
    return arg, None


# ---------------------------------------------------------------------------
# Core verify logic - exposed as run_for_mvc() for mutation-verify-coverage.py
# ---------------------------------------------------------------------------
def run_for_mvc(
    *,
    workspace: Path,
    source_file: Path,
    function: str,
    test_filter: str | None = None,
    classes: list[str] | None = None,
    max_mutants: int | None = None,
    timeout: int = 300,
) -> dict:
    """Mutation-kill oracle for a single Rust function.

    Returns a dict with the same schema as the full `verify()` call; shape is
    compatible with what `_corroborated_genuine_count()` in audit-honesty-check.py
    reads for its per_function list entries.

    Called by mutation-verify-coverage.py's Rust arm when this module is
    importable:

        import importlib.util, sys
        spec = importlib.util.spec_from_file_location(
            "rust_mutation_verify",
            str(Path(__file__).parent / "rust-mutation-verify.py"))
        rmu = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(rmu)
        result = rmu.run_for_mvc(workspace=ws, source_file=src,
                                  function=fn, test_filter=flt, ...)
    """
    engine = _load_engine()
    cargo = _cargo_bin()

    fn_name_arg, line_hint = _parse_fn_arg(function)
    lang = "rust"

    if not source_file.is_file():
        return {
            "schema": SCHEMA,
            "verdict": "error",
            "reason": f"source not found: {source_file}",
        }

    original = source_file.read_text(encoding="utf-8")

    # Generate mutants before touching disk.
    try:
        mutants, fn_name, span = engine.generate_mutants(
            original, lang,
            name=fn_name_arg, line_hint=line_hint,
            classes=classes or engine.ALL_CLASSES,
            max_mutants=max_mutants,
        )
    except LookupError:
        return {
            "schema": SCHEMA,
            "verdict": "error",
            "reason": f"function not found: {function}",
        }

    cmd, _ = _build_cargo_cmd(cargo, workspace, source_file, test_filter)

    result: dict = {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "source_file": str(source_file),
        "function": fn_name,
        "function_span": {"start_line": span[0], "end_line": span[1]},
        "language": lang,
        "test_filter": test_filter,
        "runner_command": " ".join(cmd),
        "runner_cwd": str(workspace),
        "timeout_s": timeout,
        "mutant_count": len(mutants),
    }

    _restored = {"done": False}

    def _restore():
        if not _restored["done"]:
            try:
                source_file.write_text(original, encoding="utf-8")
            finally:
                _restored["done"] = True

    def _sig(_signum, _frame):
        _restore()
        raise KeyboardInterrupt

    old_int = signal.getsignal(signal.SIGINT)
    old_term = signal.getsignal(signal.SIGTERM)
    try:
        signal.signal(signal.SIGINT, _sig)
        signal.signal(signal.SIGTERM, _sig)

        # Step 1: baseline on clean code.
        rc0, out0 = _run_cargo(cmd, workspace, timeout)
        b_status, b_pass = _classify(rc0, out0)
        result["baseline"] = {
            "status": b_status,
            "exit_code": rc0,
            "output_tail": _tail(out0),
        }
        if not b_pass:
            if b_status == "no-execution":
                result["verdict"] = "error"
                result["reason"] = (
                    "cargo test exited 0 but ran 0 tests matching the filter "
                    "(silent skip); the harness is not a valid oracle for this "
                    f"function. Filter used: {test_filter!r}"
                )
            else:
                result["verdict"] = "no_baseline"
                result["reason"] = (
                    f"harness does not PASS on clean code (status={b_status}, "
                    f"exit={rc0}); cannot be a coverage oracle."
                )
            return result

        if not mutants:
            result["verdict"] = "no_mutants"
            result["reason"] = (
                "mutation engine produced 0 mutants for the function (no "
                "mutable operators found in the body); vacuity inconclusive."
            )
            result["mutant_results"] = []
            return result

        # Step 2: per-mutant re-run.
        mutant_results = []
        killed = 0
        survived = 0
        for mut in mutants:
            source_file.write_text(mut["_mutated_source"], encoding="utf-8")
            try:
                rc, out = _run_cargo(cmd, workspace, timeout)
            finally:
                source_file.write_text(original, encoding="utf-8")
            status, passed = _classify(rc, out)
            # KILLED == harness now FAILS (status == 'fail').
            mutant_killed = status == "fail"
            if mutant_killed:
                killed += 1
            elif status == "pass":
                survived += 1
            mutant_results.append({
                "mutant_id": mut["mutant_id"],
                "operator": mut["operator"],
                "operator_class": mut["operator_class"],
                "line": mut["line"],
                "label": mut["label"],
                "original_line": mut["original_line"],
                "mutated_line": mut["mutated_line"],
                "killed": mutant_killed,
                "exit_code": rc,
                "output_tail": _tail(out),
            })

        result["mutant_results"] = mutant_results
        result["killed_count"] = killed
        result["survived_count"] = survived
        result["error_count"] = len(mutants) - killed - survived

        # Step 3: verdict.
        if killed >= 1:
            result["verdict"] = "killed"
            result["reason"] = (
                f"harness FAILED on {killed}/{len(mutants)} mutant(s); "
                f"coverage of {fn_name} is non-vacuous."
            )
            # Shape for _corroborated_genuine_count() in audit-honesty-check.py:
            result["mutation_verified"] = True
            result["oracle_verdict"] = "non-vacuous"
        elif survived == len(mutants):
            result["verdict"] = "survived"
            result["reason"] = (
                f"harness PASSED on ALL {len(mutants)} mutant(s) of {fn_name}; "
                f"coverage is vacuous (hollow)."
            )
            result["mutation_verified"] = True
            result["oracle_verdict"] = "vacuous"
        else:
            # Some mutants errored but none killed.
            result["verdict"] = "survived"
            result["reason"] = (
                f"harness killed 0/{len(mutants)} mutants "
                f"({survived} survived, {result['error_count']} errored); "
                f"no kill demonstrated - treat as vacuous."
            )
            result["mutation_verified"] = True
            result["oracle_verdict"] = "vacuous"
        return result
    finally:
        _restore()
        signal.signal(signal.SIGINT, old_int)
        signal.signal(signal.SIGTERM, old_term)


# Alias used by mutation-verify-coverage.py wiring.
verify = run_for_mvc


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Rust CUT-mutant kill oracle (R80/R81). "
                    "Plants semantic mutations in a Rust fn body, runs cargo test, "
                    "reports killed/survived per mutant."
    )
    ap.add_argument("--workspace", required=True, help="Rust workspace root (Cargo.toml directory)")
    ap.add_argument(
        "--source", required=True,
        help="path to .rs file containing the function-under-test",
    )
    ap.add_argument(
        "--function", required=True,
        help="target function: name, file:line, or bare line number",
    )
    ap.add_argument(
        "--filter", dest="test_filter", default=None,
        help="cargo test filter: a test function name, a substring, or a path "
             "to a .rs file whose #[test] functions are used as the filter",
    )
    ap.add_argument(
        "--classes", default=None,
        help="comma-separated mutation operator classes (default: all). "
             "Options: relational,arithmetic,rounding,guard_removal,boundary,boolean,assignment",
    )
    ap.add_argument("--max", type=int, default=None, help="cap number of mutants")
    ap.add_argument("--timeout", type=int, default=300,
                    help="per-run timeout seconds (default: 300)")
    ap.add_argument("--out", default=None,
                    help="write JSON record to this path (seeds *mutation*.json for R80)")
    ap.add_argument("--json", action="store_true", help="emit full JSON to stdout")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).resolve()
    src = Path(args.source)
    if not src.is_absolute():
        src = (Path.cwd() / src) if (Path.cwd() / src).exists() else (ws / src)
    src = src.resolve()

    classes = [c.strip() for c in args.classes.split(",")] if args.classes else None

    rec = run_for_mvc(
        workspace=ws,
        source_file=src,
        function=args.function,
        test_filter=args.test_filter,
        classes=classes,
        max_mutants=args.max,
        timeout=args.timeout,
    )

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(rec, indent=2), encoding="utf-8")

    if args.json:
        print(json.dumps(rec, indent=2))
    else:
        slim = {k: v for k, v in rec.items() if k != "mutant_results"}
        print(json.dumps(slim, indent=2))

    verdict = rec.get("verdict", "error")
    # Exit codes: 0 = killed (non-vacuous), 1 = survived (vacuous), 2 = error/no-baseline
    if verdict == "killed":
        return 0
    if verdict == "survived":
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
