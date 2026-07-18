#!/usr/bin/env python3
"""
hollow-engine-check.py  --  R80/R81 hollow deep-engine signal.

Reads  <ws>/.auditooor/solidity-deep-audit/manifest.json  and
       <ws>/.auditooor/genuine_coverage_manifest.json
and emits an UNMISSABLE stderr banner + writes
       <ws>/.auditooor/DEEP_AUDIT_HOLLOW.flag
when the deep layer executed 0 mutation-verified genuine harnesses despite
having generated >0 scaffold files (i.e. it ran SCAFFOLD-ONLY).

On a genuinely-audited workspace (mutation_verified_genuine_count > 0) the
flag file is REMOVED so stale flags do not persist across runs.

Advisory only: always exits 0.  Never breaks make audit-deep.

Generic: works for any workspace / any language - reads only the two
canonical JSON artifacts the pipeline already writes.

Usage:
    python3 tools/hollow-engine-check.py <workspace> <solidity_deep_out_dir>

Called automatically from the tail of the audit-deep-solidity Makefile target.
Also callable standalone for CI or spot-checks:
    python3 tools/hollow-engine-check.py ~/audits/morpho \
            ~/audits/morpho/.auditooor/solidity-deep-audit
"""

import json
import sys
from pathlib import Path


_BANNER = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
_TAG = "[DEEP-AUDIT-HOLLOW]"


def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    except Exception:
        return {}


def check(ws_str: str, out_str: str) -> bool:
    """Return True when the workspace is hollow (banner emitted), False when genuine."""
    ws = Path(ws_str).expanduser()
    out = Path(out_str).expanduser()

    manifest = _load_json(out / "manifest.json")
    gc = _load_json(ws / ".auditooor" / "genuine_coverage_manifest.json")
    flag_path = ws / ".auditooor" / "DEEP_AUDIT_HOLLOW.flag"

    # Quantities from manifest.json
    exec_count = manifest.get("executed_engine_harness_count") or 0
    gen_count = manifest.get("generated_per_function_harness_count") or 0
    avail_count = manifest.get("available_engine_harness_count") or 0

    # Quantities from genuine_coverage_manifest.json
    genuine = gc.get("mutation_verified_genuine_count") or 0
    checkable = gc.get("checkable_count") or 0
    gc_status = gc.get("status") or ""
    gc_summary = gc.get("summary") or "no genuine_coverage_manifest.json summary"

    # Skip known-hollow statuses that mean "toolchain absent / skip requested"
    # These are honest offline-safe exits, not false hollow.
    benign_statuses = {"no-per-function-manifest", "skipped", "tool-absent", ""}

    # A workspace is hollow when:
    #   - 0 mutation-verified genuine harnesses AND
    #   - something was generated (gen_count > 0) OR something was checkable
    #     OR the gc_status is a real run status (not a benign offline skip)
    real_run = gc_status not in benign_statuses
    hollow = (genuine == 0) and (gen_count > 0 or checkable > 0 or real_run)

    # Also hollow if an engine harness root was discovered but never executed
    # (exec_count == 0 AND avail_count > 0 means engines were skipped entirely)
    hollow = hollow or (exec_count == 0 and avail_count > 0)

    if not hollow:
        # Clean up stale flag from a previous hollow run
        flag_path.unlink(missing_ok=True)
        return False

    # Write marker file
    try:
        ws_auditooor = ws / ".auditooor"
        ws_auditooor.mkdir(parents=True, exist_ok=True)
        flag_content = (
            f"scaffold-only: 0 genuine mutation-verified harnesses\n"
            f"executed_engine_harness_count      = {exec_count}\n"
            f"available_engine_harness_count     = {avail_count}\n"
            f"generated_per_function_harness_count = {gen_count}\n"
            f"mutation_verified_genuine          = {genuine}\n"
            f"checkable                          = {checkable}\n"
            f"gc_status                          = {gc_status}\n"
            f"workspace                          = {ws}\n"
            f"summary                            = {gc_summary}\n"
            f"next step: make genuine-coverage WS={ws}\n"
            f"           Fill each harness with a SOURCE-GROUNDED assertion\n"
            f"           that FAILS on at least one injected mutant.\n"
        )
        flag_path.write_text(flag_content, encoding="utf-8")
    except OSError:
        pass

    # Emit the unmissable banner to stderr
    lines = [
        "",
        _BANNER,
        f"{_TAG} deep engines ran SCAFFOLD-ONLY / 0 genuine",
        f"  executed_engine_harness_count       : {exec_count}",
        f"  available_engine_harness_roots      : {avail_count}",
        f"  generated_per_function_harnesses    : {gen_count}",
        f"  mutation_verified_genuine           : {genuine} / {checkable} checkable",
        f"  genuine_coverage_manifest status    : {gc_status}",
        f"  summary                             : {gc_summary}",
        "  This workspace is NOT genuinely deep-audited.",
        f"  Marker written : {flag_path}",
        f"  Next step      : make genuine-coverage WS={ws}",
        "                   Fill each harness with a SOURCE-GROUNDED assertion",
        "                   that FAILS on at least one injected mutant.",
        _BANNER,
        "",
    ]
    print("\n".join(lines), file=sys.stderr)
    return True


def main(argv=None) -> int:
    args = (argv or sys.argv)[1:]
    if len(args) < 2:
        print(
            "Usage: hollow-engine-check.py <workspace> <solidity_deep_out_dir>",
            file=sys.stderr,
        )
        return 2
    try:
        check(args[0], args[1])
    except Exception as exc:
        print(f"[hollow-engine-check] WARN unexpected error: {exc}", file=sys.stderr)
    return 0  # always advisory


if __name__ == "__main__":
    sys.exit(main())
