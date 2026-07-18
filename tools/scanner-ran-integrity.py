#!/usr/bin/env python3
"""scanner-ran-integrity.py - generic monitor for the "silent-0 false-green" scanner bug.

A static analyzer (Slither/semgrep/aderyn) or a pattern scanner can record
``status=ok`` / ``reason=completed`` / ``returncode=0`` while having analyzed
NOTHING - e.g. Slither on a workspace whose Solidity tree does not ``forge build``
emits a 0-byte stdout, 0 findings, yet is logged as a clean "completed" run. That
reads downstream as "Solidity statically scanned, nothing found" when in truth the
scanner never saw the code. This is a false-green: a scanner that did not run is
indistinguishable from a scanner that ran and found nothing.

This monitor inspects each language arm's scan artifacts under
``<ws>/.auditooor/`` and classifies every analyzer as one of:

  ran          - positive evidence of work (non-empty stdout log, OR a
                 files-scanned/contracts-analyzed count > 0, OR >=1 finding)
  silent-skip  - recorded ok/completed/rc=0 BUT no evidence of work
                 (empty stdout AND empty stderr AND 0 findings AND 0 files-scanned)
  errored      - non-zero returncode / explicit prereq-skip (already honest)
  absent       - no artifact

A ``silent-skip`` is the false-green: it MUST be surfaced as NOT-COVERED, never
trusted as "scanned clean". The gate exits non-zero (under --check) when any
in-scope language arm has a silent-skip, so the pipeline / operator sees it loudly
instead of treating the language as covered.

Offline / read-only / stdlib-only. Safe to run any time.

Usage:
  python3 tools/scanner-ran-integrity.py --workspace <ws> [--check] [--json]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCHEMA = "auditooor.scanner_ran_integrity.v1"


def _load(p: Path) -> dict | None:
    try:
        if p.is_file() and p.stat().st_size > 0:
            return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return None


def _log_nonempty(ws: Path, rec: dict, key: str) -> bool:
    """A *_log field is a path (possibly relative to ws). True iff it exists non-empty."""
    val = rec.get(key)
    if not val or not isinstance(val, str):
        # fall back to the inline tail field
        tail = rec.get(key.replace("_log", "_tail"))
        return bool(tail and str(tail).strip())
    p = Path(val)
    if not p.is_absolute():
        p = ws / val
    try:
        return p.is_file() and p.stat().st_size > 0
    except OSError:
        return False


def _classify_solidity_engine(ws: Path, rec: dict) -> tuple[str, str]:
    """Classify one solidity-deep-audit/*.json record. Returns (verdict, reason)."""
    rc = rec.get("returncode")
    reason = str(rec.get("reason") or "")
    status = str(rec.get("status") or "")
    # honest skip / error already
    if rc not in (0, None):
        return "errored", f"returncode={rc} reason={reason!r} (honest non-pass)"
    if "prereq" in reason.lower() or "skip" in reason.lower() or status.lower() in ("skip", "skipped"):
        return "errored", f"typed-skip reason={reason!r}"
    # rc==0 / completed: demand evidence of actual work
    stdout_work = _log_nonempty(ws, rec, "stdout_log")
    stderr_work = _log_nonempty(ws, rec, "stderr_log")
    # some runners record an analyzed/findings count inline
    n_findings = 0
    for k in ("findings_count", "num_findings", "n_findings"):
        if isinstance(rec.get(k), int):
            n_findings = rec[k]
            break
    analyzed = 0
    for k in ("files_analyzed", "contracts_analyzed", "files_scanned", "analyzed_count"):
        if isinstance(rec.get(k), int):
            analyzed = rec[k]
            break
    if stdout_work or stderr_work or n_findings > 0 or analyzed > 0:
        return "ran", (
            f"evidence: stdout={'y' if stdout_work else 'n'} "
            f"stderr={'y' if stderr_work else 'n'} findings={n_findings} analyzed={analyzed}"
        )
    return "silent-skip", (
        f"status={status!r} reason={reason!r} rc={rc} but EMPTY stdout+stderr, "
        f"0 findings, 0 files analyzed - the scanner never saw the code (false-green risk)"
    )


def _classify_pattern_scanner(rec: dict, files_key: str) -> tuple[str, str]:
    """Classify a pattern scanner (go/rust *_findings.json with patterns + files-scanned)."""
    scanned = rec.get(files_key)
    pats = rec.get("patterns") or {}
    hits = sum(p.get("hit_count", 0) for p in pats.values() if isinstance(p, dict))
    findings = rec.get("findings")
    if isinstance(findings, list) and findings:
        return "ran", f"{len(findings)} finding(s)"
    if isinstance(scanned, int) and scanned > 0:
        return "ran", f"{scanned} file(s) scanned, {len(pats)} patterns, {hits} hits"
    if pats and hits >= 0 and isinstance(scanned, int):
        # patterns present but 0 files scanned == did not run
        return "silent-skip", f"{len(pats)} patterns but {scanned} files scanned (did not run)"
    if pats:
        return "ran", f"{len(pats)} patterns evaluated, {hits} hits"
    return "absent", "no patterns / no scanned count"


def analyze(ws: Path) -> dict:
    arms: dict[str, list[dict]] = {"solidity": [], "go": [], "rust": []}

    # --- Solidity static analyzers ---
    sda = ws / ".auditooor" / "solidity-deep-audit"
    if sda.is_dir():
        for name in ("slither-resilient", "wave14-slither-ast", "semgrep-solidity",
                     "regex-detectors-solidity", "economic-invariant-detectors"):
            rec = _load(sda / f"{name}.json")
            if rec is None:
                continue
            verdict, why = _classify_solidity_engine(ws, rec)
            # regex-detectors emits a companion .findings.jsonl - count it as work
            fj = sda / f"{name}.findings.jsonl"
            if verdict == "silent-skip" and fj.is_file() and fj.stat().st_size > 0:
                verdict, why = "ran", "companion findings.jsonl present"
            arms["solidity"].append({"engine": name, "verdict": verdict, "reason": why})

    # --- Go pattern scanner ---
    go = _load(ws / ".auditooor" / "go_findings.json")
    if go is not None:
        v, why = _classify_pattern_scanner(go, "go_files_scanned")
        arms["go"].append({"engine": "go-detector-runner", "verdict": v, "reason": why})

    # --- Rust pattern scanners ---
    for fn, eng, fk in (("rust_findings.json", "rust-detector", "rust_files_scanned"),
                        ("reth_findings.json", "reth-detector", "crates_scanned")):
        r = _load(ws / ".auditooor" / fn)
        if r is not None:
            v, why = _classify_pattern_scanner(r, fk)
            arms["rust"].append({"engine": eng, "verdict": v, "reason": why})

    silent = [
        {"language": lang, **e}
        for lang, engs in arms.items()
        for e in engs
        if e["verdict"] == "silent-skip"
    ]
    ran_langs = {lang for lang, engs in arms.items() if any(e["verdict"] == "ran" for e in engs)}
    verdict = "fail-silent-scanner-false-green" if silent else "pass-scanners-honest"
    return {
        "schema": SCHEMA,
        "workspace": str(ws),
        "verdict": verdict,
        "silent_skips": silent,
        "languages_with_a_real_scan": sorted(ran_langs),
        "arms": arms,
        "reason": (
            f"{len(silent)} scanner(s) recorded ok/completed but produced no evidence of work "
            "(empty output + 0 findings + 0 files) - treat the language arm as NOT statically "
            "scanned, not as clean."
        ) if silent else "every recorded scanner shows positive evidence of work",
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Scanner-ran integrity monitor (silent-0 false-green guard).")
    ap.add_argument("--workspace", "--ws", required=True, dest="workspace")
    ap.add_argument("--check", action="store_true", help="exit 1 on any silent-skip")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    ws = Path(args.workspace).expanduser().resolve()
    if not ws.is_dir():
        print(f"[scanner-ran-integrity] ERROR: workspace not found: {ws}", file=sys.stderr)
        return 2

    res = analyze(ws)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"[scanner-ran-integrity] verdict={res['verdict']}")
        print(f"  languages with a real scan: {res['languages_with_a_real_scan'] or 'NONE'}")
        for lang, engs in res["arms"].items():
            for e in engs:
                mark = "  SILENT" if e["verdict"] == "silent-skip" else f"  {e['verdict']}"
                print(f"  [{lang}] {e['engine']}: {mark} - {e['reason']}")
        if res["silent_skips"]:
            print(f"\n  FALSE-GREEN: {len(res['silent_skips'])} scanner(s) recorded clean but never ran.")
            print("  -> the affected language arm is NOT statically scanned; do not trust 'completed/0 findings'.")

    if args.check and res["silent_skips"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
