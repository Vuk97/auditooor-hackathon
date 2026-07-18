#!/usr/bin/env python3
# <!-- r36-rebuttal: lane FIX-GENUINE-COVERAGE-DISPATCH-BRIEF registered via agent-pathspec-register.py -->
"""Emit the genuine-coverage agentic harness-build dispatch brief.

Extracted from the `genuine-coverage` Makefile recipe so the non-genuine-target
SELECTION is unit-testable (inline Makefile python could not be tested and a
filter bug silently shipped: it whitelisted only verdict in
{vacuous,no-baseline,skipped,error} and so DROPPED `no-property-discovered` /
`no-execution` harnesses - the exact verdict the per-function halmos scaffolds
carry - leaving `non_genuine_targets=[]` on every workspace and making the
genuine-coverage orchestrator a silent no-op while live-engines/hollow stayed red).

Correct rule (inverted, robust): a per-function harness is a NON-GENUINE TARGET
needing agentic work UNLESS it is PROVEN genuine (verdict in the genuine set).
Everything else - vacuous, no-property-discovered, no-execution, no-baseline,
no-mutants, skipped, error, etc. - is a target. Anti-false-green: only a
mutation-verified `non-vacuous` (or equivalent) verdict is excluded.

Usage: genuine-coverage-dispatch-brief.py --workspace <ws> [--out <path>] [--json]
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "auditooor.genuine_coverage_dispatch_brief.v1"

# A harness counts as GENUINE only with one of these mutation-verified verdicts;
# every other verdict (incl. no-property-discovered / no-execution) is a target.
GENUINE_VERDICTS = frozenset({
    "non-vacuous", "nonvacuous", "genuine", "mutation-verified", "killed",
})


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def select_non_genuine_targets(verdicts: list) -> list:
    """Non-genuine targets = every verdict row NOT proven genuine. Robust against
    new non-genuine verdict strings (the inline-Makefile whitelist was not)."""
    out = []
    for v in verdicts or []:
        if not isinstance(v, dict):
            continue
        if str(v.get("verdict")) not in GENUINE_VERDICTS:
            out.append(v)
    return out


def build_brief(ws: Path, brief_dir: Path) -> dict:
    gc = ws / ".auditooor" / "genuine_coverage_manifest.json"
    gcdata = {}
    if gc.is_file():
        try:
            gcdata = json.loads(gc.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            gcdata = {}
    verdicts = gcdata.get("verdicts") or []
    targets = select_non_genuine_targets(verdicts)
    return {
        "schema": SCHEMA,
        "generated_at": _utc_now(),
        "workspace": str(ws),
        "mission": (
            "Turn every vacuous / untouched / no-property in-scope function into a "
            "GENUINE, mutation-verified per-function harness. A harness is genuine "
            "ONLY if tools/mutation-verify-coverage.py classifies it non-vacuous (it "
            "FAILS on >=1 injected mutant of the function-under-test)."
        ),
        "inputs": {
            "per_function_attack_worklist": str(
                ws / ".auditooor" / "per_function_attack_worklist.jsonl"),
            "genuine_coverage_manifest": str(gc),
            "function_coverage_gate": "tools/function-coverage-completeness.py",
        },
        "non_genuine_targets": targets,
        "definition_of_done": (
            "make genuine-coverage re-run reports mutation_verified_genuine_count == "
            "checkable_count (zero vacuous), OR each residual vacuous row carries a "
            "source-cited ruled-out reason."
        ),
        "steps": [
            "For each non_genuine_target, read the worklist attack topics for that function.",
            "Write a per-function harness whose assertion encodes a SOURCE-GROUNDED "
            "property of the function (not assert(true)).",
            "Run tools/mutation-verify-coverage.py against it; iterate until verdict==non-vacuous.",
            "Re-run make genuine-coverage to refresh the manifest.",
        ],
    }


def main(argv) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--out", default=None)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    ws = Path(args.workspace).expanduser()
    brief_dir = ws / ".auditooor" / "genuine-coverage"
    brief_dir.mkdir(parents=True, exist_ok=True)
    out = Path(args.out).expanduser() if args.out else (brief_dir / "dispatch_brief.json")
    brief = build_brief(ws, brief_dir)
    out.write_text(json.dumps(brief, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    n = len(brief["non_genuine_targets"])
    if args.json:
        print(json.dumps({"out": str(out), "non_genuine_targets": n}))
    else:
        print(f"[genuine-coverage]   wrote {out} ({n} non-genuine targets)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
