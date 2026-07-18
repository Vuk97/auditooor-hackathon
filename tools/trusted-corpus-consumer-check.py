#!/usr/bin/env python3
"""Active-hunt routing check (PR2b): verify corpus consumers read the TRUSTED index.

Phase 1 of docs/FIND_ALL_BUGS_CAPABILITY_UPLIFT_PLAN_2026-05-29.md requires that
active hunt, originality, and backtest scoring route corpus consumption through
the shared trusted-corpus resolver (`tools/lib/trusted_corpus_resolver.py`) so a
fabricated / prose-only / quarantined row can never silently drive a hypothesis
or a score. This tool is the mechanical enforcement: it statically confirms each
named consumer imports the resolver AND stamps a `corpus_trust` provenance field
on its output.

It is READ-ONLY: it parses source files, runs no consumer, mutates nothing.

VERDICTS:
  pass-all-consumers-routed   - every required consumer imports + annotates
  fail-consumer-not-routed    - one or more consumers missing the wiring
  error                       - a required consumer file is missing

USAGE:
  python3 tools/trusted-corpus-consumer-check.py [--json]

RELATED TOOLS:
  - tools/lib/trusted_corpus_resolver.py : the resolver this enforces use of.
  - tools/corpus-quality-routing.py (PR2a): produces the buckets the resolver reads.
Gap filled: nothing previously asserted, mechanically, that hunt/score consumers
route through the trusted index rather than reading the raw corpus directly.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCHEMA = "auditooor.trusted_corpus_consumer_check.v1"
REPO_ROOT = Path(__file__).resolve().parent.parent

# Each consumer must (a) import the resolver and (b) emit a corpus_trust field.
REQUIRED_CONSUMERS = {
    "hunt-guidance": "tools/corpus-driven-hunt.py",
    "backtest": "tools/auditor-backtest.py",
    "originality": "tools/originality-before-proof-gate.py",
}

IMPORT_NEEDLE = "trusted_corpus_resolver"
ANNOTATE_NEEDLE = "corpus_trust"


def check_consumer(rel_path: str) -> dict:
    path = REPO_ROOT / rel_path
    out = {"consumer": rel_path}
    if not path.is_file():
        out["status"] = "missing"
        out["imports_resolver"] = False
        out["annotates_trust"] = False
        return out
    text = path.read_text(encoding="utf-8", errors="replace")
    imports = IMPORT_NEEDLE in text
    annotates = ANNOTATE_NEEDLE in text
    out["imports_resolver"] = imports
    out["annotates_trust"] = annotates
    out["status"] = "routed" if (imports and annotates) else "not-routed"
    return out


def run() -> dict:
    consumers = []
    any_missing = False
    all_routed = True
    for label, rel in REQUIRED_CONSUMERS.items():
        r = check_consumer(rel)
        r["label"] = label
        consumers.append(r)
        if r["status"] == "missing":
            any_missing = True
        if r["status"] != "routed":
            all_routed = False

    if any_missing:
        verdict = "error"
    elif all_routed:
        verdict = "pass-all-consumers-routed"
    else:
        verdict = "fail-consumer-not-routed"

    return {
        "schema_version": SCHEMA,
        "verdict": verdict,
        "consumers": consumers,
    }


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="Active-hunt trusted-corpus routing check")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    res = run()
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"[active-hunt-routing-check] {res['verdict']}")
        for c in res["consumers"]:
            print(f"  - {c['label']:14s} {c['consumer']}: {c['status']} "
                  f"(import={c['imports_resolver']} annotate={c['annotates_trust']})")

    if res["verdict"] == "pass-all-consumers-routed":
        return 0
    if res["verdict"] == "error":
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
