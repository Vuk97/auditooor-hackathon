#!/usr/bin/env python3
"""routing-integrity-check.py - B2 advisory-first routing-integrity gate.

WHAT THIS GUARDS
================
A hacker-question / attack-class record carries `target_languages`, the set of
source languages on which the question is meant to fire. A worker lane for a
Go/Rust/Move/Cairo/ZK workspace filters the library by its own language
(`vault_hacker_questions(target_language="go")`), so a record whose
`target_languages` is skewed to Solidity NEVER surfaces on the surface where its
attack class actually lives. Consensus, memory-safety, Cosmos/IBC, Substrate,
Zebra and compiler classes were all stamped `["solidity"]` by a fail-to-solidity
default - amputating whole attack classes from the non-Solidity fleet by
construction. This is a trusted-enforcement-unsoundness in our OWN routing:
severity-anchored, impact-agnostic.

WHAT IT CHECKS
==============
For every record, it recomputes the class's NATIVE language(s) from the shared
`tools/lib/per_function_target_patterns.py` derivation (attack-class taxonomy
anchor + source-shape evidence). If a native language is derivable and the
record's stored `target_languages` does NOT contain it, that is a mis-route.

It never over-corrects: a class with no derivable native language (fail-open) is
skipped, and a genuinely Solidity-only class (allowance-residue,
unlimited-approve, ERC-20 misuse, ...) resolves to `("solidity",)` and matches a
`["solidity"]` record -> silent.

ADVISORY-FIRST
==============
Exit 0 (WARN) by default even when mismatches exist. Exit 1 (BLOCK) only when
AUDITOOOR_ROUTING_INTEGRITY_STRICT is set truthy. A JSON report is always
written so downstream consumers / audit-complete can read the mismatch set.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_CORPUS = REPO / "audit" / "corpus_tags" / "derived" / "hacker_questions_library.jsonl"
DEFAULT_REPORT = REPO / "audit" / "corpus_tags" / "derived" / "routing_integrity_report.json"
STRICT_ENV = "AUDITOOOR_ROUTING_INTEGRITY_STRICT"


def _truthy(v: str) -> bool:
    return str(v or "").strip().lower() in ("1", "true", "yes", "on", "strict")


def _load_lib():
    lib = REPO / "tools" / "lib" / "per_function_target_patterns.py"
    spec = importlib.util.spec_from_file_location("pftp_gate", lib)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def scan_records(records, lib):
    """Return (mismatches, checked, native_decidable).

    A mismatch = a record whose derivable native language(s) are not all present
    in its stored target_languages.
    """
    mismatches = []
    checked = 0
    native_decidable = 0
    for rec in records:
        if not isinstance(rec, dict):
            continue
        checked += 1
        anchor = str(rec.get("attack_class_anchor") or rec.get("attack_class") or "")
        qtext = str(rec.get("question_text") or "")
        native = lib.derive_native_target_languages(anchor, qtext)
        if not native:
            continue  # fail-open: undecidable native language is not a mis-route
        native_decidable += 1
        stored = [str(x).lower().strip() for x in (rec.get("target_languages") or [])]
        missing = [lg for lg in native if lg not in stored]
        if missing:
            mismatches.append({
                "question_id": rec.get("question_id"),
                "attack_class_anchor": anchor,
                "native_target_languages": native,
                "stored_target_languages": stored,
                "missing_native_languages": missing,
            })
    return mismatches, checked, native_decidable


def load_records(path: Path):
    out = []
    if not path.is_file():
        return out
    for raw in path.read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            out.append(json.loads(raw))
        except json.JSONDecodeError:
            continue
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS),
                        help="hacker_questions_library.jsonl path")
    parser.add_argument("--report", default=str(DEFAULT_REPORT),
                        help="Where to write the JSON mismatch report")
    parser.add_argument("--strict", action="store_true",
                        help=f"Force strict/block mode (same as {STRICT_ENV}=1)")
    parser.add_argument("--no-report", action="store_true",
                        help="Do not write the JSON report (stdout only)")
    args = parser.parse_args()

    strict = bool(args.strict) or _truthy(os.environ.get(STRICT_ENV, ""))
    lib = _load_lib()
    corpus_path = Path(args.corpus)
    records = load_records(corpus_path)
    mismatches, checked, native_decidable = scan_records(records, lib)

    report = {
        "schema": "auditooor.routing_integrity_report.v1",
        "gate": "routing-integrity-check",
        "corpus": str(corpus_path),
        "strict_mode": strict,
        "strict_env": STRICT_ENV,
        "records_checked": checked,
        "records_native_decidable": native_decidable,
        "mismatch_count": len(mismatches),
        "mismatches": mismatches[:2000],
        "advisory_first": True,
    }

    if not args.no_report:
        report_path = Path(args.report)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")

    verdict = "pass-routing-integrity" if not mismatches else (
        "FAIL-routing-integrity" if strict else "WARN-routing-integrity")
    print(json.dumps({
        "verdict": verdict,
        "records_checked": checked,
        "records_native_decidable": native_decidable,
        "mismatch_count": len(mismatches),
        "strict_mode": strict,
        "sample": mismatches[:5],
    }, indent=2, sort_keys=True))

    if mismatches and strict:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
