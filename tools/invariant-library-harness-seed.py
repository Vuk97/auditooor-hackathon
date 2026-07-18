#!/usr/bin/env python3
"""
invariant-library-harness-seed.py - corpus-fed runnable-oracle CANDIDATE seeder.

Problem
=======
The corpus invariant library (audit/corpus_tags/derived/invariants_pilot_audited.jsonl
+ invariants_extracted.jsonl, ~1394 records) is PROSE-only: 0 records carry a
harness_target / predicate / executable_predicate / negative_test field. The
existing planners only ever consume a per-workspace exploit_queue.json, never the
corpus library, so a corpus invariant has no path to becoming a runnable oracle:

  - tools/invariant-harness-planner.py (choose_harness_family ~line 157) reads the
    per-workspace ledger.
  - tools/exploit-queue-to-invariant-ledger.py reads exploit_queue.json.

This tool adds the missing CORPUS-fed path. For every corpus invariant it attaches:

  - harness_family       mapped from the invariant `category`
                         (conservation -> balance-sum-invariant,
                          custody       -> no-unauthorized-transfer,
                          atomicity      -> no-double-spend,
                          freshness      -> monotonic-state,
                          authorization  -> access-gate,
                          ... plus a small extended map; else needs-human)
  - predicate_sketch     a checkable assertion TEMPLATE derived from `statement`
                         + `commit_point_pattern`.
  - negative_test_sketch the mutation that BREAKS the invariant.
  - verification_tier    UNCHANGED (the corpus provenance tier is preserved).
  - execution_status     NEW field = 'planned'.

HONESTY (hard, R80)
===================
These are PLANNED oracle CANDIDATES, not mutation-verified harnesses. A
predicate_sketch is a template string; a negative_test_sketch names a mutation
in prose. NOTHING here has been compiled, executed, or mutation-verified. The
execution_status is therefore the literal string 'planned' for every emitted
record. A later harness-author / fuzz run is what MATERIALIZES a candidate into a
mutation-verified harness; only that run may flip execution_status onward. This
tool never claims a pass it did not observe.

Output
======
    audit/corpus_tags/derived/invariant_runnable_plans.jsonl

CLI
===
    python3 tools/invariant-library-harness-seed.py
    python3 tools/invariant-library-harness-seed.py --limit 5
    python3 tools/invariant-library-harness-seed.py --out /tmp/plans.jsonl
    python3 tools/invariant-library-harness-seed.py --category conservation

Discipline
----------
- stdlib-only.
- Idempotent: re-running on an unchanged corpus produces byte-identical output
  (records emitted in corpus-read order, sorted keys per record).
- Heuristic, not magic. An unmapped category yields harness_family 'needs-human'
  with a precise reason and execution_status still 'planned'.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

SCHEMA_VERSION = "auditooor.invariant_runnable_plan.v1"

# The two prose-only corpus libraries, relative to repo root.
DEFAULT_CORPUS = (
    "audit/corpus_tags/derived/invariants_pilot_audited.jsonl",
    "audit/corpus_tags/derived/invariants_extracted.jsonl",
)
DEFAULT_OUT = "audit/corpus_tags/derived/invariant_runnable_plans.jsonl"

# ---------------------------------------------------------------------------
# Category -> harness family map (the SPEC-mandated five, plus a small
# extension table for the long tail; anything unmapped -> needs-human).
# ---------------------------------------------------------------------------
CATEGORY_HARNESS_FAMILY: Dict[str, str] = {
    "conservation": "balance-sum-invariant",
    "custody": "no-unauthorized-transfer",
    "atomicity": "no-double-spend",
    "freshness": "monotonic-state",
    "authorization": "access-gate",
    # ---- extended map (best-effort; still 'planned' candidates) ----
    "ordering": "monotonic-state",
    "uniqueness": "no-double-spend",
    "monotonicity": "monotonic-state",
    "bounds": "balance-sum-invariant",
    "determinism": "no-double-spend",
}

# A short prose template per harness family, used to build the predicate sketch.
# {stmt} = the corpus statement (trimmed), {commit} = commit_point_pattern.
FAMILY_PREDICATE_TEMPLATE: Dict[str, str] = {
    "balance-sum-invariant": (
        "assert(sum(component_balances_after) == sum(component_balances_before)); "
        "// at commit point: {commit} ; property: {stmt}"
    ),
    "no-unauthorized-transfer": (
        "assert(transfer.caller == authorized_custodian(transfer.asset)); "
        "// at commit point: {commit} ; property: {stmt}"
    ),
    "no-double-spend": (
        "assert(spent_set.insert(spend_id) == NEWLY_INSERTED); "
        "// at commit point: {commit} ; property: {stmt}"
    ),
    "monotonic-state": (
        "assert(state_after.seq >= state_before.seq && "
        "state_after.freshness_ok()); // at commit point: {commit} ; property: {stmt}"
    ),
    "access-gate": (
        "assert(access_gate(caller, action) == ALLOWED before side_effect); "
        "// at commit point: {commit} ; property: {stmt}"
    ),
    "needs-human": (
        "// NO MAPPED PREDICATE: operator must hand-author the assertion. "
        "commit point: {commit} ; property: {stmt}"
    ),
}

# The mutation that BREAKS each family's invariant (the negative test).
FAMILY_NEGATIVE_TEMPLATE: Dict[str, str] = {
    "balance-sum-invariant": (
        "MUTATION: skip/short one leg of the transfer (credit without debit) so "
        "sum(after) != sum(before); the predicate MUST fail."
    ),
    "no-unauthorized-transfer": (
        "MUTATION: invoke the transfer from an unauthorized caller / module "
        "account; the access check MUST reject it."
    ),
    "no-double-spend": (
        "MUTATION: replay the same spend_id / nullifier twice in one or two txs; "
        "the second insert MUST be rejected as already-spent."
    ),
    "monotonic-state": (
        "MUTATION: feed a stale / lower-sequence (pre-fork) state or proof; the "
        "freshness/monotonicity guard MUST reject it."
    ),
    "access-gate": (
        "MUTATION: call the gated entry point from a non-admin / non-owner caller "
        "(or before role assignment); the gate MUST deny the side effect."
    ),
    "needs-human": (
        "MUTATION: operator must hand-author the breaking mutation for this "
        "unmapped category."
    ),
}


def _trim(s: Optional[str], n: int = 200) -> str:
    if not isinstance(s, str):
        return ""
    s = " ".join(s.split())
    return s if len(s) <= n else (s[: n - 3] + "...")


def choose_corpus_harness_family(row: Dict[str, Any]) -> Tuple[str, str]:
    """Map a corpus invariant's `category` to a runnable-oracle harness family.

    Returns (harness_family, reason). Unmapped category -> ('needs-human', ...).
    """
    cat = (row.get("category") or "").strip().lower()
    fam = CATEGORY_HARNESS_FAMILY.get(cat)
    if fam is not None:
        return (
            fam,
            f"corpus category {cat!r} maps to harness family {fam!r}.",
        )
    return (
        "needs-human",
        f"corpus category {cat!r} has no harness-family mapping; "
        f"operator must pick a family before this candidate is materializable.",
    )


def build_predicate_sketch(row: Dict[str, Any], family: str) -> str:
    """A checkable assertion TEMPLATE derived from statement + commit_point_pattern.

    This is a SKETCH, not executable code: it names the assertion shape and the
    commit point where it should fire. A later harness-author run turns it into a
    real harness.
    """
    tmpl = FAMILY_PREDICATE_TEMPLATE.get(family, FAMILY_PREDICATE_TEMPLATE["needs-human"])
    return tmpl.format(
        stmt=_trim(row.get("statement"), 160),
        commit=_trim(row.get("commit_point_pattern"), 120) or "UNSPECIFIED",
    )


def build_negative_test_sketch(row: Dict[str, Any], family: str) -> str:
    """The mutation that BREAKS the invariant (a prose sketch, not code)."""
    return FAMILY_NEGATIVE_TEMPLATE.get(
        family, FAMILY_NEGATIVE_TEMPLATE["needs-human"]
    )


def seed_record(row: Dict[str, Any], source_file: str) -> Dict[str, Any]:
    """Build one runnable-oracle CANDIDATE record from a corpus invariant.

    execution_status is ALWAYS the literal 'planned' (R80 honesty): a sketch is
    not a mutation-verified harness.
    """
    family, reason = choose_corpus_harness_family(row)
    return {
        "schema_version": SCHEMA_VERSION,
        "invariant_id": row.get("invariant_id"),
        "category": row.get("category"),
        "source_corpus_file": source_file,
        # verification_tier is PRESERVED, unchanged, from the corpus provenance.
        "verification_tier": row.get("verification_tier"),
        "harness_family": family,
        "harness_family_reason": reason,
        "predicate_sketch": build_predicate_sketch(row, family),
        "negative_test_sketch": build_negative_test_sketch(row, family),
        # NEW field. Honest: these are PLANNED candidates, never observed-pass.
        "execution_status": "planned",
        "statement": _trim(row.get("statement"), 240),
        "commit_point_pattern": row.get("commit_point_pattern"),
        "target_lang": row.get("target_lang"),
    }


def iter_corpus(paths: Iterable[Path]) -> Iterable[Tuple[str, Dict[str, Any]]]:
    for p in paths:
        if not p.exists():
            continue
        rel = p.name
        with p.open() as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield rel, json.loads(line)
                except json.JSONDecodeError:
                    continue


def seed_plans(
    corpus_paths: List[Path],
    category: Optional[str] = None,
    limit: Optional[int] = None,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for source_file, row in iter_corpus(corpus_paths):
        if category and (row.get("category") or "").strip().lower() != category.lower():
            continue
        out.append(seed_record(row, source_file))
        if limit is not None and len(out) >= limit:
            break
    return out


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    repo_root = Path(__file__).resolve().parents[1]
    ap.add_argument(
        "--corpus",
        nargs="*",
        default=[str(repo_root / p) for p in DEFAULT_CORPUS],
        help="corpus jsonl files (default: the two prose-only invariant libraries)",
    )
    ap.add_argument(
        "--out",
        default=str(repo_root / DEFAULT_OUT),
        help="output jsonl path (default: invariant_runnable_plans.jsonl)",
    )
    ap.add_argument("--category", default=None, help="filter to one category")
    ap.add_argument("--limit", type=int, default=None, help="cap emitted records")
    ap.add_argument(
        "--stdout",
        action="store_true",
        help="print plans to stdout instead of writing --out",
    )
    args = ap.parse_args(argv)

    corpus_paths = [Path(p) for p in args.corpus]
    plans = seed_plans(corpus_paths, category=args.category, limit=args.limit)

    lines = [json.dumps(p, sort_keys=True) for p in plans]
    body = "\n".join(lines) + ("\n" if lines else "")

    if args.stdout:
        sys.stdout.write(body)
    else:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(body)

    planned = sum(1 for p in plans if p["execution_status"] == "planned")
    needs_human = sum(1 for p in plans if p["harness_family"] == "needs-human")
    sys.stderr.write(
        f"invariant-library-harness-seed: {len(plans)} runnable-oracle CANDIDATES "
        f"(execution_status=planned: {planned}; needs-human family: {needs_human}). "
        f"NOTE: planned != mutation-verified; a later harness-author run materializes.\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
