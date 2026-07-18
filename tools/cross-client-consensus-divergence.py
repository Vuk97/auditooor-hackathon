#!/usr/bin/env python3
"""
cross-client-consensus-divergence.py  (capability R4-e13)

GENERAL consensus-enforcement screen - NOT a bug-shape detector.

THE INVARIANT (north-star method, applied)
------------------------------------------
Delegated-and-trusted safety property:
    "For every consensus-critical spec rule (state-transition, gas/fee
     schedule, tx-validity predicate, fork-choice, encoding-
     canonicalization) implemented by a client of a SHARED external spec,
     every co-equal implementation agrees byte-for-byte on
     (accept/reject, post-state root, gas-used) for identical input."

The PRIVATE invariant the enforcement leans on:
    "Agreement is only actually ESTABLISHED for a (rule x client-pair)
     cell that is DIFFERENTIALLY EXERCISED - identical input fed to each
     implementation with an equal-post-state assertion. A cell that is
     never differentially exercised is ASSUMED to agree = false-GREEN."

Attack the invariant:
    A consensus-critical rule with no differential exercise is a
    never-enumerated matrix cell. A latent divergence there (a client
    accepts what another rejects, or computes a different post-state root)
    silently persists until an adversary crafts the triggering input, at
    which point the network chain-splits. Anchor: the 2020-11-11 go-
    ethereum vs OpenEthereum mainnet split.

WHAT THIS TOOL DOES (general, impact-agnostic)
----------------------------------------------
1. Enumerates CONSENSUS-CRITICAL RULE SITES in the (non-test) source of a
   root: functions whose file/name matches a fixed consensus-rule-category
   taxonomy (RULE_CATEGORIES). This is the enforcement-point enumeration -
   never a specific bug shape.
2. Enumerates DIFFERENTIAL-EXERCISE evidence: test / testdata / fuzz files
   that constitute a cross-client or shared-external-spec differential
   harness (feed identical input to >=1 implementation and assert an equal
   accept/reject + post-state). Each harness declares the rule CATEGORIES
   it exercises (DIFF_CATEGORY_SIGNALS).
3. Builds the matrix {rule category} x {rule site}: a rule site is
   "differentially exercised" iff some harness exercises its category.
   Every NOT-exercised site -> an advisory cell verdict="needs-fuzz"
   (never-enumerated = false-GREEN). NO auto-credit, NO impact claim.
4. Reports the detected independent client implementations (client-pair
   dimension of the matrix) for context.

ADVISORY-FIRST
--------------
Default: WARN, exit 0, verdict="needs-fuzz" on every emitted cell, never
fail-closed. Strict env AUDITOOOR_CROSS_CLIENT_CONSENSUS_STRICT=1 (or
--strict) makes exit non-zero when >=1 consensus-critical rule x client
cell was never differentially exercised (never-enumerated = false-GREEN),
matching completeness-matrix never-enumerated-cell semantics.

Usage:
    python3 tools/cross-client-consensus-divergence.py --root <dir> [--json]
    python3 tools/cross-client-consensus-divergence.py --root <dir> --strict
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Consensus-critical spec-rule category taxonomy (GENERAL - never a bug shape)
# Each category: signals that a (non-test) source symbol IMPLEMENTS that rule.
#   file_re  - file path signal (any language)
#   fn_re    - function / symbol name signal
# A rule site matches a category if BOTH a file_re-or-fn_re for the category
# fire at the function granularity (fn_re alone qualifies; file_re narrows).
# ---------------------------------------------------------------------------
RULE_CATEGORIES: dict[str, dict[str, str]] = {
    "state-transition": {
        "file_re": r"state[_-]?transition|state[_-]?processor|apply.?tx|"
                   r"execut|deliver.?tx|process.?proposal|abci|endblock|beginblock",
        "fn_re": r"\b(Apply(Message|Transaction|Tx)?|Execute|StateTransition|"
                 r"ProcessProposal|DeliverTx|EndBlock(er)?|BeginBlock(er)?|"
                 r"transition|runTx|finalizeBlock)\b",
    },
    "gas-fee-schedule": {
        "file_re": r"gas|fee|protocol_params|params|intrinsic",
        "fn_re": r"\b(IntrinsicGas|FloorDataGas|BuyGas|gasUsed|calcRefund|"
                 r"returnGas|blobGasUsed|CalcBaseFee|gasCost|feeSchedule|"
                 r"consumeGas)\b",
    },
    "tx-validity": {
        "file_re": r"valid|check|verif|precheck|mempool|ante|admission",
        "fn_re": r"\b(preCheck|StatelessChecks|ValidateBasic|CheckTx|"
                 r"validateAuthorization|validateTx|verifyTx|AnteHandle|"
                 r"acceptTx|rejectTx)\b",
    },
    "fork-choice": {
        "file_re": r"fork|choice|reorg|canonical.?chain|head|finaliz|"
                   r"blockchain|insert.?chain",
        "fn_re": r"\b(forkchoice|ForkChoice|SetHead|reorg|InsertChain|"
                 r"WriteBlockAndSetHead|updateHead|GetCanonicalHash|"
                 r"chooseHead)\b",
    },
    "encoding-canonicalization": {
        "file_re": r"encod|decod|rlp|marshal|unmarshal|serial|codec|ssz|amino",
        "fn_re": r"\b((En|De)codeRLP|Marshal(Binary|JSON)?|Unmarshal(Binary|JSON)?|"
                 r"EncodeToBytes|DecodeBytes|encode|decode|serialize|deserialize)\b",
    },
}

# ---------------------------------------------------------------------------
# Differential-harness signals. A test/testdata file is a DIFFERENTIAL harness
# if it carries a cross-client / shared-external-spec agreement oracle, i.e. it
# feeds identical input to an implementation and asserts an equal accept/reject
# + post-state against a reference (the shared spec fixtures or a peer impl).
# Each signal group declares which rule categories that harness EXERCISES.
# GENERAL - keyed on the differential-oracle idiom, not on any project.
# ---------------------------------------------------------------------------
DIFF_CATEGORY_SIGNALS: list[tuple[str, list[str]]] = [
    # shared-external-spec STATE tests (ethereum/tests StateTests, cosmos
    # abci conformance, etc.): identical input -> equal post-state root +
    # equal accept/reject exercises the whole state-transition trio.
    (r"StateTest|StateTests|state[_-]?test|statetests|post[_-]?state|"
     r"ExpectException|postStateRoot|expectedRoot",
     ["state-transition", "gas-fee-schedule", "tx-validity"]),
    # shared-external-spec BLOCK / consensus tests: full block import +
    # fork-choice + wire encoding.
    (r"BlockTest|BlockTests|block[_-]?test|blocktests|forkchoice|"
     r"fork[_-]?choice|consensus[_-]?test|conformance",
     ["fork-choice", "state-transition", "encoding-canonicalization"]),
    # explicit cross-client / peer-implementation differential harness.
    (r"cross[_-]?client|differential|two[_-]?impl|reference[_-]?impl(ementation)?|"
     r"peer[_-]?impl|golden[_-]?vector|spec[_-]?vector",
     ["state-transition", "gas-fee-schedule", "tx-validity",
      "fork-choice", "encoding-canonicalization"]),
    # encoding round-trip / canonicalization differential.
    (r"round[_-]?trip|canonical|rlp[_-]?test|encode.*decode|marshal.*unmarshal|"
     r"ssz[_-]?test|amino[_-]?test",
     ["encoding-canonicalization"]),
    # gas / fee schedule conformance vectors.
    (r"gas[_-]?test|intrinsic[_-]?gas|fee[_-]?schedule|gas[_-]?vector|"
     r"gasUsed.*expect",
     ["gas-fee-schedule"]),
]

# Any of these makes a path a TEST/harness path (so it is excluded from
# rule-site enumeration and considered as differential-harness evidence).
_TEST_PATH_RE = re.compile(
    r"(^|/)(test|tests|testdata|testutil|conformance|differential[_-]?fuzz|"
    r"fuzz|vectors|golden)(/|$)|_test\.(go|rs|py|sol|ts|js)$|\.t\.sol$",
    re.IGNORECASE,
)

_SRC_EXT = {".go", ".rs", ".sol", ".ts", ".js", ".py", ".c", ".cpp", ".cc"}

# Function-definition patterns per extension family (general, best-effort).
_FN_DEF_RE = re.compile(
    r"^\s*(?:pub\s+|pub\(crate\)\s+)?(?:async\s+)?"
    r"(?:func|fn|def|function)\s+"
    r"(?:\([^)]*\)\s*)?"          # go receiver
    r"([A-Za-z_][A-Za-z0-9_]*)",  # captured name
    re.MULTILINE,
)
# Solidity `function name(` form (no leading func/fn keyword variant above).
_SOL_FN_RE = re.compile(r"^\s*function\s+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE)

_SKIP_DIRS = {".git", "node_modules", "vendor", "target", "build", "dist",
              ".auditooor", "prior_audits", "agent_outputs"}

# Compile category regexes once.
_CAT_FILE = {c: re.compile(d["file_re"], re.IGNORECASE)
             for c, d in RULE_CATEGORIES.items()}
_CAT_FN = {c: re.compile(d["fn_re"]) for c, d in RULE_CATEGORIES.items()}
_DIFF_SIG = [(re.compile(pat, re.IGNORECASE), cats)
             for pat, cats in DIFF_CATEGORY_SIGNALS]


# ---------------------------------------------------------------------------
# Core primitives (load-bearing predicates - test neutralizes these).
# ---------------------------------------------------------------------------
def _is_test_path(rel_path: str) -> bool:
    return bool(_TEST_PATH_RE.search(rel_path))


def _classify_rule_site(rel_path: str, fn_name: str) -> str | None:
    """Return the consensus-rule category a (file, fn) implements, or None.

    LOAD-BEARING: the enforcement-point enumerator. A hit needs the function
    name to match a category's fn_re (the strong signal); the file_re only
    disambiguates when several fn categories could match.
    """
    matched = [c for c, rgx in _CAT_FN.items() if rgx.search(fn_name)]
    if not matched:
        return None
    if len(matched) == 1:
        return matched[0]
    # tie-break by file signal
    for c in matched:
        if _CAT_FILE[c].search(rel_path):
            return c
    return matched[0]


def _harness_exercised_categories(text: str) -> set[str]:
    """Categories a differential-harness file exercises (empty = not a diff harness)."""
    cats: set[str] = set()
    for rgx, sig_cats in _DIFF_SIG:
        if rgx.search(text):
            cats.update(sig_cats)
    return cats


def _category_is_exercised(category: str, exercised: set[str]) -> bool:
    """LOAD-BEARING core predicate: is this rule category differentially exercised?

    Neutralizing this (always-True) makes every rule site count as covered and
    the screen stops firing - the non-vacuity anchor.
    """
    return category in exercised


# ---------------------------------------------------------------------------
# Enumeration
# ---------------------------------------------------------------------------
def _iter_source_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.suffix.lower() in _SRC_EXT:
                yield p


def _extract_functions(text: str, suffix: str) -> list[str]:
    names = set(m.group(1) for m in _FN_DEF_RE.finditer(text))
    if suffix == ".sol":
        names.update(m.group(1) for m in _SOL_FN_RE.finditer(text))
    return sorted(names)


def _detect_client_impls(root: Path, rule_files: list[str]) -> list[str]:
    """Independent client implementations = distinct top-level module roots that
    each carry consensus-critical rule sites. General heuristic for the client-
    pair matrix dimension; never gates firing."""
    tops: set[str] = set()
    for rf in rule_files:
        parts = Path(rf).parts
        tops.add(parts[0] if parts else rf)
    return sorted(tops)


def scan(root: str):
    """Screen a source root. Returns (cells, accounting).

    cells: one advisory dict per consensus-critical rule site that is NOT
    differentially exercised (verdict="needs-fuzz"). Silent (no cell) when the
    site's category is exercised by a differential harness.
    """
    root_p = Path(root).resolve()
    rule_sites: list[dict] = []          # every consensus-critical rule site
    rule_files: set[str] = set()
    exercised: set[str] = set()          # union of categories exercised by harnesses
    harnesses: list[dict] = []

    for p in _iter_source_files(root_p):
        try:
            rel = str(p.relative_to(root_p))
        except ValueError:
            rel = str(p)
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        if _is_test_path(rel):
            cats = _harness_exercised_categories(text)
            if cats:
                exercised.update(cats)
                harnesses.append({"file": rel, "exercises": sorted(cats)})
            continue  # test files are never rule SITES

        for fn in _extract_functions(text, p.suffix.lower()):
            cat = _classify_rule_site(rel, fn)
            if cat:
                rule_sites.append({"file": rel, "fn": fn, "category": cat})
                rule_files.add(rel)

    client_impls = _detect_client_impls(root_p, sorted(rule_files))

    cells: list[dict] = []
    for site in rule_sites:
        if not _category_is_exercised(site["category"], exercised):
            cells.append({
                "file": site["file"],
                "fn": site["fn"],
                "rule_category": site["category"],
                "client_impls": client_impls,
                "verdict": "needs-fuzz",
                "reason": "consensus-critical rule site with no differential "
                          "cross-client / shared-spec exercise (never-enumerated "
                          "matrix cell = false-GREEN)",
                "invariant": "every consensus-critical (rule x client-pair) cell "
                             "is differentially exercised for equal accept/reject "
                             "+ post-state",
                "auto_credit": False,
            })

    # never-enumerated categories = categories present in source but never in
    # any differential harness (the strongest false-GREEN signal).
    present_cats = sorted({s["category"] for s in rule_sites})
    never_exercised_cats = sorted(c for c in present_cats
                                  if not _category_is_exercised(c, exercised))

    accounting = {
        "root": str(root_p),
        "rule_sites": len(rule_sites),
        "rule_files": len(rule_files),
        "differential_harnesses": len(harnesses),
        "categories_present": present_cats,
        "categories_exercised": sorted(exercised & set(present_cats)),
        "categories_never_exercised": never_exercised_cats,
        "client_impls_detected": client_impls,
        "needs_fuzz_cells": len(cells),
        "advisory_first": True,
    }
    return cells, accounting, harnesses


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _strict_enabled(args) -> bool:
    return bool(args.strict) or os.environ.get(
        "AUDITOOOR_CROSS_CLIENT_CONSENSUS_STRICT", "") not in ("", "0", "false")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="R4 cross-client consensus-divergence screen (advisory-first).")
    ap.add_argument("--root", required=True, help="source root to screen")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--strict", action="store_true",
                    help="fail-close on any never-enumerated consensus cell "
                         "(also AUDITOOOR_CROSS_CLIENT_CONSENSUS_STRICT=1)")
    args = ap.parse_args()

    if not Path(args.root).exists():
        print(f"ERROR: root not found: {args.root}", file=sys.stderr)
        return 2

    cells, acc, harnesses = scan(args.root)

    # Advisory sidecar for the hunt corpus (folded by auto-coverage-closer's
    # NETNEW_ADVISORY list) when run over a directory root: JSONL, one
    # needs-fuzz / no-auto-credit row per divergence cell, under <root>/.auditooor/.
    _root_p = Path(args.root)
    if _root_p.is_dir():
        _sd = _root_p / ".auditooor"
        _sd.mkdir(parents=True, exist_ok=True)
        with open(_sd / "cross_client_consensus_divergence_hypotheses.jsonl", "w", encoding="utf-8") as _sf:
            for _c in (cells or []):
                _row = _c if isinstance(_c, dict) else {"cell": _c}
                _sf.write(json.dumps({
                    **_row, "capability": "R4",
                    "verdict": "needs-fuzz", "advisory": True, "auto_credit": False,
                }) + "\n")

    if args.json:
        print(json.dumps(
            {"accounting": acc, "cells": cells, "harnesses": harnesses},
            indent=2))
    else:
        print("== R4 cross-client consensus-divergence screen (ADVISORY) ==")
        print(f"root                    : {acc['root']}")
        print(f"rule sites              : {acc['rule_sites']} "
              f"across {acc['rule_files']} files")
        print(f"differential harnesses  : {acc['differential_harnesses']}")
        print(f"client impls detected   : {acc['client_impls_detected']}")
        print(f"categories present      : {acc['categories_present']}")
        print(f"categories exercised    : {acc['categories_exercised']}")
        print(f"categories NEVER exerc. : {acc['categories_never_exercised']}")
        print(f"needs-fuzz cells        : {acc['needs_fuzz_cells']}")
        for c in cells:
            print(f"  [needs-fuzz] {c['rule_category']:26s} "
                  f"{c['file']}::{c['fn']}")

    strict = _strict_enabled(args)
    if strict and cells:
        print(f"\nSTRICT: {len(cells)} consensus-critical rule x client cell(s) "
              f"never differentially exercised (never-enumerated = false-GREEN).",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
