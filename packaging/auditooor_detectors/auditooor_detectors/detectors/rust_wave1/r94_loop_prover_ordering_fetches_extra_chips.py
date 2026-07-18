"""
r94_loop_prover_ordering_fetches_extra_chips.py

Flags zkVM verifier fns that use a prover-supplied `chip_ordering`
(or equivalent) to enumerate / fetch chips — without cross-checking
that every preprocessed chip's constraint is evaluated. Prover
provides an ordering that excludes some chips, skipping constraint
evaluation on them.

Source: Solodit #63638 (Sherlock Brevis Pico ZKVM).
Class: prover-ordering-fetches-extra-chips (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(verify|verify_shard|verify_program|verify_proof|"
    r"verify_opening|verify_constraints|check_chips|eval_chips)"
)
_USE_ORDERING_RE = re.compile(
    r"(chip_ordering|chip_order|prover_order|chips_ordering)"
    r"\s*(\[|\.\s*iter|\.\s*get|\.\s*contains_key)"
)
# Safe: iterates *all* preprocessed chips independently OR compares
# ordering.len() against preprocessed_chips.len() / expected_chips.
_COMPLETENESS_RE = re.compile(
    fr"(?i)(preprocessed_chips\s*\.\s*iter|"
    fr"all_chips\s*\.\s*iter|"
    fr"assert\w*\s*!?\s*\(\s*{IDENT}ordering\.len\s*\(\s*\)\s*==\s*{IDENT}preprocessed|"
    fr"assert\w*\s*!?\s*\(\s*{IDENT}ordering\.len\s*\(\s*\)\s*==\s*{IDENT}expected_chips|"
    fr"require\s*\(\s*{IDENT}ordering\.length\s*==)"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if not _USE_ORDERING_RE.search(body_nc):
            continue
        if _COMPLETENESS_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` uses prover-supplied `chip_ordering` "
                f"to enumerate chips without verifying it covers all "
                f"preprocessed chips — prover can omit chips to skip "
                f"constraint evaluation (prover-ordering-fetches-extra-chips). "
                f"See Solodit #63638 (Sherlock Brevis Pico ZKVM)."
            ),
        })
    return hits
