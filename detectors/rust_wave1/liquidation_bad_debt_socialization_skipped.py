"""
liquidation_bad_debt_socialization_skipped.py

When a liquidation runs and the borrower's collateral value is less than
their debt (bad-debt), the remaining deficit must be socialized — written
to a bad-debt accumulator, sent to a treasury/insurance fund, or the
protocol silently takes a loss.

Heuristic:
  1. Function name contains `liquidat`.
  2. Body contains a branch comparing `collateral` with `debt` where
     `collateral < debt` or `debt > collateral`.
  3. Inside that branch, the body does NOT call any of:
        socialize_debt / accumulate_bad_debt / treasury.absorb_loss /
        record_bad_debt / insurance_fund / bad_debt.set
     AND does not revert (panic_with_error, panic!, return Err).

Maps to corpus: 15+ Aave/Compound/Silo findings where bad debt silently
accumulates.
"""

from __future__ import annotations

import re

from _util import (
    function_items, fn_body, fn_name, text_of, walk_no_nested_fn,
    line_col, snippet_of, in_test_cfg,
)


_LIQ_RE = re.compile(r"liquidat", re.IGNORECASE)

_BAD_DEBT_BRANCH_PATTERNS = (
    r"collateral\s*<\s*debt",
    r"debt\s*>\s*collateral",
    r"collateral_value\s*<\s*debt_value",
    r"seized\s*<\s*debt",
    r"actual\w*\s*<\s*debt",
)

_SOCIALIZE_TOKENS = (
    "socialize_debt", "accumulate_bad_debt", "absorb_loss",
    "record_bad_debt", "insurance_fund", "bad_debt", "bad_debt_fund",
    "record_deficit", "deficit_fund", "record_loss", "treasury",
)

_REVERT_TOKENS = ("panic_with_error", "panic!", "return Err")


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        name = fn_name(fn, source)
        if not _LIQ_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_text = text_of(body, source)

        # Must have a branch comparing collateral < debt
        matched_branch = None
        for pat in _BAD_DEBT_BRANCH_PATTERNS:
            m = re.search(pat, body_text)
            if m:
                matched_branch = (pat, m)
                break
        if matched_branch is None:
            continue

        # Branch exists — does the body handle it?
        if any(tok in body_text for tok in _SOCIALIZE_TOKENS):
            continue
        # Does the branch revert immediately?
        # crude check: does a revert token exist in the body?
        if any(tok in body_text for tok in _REVERT_TOKENS):
            # more nuanced — require the revert to be in SAME 200 chars after
            # the branch match
            bstart = matched_branch[1].start()
            window = body_text[bstart:bstart + 250]
            if any(tok in window for tok in _REVERT_TOKENS):
                continue

        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": matched_branch[1].group(0),
            "message": (
                f"fn `{name}` compares collateral < debt but never socializes "
                f"the deficit (no bad-debt accumulator / treasury / insurance "
                f"call) — silent protocol loss."
            ),
        })
    return hits
