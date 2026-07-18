"""
r94_loop_oracle_confidence_negative_accept.py

Flags Pyth/oracle consumers that compare a new price fluctuation to
a confidence interval with a SIGNED comparison `>` / `<` (allowing
negative deviations to slip through) instead of an ABSOLUTE-value
comparison.

Source: Solodit #53212 (OtterSec Exponent Generic Standard).
Class: oracle-confidence-negative-accept (both).

Heuristic:
  1. Body mentions `pyth`, `conf`, `confidence`, `PriceFeed`.
  2. Body has an expression like `delta > conf` / `(new - old) > conf`
     without `.abs()`, `abs(`, `saturating_abs`, or i256 sign check.
"""

from __future__ import annotations

import re

from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)


_ORACLE_CTX_RE = re.compile(
    r"pyth|\bconf\b|\bconfidence\b|PriceFeed|price_\w*\.conf|\.confidence"
)

_DELTA_COMPARE_RE = re.compile(
    r"(\w+\s*-\s*\w+)\s*[<>]\s*\w+\s*\.\s*conf|"
    r"(new_\w+\s*-\s*current_\w+)\s*[<>]|"
    r"delta\s*[<>]\s*\w+|"
    r"\b(deviation|diff)\s*[<>]\s*\w+"
)

_ABS_RE = re.compile(
    r"\.abs\s*\(|abs\s*\(\s*\w|saturating_abs|checked_abs|\.unsigned_abs"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    for fn, _impl in functions_in_contractimpl(root, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)

        if not _ORACLE_CTX_RE.search(body_nc):
            continue
        if not _DELTA_COMPARE_RE.search(body_nc):
            continue
        if _ABS_RE.search(body_nc):
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "medium",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` compares an oracle price delta to the "
                f"confidence interval with a signed `>` / `<` but no "
                f"`.abs()`. Negative deviations (current − new > 0) slip "
                f"through and skew the index. See Solodit #53212 (Exponent)."
            ),
        })
    return hits
