"""
liquidation_close_factor_off_by_one.py

Flags liquidation functions where a close-factor or health-factor boundary
uses a strict `<` / `>` instead of `<=` / `>=`, causing dust-amount drift
and boundary-case livelocks.

Heuristic:
  - Function whose name contains `liquidat` or `close`.
  - Body contains a comparison involving an identifier matching
    `close_factor`, `CLOSE_FACTOR`, `health_factor`, `hf`, or the literal
    `5000` (Aave 50% bps default).
  - The comparison operator on that identifier is STRICT (`<` or `>`) —
    we flag because the author likely meant `<=` / `>=`.
  - If BOTH strict and non-strict variants appear (defensive double-check)
    we stay silent to avoid flagging intentional dual-guards.

Maps to corpus: 4 Aave / Compound bug reports about close-factor off-by-one
causing dust accumulation / undercollateralized liquidation bypass.
"""

from __future__ import annotations

import re

from _util import (
    function_items, fn_body, fn_name, text_of, line_col, snippet_of,
    in_test_cfg,
)


_LIQ_NAME_RE = re.compile(r"(liquidat|^close_|close_position)", re.IGNORECASE)

# Tokens we consider "boundary-sensitive" for liquidations.
_BOUNDARY_IDENTS = (
    "close_factor", "CLOSE_FACTOR", "closeFactor",
    "health_factor", "HEALTH_FACTOR", "healthFactor",
    "\\bhf\\b", "\\bHF\\b",
    "liquidation_threshold", "LIQUIDATION_THRESHOLD",
)

# 50%-bps and 1e18 HF thresholds commonly used
_BOUNDARY_LITERALS = (r"\b5000\b", r"\b1e18\b", r"1_000_000_000_000_000_000")


def _find_strict_comparisons(body_text: str, ident_pat: str) -> list[tuple[int, str]]:
    """Return list of (line_index, matched_expr) for strict comparisons
    involving ident_pat.  We use a 1-line window, which is fine for typical
    rust code."""
    out = []
    # Strict `<` not followed by `=` ; same for `>`
    for i, ln in enumerate(body_text.splitlines()):
        if not re.search(ident_pat, ln):
            continue
        # ignore line-comments
        code = ln.split("//", 1)[0]
        # Strict LT: `<` followed by non-`=` non-`<`
        if re.search(r"(?<![<=!])<(?![=<])", code) and not re.search(
                r"<=", code):
            out.append((i, code.strip()))
            continue
        if re.search(r"(?<![>=!])>(?![=>])", code) and not re.search(
                r">=", code):
            out.append((i, code.strip()))
    return out


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        name = fn_name(fn, source)
        if not _LIQ_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_text = text_of(body, source)

        # Identify at least one boundary identifier / literal
        combined_pat = "|".join(_BOUNDARY_IDENTS + _BOUNDARY_LITERALS)
        if not re.search(combined_pat, body_text):
            continue

        strict_hits = _find_strict_comparisons(body_text, combined_pat)
        if not strict_hits:
            continue
        # Defensive dual-guard: if any `<=` or `>=` over the same ident
        # appears in the body, stay silent.
        if re.search(r"(<=|>=)", body_text) and re.search(
                r"(" + combined_pat + r")[^\n]*(<=|>=)", body_text):
            continue

        line_base, col = line_col(fn)
        # Approximate actual line of first strict hit:
        first_i, first_expr = strict_hits[0]
        line = line_base + first_i + 1  # fn line already 1-based

        hits.append({
            "severity": "medium",
            "line": line,
            "col": col,
            "snippet": first_expr[:160],
            "message": (
                f"fn `{name}` uses strict `<` / `>` against a "
                f"close-factor / health-factor boundary — consider `<=` / `>=` "
                f"to avoid dust-amount drift at the boundary."
            ),
        })
    return hits
