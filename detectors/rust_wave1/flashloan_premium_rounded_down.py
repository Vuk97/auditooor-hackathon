"""
flashloan_premium_rounded_down.py

Flags flash-loan premium / fee calculations that use floor division
(`amount * fee_bps / BASIS_POINTS`) instead of ceil division, OR that use
the half-even rounding helper (`percent_mul`) where the rounding-up
variant (`percent_mul_up` / `percent_mul_ceil`) is required for fees owed
TO the protocol.

Heuristic:
  1. Function name contains `flash` OR `premium` OR `fee`.
  2. Body contains an expression matching
        `<amount_ident> * <bps_ident> / <denom_ident>`
     where `<denom_ident>` looks like BASIS_POINTS / 10_000 / BPS_SCALE /
     WAD.
  3. Same fn does NOT contain the ceil pattern
        `(... + DENOM - 1) / DENOM`
     and does NOT call a `_ceil` / `_up` helper.

OR:
  4. Body calls `percent_mul(` WITHOUT a paired `percent_mul_up` /
     `percent_mul_ceil` call — flag as potential floor-bias bug.
"""

from __future__ import annotations

import re

from _util import (
    function_items, fn_body, fn_name, text_of, line_col, snippet_of,
    in_test_cfg,
)


_FN_NAME_RE = re.compile(r"(flash|premium|fee)", re.IGNORECASE)

_FLOOR_MUL_DIV_RE = re.compile(
    r"([A-Za-z_][A-Za-z_0-9]*)\s*\*\s*([A-Za-z_][A-Za-z_0-9]*)\s*/\s*"
    r"(BASIS_POINTS|BPS_SCALE|10_000|10000|WAD|RAY|PERCENTAGE_FACTOR)"
)

_CEIL_TOKENS = (
    "ceil", "_up", "saturating_add", "checked_add", "round_up",
    "+ 1) / ", "- 1) / ",
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_text = text_of(body, source)

        # Pattern 1: floor mul-div
        for m in _FLOOR_MUL_DIV_RE.finditer(body_text):
            # Skip if ceil pattern is present in same 120-char window
            start = max(0, m.start() - 120)
            end = min(len(body_text), m.end() + 120)
            window = body_text[start:end]
            if any(tok in window for tok in _CEIL_TOKENS):
                continue
            # Build approximate line
            before = body_text[:m.start()]
            line_offset = before.count("\n")
            fn_line, col = line_col(fn)
            hits.append({
                "severity": "medium",
                "line": fn_line + line_offset,
                "col": col,
                "snippet": m.group(0),
                "message": (
                    f"fn `{name}` computes `{m.group(1)} * {m.group(2)} / "
                    f"{m.group(3)}` with floor division — flash-loan "
                    f"premium owed TO the protocol should round UP "
                    f"(`+ DENOM - 1) / DENOM`)."
                ),
            })

        # Pattern 2: percent_mul (half-even) without ceil variant
        if re.search(r"\bpercent_mul\s*\(", body_text) and \
                not re.search(r"percent_mul_(up|ceil)", body_text):
            # only flag when this fn is named like premium/fee/flash
            fn_line, col = line_col(fn)
            hits.append({
                "severity": "medium",
                "line": fn_line,
                "col": col,
                "snippet": snippet_of(fn, source, 200),
                "message": (
                    f"fn `{name}` uses `percent_mul` (half-even rounding) "
                    f"for a premium/fee computation — prefer "
                    f"`percent_mul_up` / `_ceil` so the protocol never "
                    f"under-charges."
                ),
            })
    return hits
