"""
rust_block_depth_toctou_u32_underflow.py

Flags functions that compute a block depth or confirmation count by:

  (1) Calling a `tip_height`-like function to read the chain tip height,
  (2) Separately calling a transaction/block lookup function to obtain a
      target block's `height` value (the two reads are not protected by a
      consistent snapshot lock),
  (3) Subtracting the two `u32` `.0` fields with bare arithmetic
      (`1 + tip.0 - height.0`) without a `checked_sub` / `saturating_sub`
      guard.

Between the two reads a chain reorganization can retract the tip, making
`height.0 > tip.0`, which causes u32 underflow (wraps to ~2^32) and produces
a wildly incorrect confirmation count that propagates to callers (wallet
display, RPC responses, finality decisions).

The comment phrase "it is ok to do this lookup in two different calls" or
"two separate calls" is the canonical author acknowledgement of the TOCTOU
race; its presence is required to keep the detector tight (it is a
distinguishing marker of the zebra pattern class and avoids FPs from other
u32 depth computations that do not involve a separate tip lookup).

Real surface confirmed:
  zebra-state/src/service/read/block.rs  fn mined_transaction   line ~156
  zebra-state/src/service/read/block.rs  fn any_transaction     line ~197

  Both match: `1 + tip_height(...).?.0 - height.0` with the author comment.
  See https://github.com/ZcashFoundation/zebra/issues/10470

Severity: HIGH
Rubric: Non-distributed DoS against an individual node or wallet.
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    in_test_cfg,
    line_col,
    snippet_of,
    text_of,
    walk_no_nested_fn,
    IDENT,
)

# ---------------------------------------------------------------------------
# Signal 1 - bare u32 depth / confirmation arithmetic
# Matches the canonical shape:  1 + <something>.0 - <something_else>.0
# The `.0` tuple-field accessor is how zebra unwraps the Height(u32) newtype.
# The tip-height expression can include function-call syntax and the `?`
# propagation operator, e.g. `tip_height(chain, db)?.0`, so we allow any
# non-dash, non-newline characters between `1 +` and the first `.0 -`.
# ---------------------------------------------------------------------------
_DEPTH_ARITH_RE = re.compile(
    r"1\s*\+\s*[^\n\-]+\.0\s*-\s*[\w\.]+\.0"
)

# ---------------------------------------------------------------------------
# Signal 2 - tip-height call within the same function body
# The function must call a function whose name contains "tip_height" or
# "chain_tip_height" or "best_tip_height" (common naming for chain tip reads).
# ---------------------------------------------------------------------------
_TIP_HEIGHT_CALL_RE = re.compile(
    r"\btip_height\s*\("
)

# ---------------------------------------------------------------------------
# Signal 3 - author TOCTOU acknowledgement comment
# This is the key FP-reduction anchor: the comment pattern that explicitly
# says the two reads are intentionally separate but does NOT protect the
# subsequent arithmetic.  We match the raw source (including comments) for
# this signal, since we specifically WANT to find the comment.
# ---------------------------------------------------------------------------
_TOCTOU_COMMENT_RE = re.compile(
    r"(?:two\s+(?:separate|different)\s+calls|lookup\s+in\s+(?:two|multiple)\s+different\s+calls)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Safety guards - if ANY of these are present in the body, the arithmetic is
# protected and we skip the function.
# ---------------------------------------------------------------------------
_GUARD_PATTERNS = [
    # checked_sub / saturating_sub applied to any height-related subtraction
    r"\bchecked_sub\s*\(",
    r"\bsaturating_sub\s*\(",
    # cast to signed type before subtraction (i32, i64, i128)
    r"as\s+i(?:32|64|128)\s*\)",
    # explicit >= comparison guarding the subtraction
    r"tip(?:_height)?\s*[\.\w]*\.0\s*>=\s*height(?:_height)?\s*[\.\w]*\.0",
    r"height(?:_height)?\s*[\.\w]*\.0\s*<=\s*tip(?:_height)?\s*[\.\w]*\.0",
    # HeightDiff type (the proper zebra wrapper for signed height differences)
    r"\bHeightDiff\b",
]
_GUARD_RES = [re.compile(p, re.IGNORECASE) for p in _GUARD_PATTERNS]


def _has_arithmetic_guard(body_text: str) -> bool:
    return any(g.search(body_text) for g in _GUARD_RES)


def run(tree, source: bytes, filepath: str) -> list[dict]:
    hits = []
    # Decode full source (including comments) once for signal 3
    full_source_text = source.decode("utf-8", errors="replace")

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        # Signal 2: must call tip_height somewhere in this function body
        body_with_comments = text_of(body, source)
        if not _TIP_HEIGHT_CALL_RE.search(body_with_comments):
            continue

        # Signal 1: bare u32 depth arithmetic (strip comments first)
        body_nocomment = body_text_nocomment(body, source)
        arith_match = _DEPTH_ARITH_RE.search(body_nocomment)
        if arith_match is None:
            continue

        # Safety guard: checked/saturating arithmetic or cast
        if _has_arithmetic_guard(body_nocomment):
            continue

        # Signal 3: the enclosing block or function must contain the TOCTOU
        # acknowledgement comment (look at the raw source including comments).
        # We search the full text of the function node (not just body) so that
        # the comment above the function body is included.
        fn_text_raw = text_of(fn, source)
        if not _TOCTOU_COMMENT_RE.search(fn_text_raw):
            continue

        name = fn_name(fn, source)

        # Locate the arithmetic expression node for a precise hit location.
        # Walk the body AST to find the binary expression that matches.
        hit_node = body
        for node in walk_no_nested_fn(body):
            if node.type == "binary_expression":
                node_text = body_text_nocomment(node, source) if False else text_of(node, source)
                if _DEPTH_ARITH_RE.search(text_of(node, source)):
                    hit_node = node
                    break

        line, col = line_col(hit_node)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(hit_node, source),
            "message": (
                f"fn `{name}` computes block depth/confirmations as "
                "`1 + tip_height(...).?.0 - height.0` across two separate "
                "state reads. A chain reorganization between the `tip_height` "
                "call and the block/transaction height lookup can make "
                "`height.0 > tip.0`, causing u32 underflow (wraps to ~2^32). "
                "Use `checked_sub` or cast both operands to `i64` before "
                "subtracting, or hold a consistent read snapshot across both "
                "lookups. See: https://github.com/ZcashFoundation/zebra/issues/10470"
            ),
        })

    return hits
