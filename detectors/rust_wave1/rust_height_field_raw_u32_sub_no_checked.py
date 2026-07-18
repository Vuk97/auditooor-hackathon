"""
rust_height_field_raw_u32_sub_no_checked.py

Flags plain u32 subtraction of the form `<expr_a>.0 - <expr_b>.0` (or
`1 + <expr_a>.0 - <expr_b>.0`) where:

  (1) At least one operand name matches a Height/BlockHeight variable
      (local or via a call like `tip_height(...)`).
  (2) The expression is assigned to a variable whose name suggests it is a
      confirmations, depth, or block-count value, OR the function returns
      `Option<u32>` and the subtraction appears in a `Some(...)` return.
  (3) No `checked_sub` / `saturating_sub` / guard (`>= ` / `assert`) that
      would protect the high - low ordering appears in the same function body.

Structural shape (class-invariant):
  fn depth(...) -> Option<u32> {
      let tip    = tip_height(...)?;   // Height newtype wrapping u32
      let height = height_by_hash(...)?;
      Some(tip.0 - height.0)          // VULN: plain u32 sub - no ordering guarantee
  }

  fn mined_transaction(...) -> Option<MinedTx> {
      ...
      let confirmations = 1 + tip_height(...)?.0 - height.0;   // VULN
      ...
  }

Verified real surfaces (zebra):
  zebra-state/src/service/read/find.rs:154   fn depth
  zebra-state/src/service/read/block.rs:156  fn mined_transaction
  zebra-state/src/service/read/block.rs:197  fn any_transaction

Severity: MEDIUM
Rubric: Node falls behind the chain tip / prevents an instance from participating
reliably (MEDIUM). Concretely: a concurrent reorg where the block was just
reorganised away causes `height > tip`, wrapping u32 to ~u32::MAX and returning
a fabricated confirmations count to wallets.

Why generalizable:
  Any Rust blockchain node with a Height newtype (u32 inner) performing
  confirmations arithmetic directly on `.0` instead of using a safe
  `checked_sub` or the type-safe `Height - Height -> HeightDiff` operator
  carries this pattern. Fix: `tip.0.checked_sub(height.0)` or the safe
  operator that returns `HeightDiff`.
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
# Signal 1 - function return type is Option<u32> or Option<MinedTx> etc.
# (We check return type OR that the subtraction feeds confirmations/depth.)
# Broad initial screen: the function text must mention "height" (case-insensitive).
# ---------------------------------------------------------------------------
_HEIGHT_IN_SIG_RE = re.compile(r"\bHeight\b", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Signal 2 - the raw subtraction pattern
# Matches:
#   tip.0 - height.0
#   tip_height(...).0 - height.0
#   1 + something.0 - something_else.0
# at least one operand name must look height-ish (checked below).
# ---------------------------------------------------------------------------
_RAW_SUB_RE = re.compile(
    # Optional leading `1 +`
    r"(?:1\s*\+\s*)?"
    # Left operand: anything ending in `.0`
    r"([\w\(\)\?,\.\s]+?)\.0"
    r"\s*-\s*"
    # Right operand: anything ending in `.0`
    r"([\w\(\)\?,\.\s]+?)\.0"
    # Lookahead: not immediately followed by another dot-zero (avoid matching
    # the middle of a longer chain).
    r"(?!\.0)",
)

# ---------------------------------------------------------------------------
# Signal 3 - at least one operand must be height-ish
# ---------------------------------------------------------------------------
_HEIGHT_OPERAND_RE = re.compile(
    r"\b(?:height|tip|block_height|chain_height|tip_height|start_height|end_height)\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Signal 4 - the result is used in a confirmations/depth context
# (assigned to a variable whose name suggests so, OR is inside Some(...))
# ---------------------------------------------------------------------------
_CONFIRMATIONS_CTX_RE = re.compile(
    r"\b(?:confirmations|depth|block_count|count|diff)\b",
    re.IGNORECASE,
)
_SOME_RETURN_RE = re.compile(r"\bSome\s*\(")

# ---------------------------------------------------------------------------
# Guard patterns - presence of ANY of these means the developer used a safe
# subtraction, so we skip.
# ---------------------------------------------------------------------------
_GUARD_PATTERNS = [
    # checked_sub anywhere in the same function body
    r"\.checked_sub\s*\(",
    # saturating_sub
    r"\.saturating_sub\s*\(",
    # assert or >= guard proving ordering before subtracting
    r"assert\s*!\s*\([^;]*height[^;]*>=",
    r"assert\s*!\s*\([^;]*tip[^;]*>=",
    # Explicit ordering comparisons on the .0 fields (both >= and > forms)
    r"height\.0\s*(?:>=|>)\s*\w",
    r"\w+\.0\s*(?:>=|>)\s*height\.0",
    r"tip\.0\s*(?:>=|>)\s*\w",
    r"\w+\.0\s*(?:>=|>)\s*tip\.0",
    # HeightDiff safe operator (Zcash-specific)
    r"HeightDiff",
    # wrapping_sub
    r"\.wrapping_sub\s*\(",
]
_GUARD_RES = [re.compile(p, re.IGNORECASE) for p in _GUARD_PATTERNS]


def _has_safe_guard(body_text: str) -> bool:
    return any(g.search(body_text) for g in _GUARD_RES)


def run(tree, source: bytes, filepath: str):
    hits = []

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        # Quick screen: function signature or body must mention Height
        fn_text = text_of(fn, source)
        if not _HEIGHT_IN_SIG_RE.search(fn_text):
            continue

        body_text = body_text_nocomment(body, source)

        # Gate: skip if any safe guard is present
        if _has_safe_guard(body_text):
            continue

        # Find all raw .0 - .0 subtraction expressions in the body
        for m in _RAW_SUB_RE.finditer(body_text):
            left_operand = m.group(1)
            right_operand = m.group(2)

            # At least one operand must be height-ish
            if not (
                _HEIGHT_OPERAND_RE.search(left_operand)
                or _HEIGHT_OPERAND_RE.search(right_operand)
            ):
                continue

            # The result must feed confirmations/depth OR appear in Some(...)
            # Look at a window of text around the match for context.
            start = max(0, m.start() - 20)
            end = min(len(body_text), m.end() + 60)
            ctx = body_text[start:end]

            if not (_CONFIRMATIONS_CTX_RE.search(ctx) or _SOME_RETURN_RE.search(ctx)):
                continue

            # Locate the source line to produce a real hit location.
            # Walk the AST for a binary_expression node whose text contains
            # the matched substring.
            match_text_fragment = m.group(0).strip()[:40]
            hit_node = None
            for node in walk_no_nested_fn(body):
                if node.type in (
                    "binary_expression",
                    "let_declaration",
                    "call_expression",
                    "return_expression",
                ):
                    node_t = text_of(node, source)
                    if ".0 -" in node_t and (
                        _HEIGHT_OPERAND_RE.search(node_t)
                    ):
                        hit_node = node
                        break

            if hit_node is None:
                hit_node = body

            name = fn_name(fn, source)
            line, col = line_col(hit_node)
            snip = snippet_of(hit_node, source)

            hits.append({
                "severity": "medium",
                "line": line,
                "col": col,
                "snippet": snip,
                "message": (
                    f"fn `{name}`: raw u32 subtraction on Height `.0` fields without "
                    "`checked_sub` or ordering guard. If a concurrent reorg causes "
                    "`height > tip`, the subtraction wraps to ~u32::MAX, returning a "
                    "fabricated depth/confirmations value to callers (wallets may "
                    "accept unconfirmed transactions as deeply confirmed). "
                    "Fix: use `tip.0.checked_sub(height.0)` or the safe "
                    "`Height - Height -> HeightDiff` operator."
                ),
            })

    return hits
