"""
rust_height_field_raw_u32_add_no_bounds_guard.py

Flags raw u32 addition on a Height (or block-height) inner field used to
construct a new Height value, with no checked_add, saturating_add, or
explicit MAX guard, silently overflowing the u32 range and producing a
Height that wraps below the start height.

Structural shape (class-invariant):
  Height(<some_height>.0 + <non_small_var>)

where:
  (a) The addend is NOT a small compile-time integer literal (<= 4);
      adding 1 for "next block" is safe and common; adding a variable
      that can be peer-supplied or config-supplied is the bug class.
  (b) No `checked_add`, `saturating_add`, or `<= MAX - addend`-style
      overflow guard appears in the same function body.

Overflow produces a wrapped Height smaller than the start height; in a
block-range computation this yields `start > end`, silently returning an
empty response rather than an error, making the behaviour indistinguishable
from a legitimate empty range and suppressing blocks the peer requested.

Verified real surface:
  zebra-state/src/service/read/find.rs  fn find_chain_height_range  line ~395-396
  `Height(intersection_height.0 + max_len)` — max_len is a u32 parameter;
  if intersection_height.0 is close to u32::MAX the addition wraps silently.
  The current callers cap max_len <= 500, making the overflow latent rather
  than immediately reachable, but the function signature accepts any u32.

Severity: LOW
Rubric: LOW row - indirectly contributes to harm at scale; specifically
'footgun flags / misleading behaviour'. If a caller can supply an unbounded
max_len, severity rises to MEDIUM (node falls behind the chain tip / sync stalls).
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
# Signal 1 - The call pattern: Height(<expr>.0 + <addend>)
#
# Match any expression of the form:
#   Height(  ...ANYTHING...  .0 +  <addend>  )
#
# where <addend> is NOT a small integer literal (0-4).  We need at least
# one identifier character in the addend position (i.e., a variable name or
# a qualified constant like `max_len`, `MAX_BLOCKS`, `n` etc.).
#
# The regex is applied to body text after comment stripping.
# ---------------------------------------------------------------------------
_HEIGHT_RAW_ADD_RE = re.compile(
    r"Height\s*\(\s*"          # Height( opening
    r"[\w\.\s\*\&]*"           # optional prefix tokens (self, field access)
    r"\.0\s*\+\s*"             # .0 +
    r"(?!"                     # NEGATIVE lookahead: reject small literals
    r"(?:[0-4]\s*[,\)])"       # 0-4 followed by , or )
    r")"
    r"([\w:]+)"                # capture: addend must have at least one ident char
    r"[\s\)]*",                # trailing whitespace / closing paren(s)
)

# ---------------------------------------------------------------------------
# Guard patterns - presence of ANY of these means the developer already
# handled overflow, so we do NOT flag.
# ---------------------------------------------------------------------------
_GUARD_PATTERNS = [
    r"\bchecked_add\b",
    r"\bsaturating_add\b",
    r"\badd_clamped\b",
    r"\bwrapping_add\b",        # wrapping is intentional; developer aware
    r"\bu32::MAX\b",            # explicit MAX comparison
    r"\.checked_add\s*\(",
    r"\.saturating_add\s*\(",
    r"Height::MAX",
    r"overflows?\s*u32",
    r"would_overflow",
]
_GUARD_RES = [re.compile(p) for p in _GUARD_PATTERNS]


def _has_overflow_guard(body_text: str) -> bool:
    return any(g.search(body_text) for g in _GUARD_RES)


def run(tree, source: bytes, filepath: str):
    hits = []

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        body_text = body_text_nocomment(body, source)

        # Must have the raw-add pattern somewhere in the body
        matches = list(_HEIGHT_RAW_ADD_RE.finditer(body_text))
        if not matches:
            continue

        # If there is already an overflow guard anywhere in the function,
        # the developer is aware of the issue - skip.
        if _has_overflow_guard(body_text):
            continue

        name = fn_name(fn, source)

        # Find the AST node(s) corresponding to the matched position(s).
        # We use a best-effort approach: walk for call_expression nodes whose
        # text contains the raw-add pattern.  Report each unique occurrence.
        reported_lines = set()
        for node in walk_no_nested_fn(body):
            if node.type not in ("call_expression", "tuple_expression",
                                  "binary_expression", "let_declaration",
                                  "assignment_expression"):
                continue
            node_text = text_of(node, source)
            if not _HEIGHT_RAW_ADD_RE.search(node_text):
                continue
            # Avoid very large nodes (whole-function body captured)
            if node.end_point[0] - node.start_point[0] > 5:
                continue
            ln, col = line_col(node)
            if ln in reported_lines:
                continue
            reported_lines.add(ln)

            addend_m = _HEIGHT_RAW_ADD_RE.search(node_text)
            addend_name = addend_m.group(1) if addend_m else "?"

            hits.append({
                "severity": "low",
                "line": ln,
                "col": col,
                "snippet": snippet_of(node, source),
                "message": (
                    f"fn `{name}`: `Height(<height>.0 + {addend_name})` performs "
                    "a raw u32 addition on a Height inner field with no "
                    "checked_add / saturating_add / MAX guard. If the base height "
                    f"is close to u32::MAX and `{addend_name}` is large, the result "
                    "wraps silently to a value below the start height, making any "
                    "resulting block range empty without an error. "
                    "Fix: use `height.0.checked_add(addend)` and propagate None as "
                    "an error, or assert `height.0 <= u32::MAX - addend` first."
                ),
            })

    return hits
