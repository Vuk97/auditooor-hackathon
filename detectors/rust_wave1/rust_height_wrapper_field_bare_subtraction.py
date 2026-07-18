"""
rust_height_wrapper_field_bare_subtraction.py

Flags functions that subtract two `.0` fields of a Height-like newtype wrapper
using the bare `-` operator instead of the safe Sub trait, checked_sub, or
saturating_sub.

The vulnerability class:
  In Rust, `struct Height(u32)` is a common newtype for monotonic block counters.
  The inner u32 is exposed via the `.0` field. When code computes the difference
  between two such heights directly as `a.0 - b.0`, and `a < b` for any reason
  (reorg, TOCTOU between two DB reads, attacker-supplied value), the subtraction
  wraps to a large u32 in release builds (panics in debug). This silently produces
  a wrong confirmation count or depth value that is then stored, returned over RPC,
  or used in further arithmetic.

Structural shape:
  fn <name>(...) -> Option<u32> / Option<MinedTx> / ... {
      let tip   = tip_height(chain, db)?;   // first DB read
      let height = height_by_hash(...)?;    // second DB read
      Some(tip.0 - height.0)               // <-- bare .0 subtraction, no check
  }

  Also catches the addition-then-subtraction chain:
      let confirmations = 1 + tip_height(...)?.0 - height.0;

Verified real surfaces in zebra:
  zebra-state/src/service/read/find.rs:154   fn depth    -> Some(tip.0 - height.0)
  zebra-state/src/service/read/block.rs:156  fn mined_transaction -> 1 + tip_height(...)?.0 - height.0
  zebra-state/src/service/read/block.rs:197  fn any_transaction   -> 1 + tip_height(...)?.0 - height.0

Fix: use `(tip - height)` which invokes Height::Sub returning HeightDiff (i64),
or call `.0.checked_sub(height.0).unwrap_or(0)`.

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
)

# ---------------------------------------------------------------------------
# Signal 1 - bare .0 subtraction pattern
#
# Matches:  <ident>.0 - <ident>.0
#           1 + <expr>.0 - <ident>.0
#           tip.0 - height.0
#
# The pattern requires:
#   - A dotted identifier ending in `.0` on the LEFT side
#   - A literal `-` operator (not `-=`, not inside checked_sub)
#   - A dotted identifier ending in `.0` on the RIGHT side
#
# We use a word-boundary at the end of the RHS `.0` so that `.0` doesn't
# match floating-point literals like `1.0`.
# ---------------------------------------------------------------------------
_BARE_DOT0_SUB_RE = re.compile(
    r"[\w\.]+\.0\s*-\s*[\w\.]+\.0\b",
)

# ---------------------------------------------------------------------------
# Signal 2 - the expression must NOT already use checked_sub / saturating_sub
# wrapping the subtraction directly. We look for these in the same line/expression
# to avoid rejecting safe code.
# ---------------------------------------------------------------------------
_SAFE_SUB_RE = re.compile(
    r"\bchecked_sub\s*\(|saturating_sub\s*\(",
)

# ---------------------------------------------------------------------------
# Guard - if the function is a Sub trait impl itself (fn sub(self, rhs: ...)
# inside an `impl ... Sub`), skip it - that IS the definition of the operator.
# We detect this by checking the text before the function body for "impl" + "Sub".
# ---------------------------------------------------------------------------
_IMPL_SUB_RE = re.compile(r"\bimpl\b[^{]*\bSub\b")


def _is_inside_sub_impl(fn_node, source: bytes) -> bool:
    """Return True if this function is directly inside an impl Sub block."""
    parent = fn_node.parent
    while parent is not None:
        if parent.type == "impl_item":
            # Get the text of the impl header (before the declaration_list)
            impl_text = text_of(parent, source)
            # Just check the first 120 chars (the impl header)
            if _IMPL_SUB_RE.search(impl_text[:120]):
                return True
        parent = parent.parent
    return False


def _rhs_is_dot0_field(node, source: bytes) -> bool:
    """Return True if a node is a field_expression whose field is `0`."""
    if node.type != "field_expression":
        return False
    for c in node.children:
        if c.type in ("field_identifier", "integer_literal"):
            if text_of(c, source).strip() == "0":
                return True
    return False


def _lhs_contains_dot0(node, source: bytes) -> bool:
    """Return True if the left-side node's text contains a `.0` access.

    Covers two cases:
      (a) Simple field_expression: `tip.0`  -> matches _BARE_DOT0_SUB_RE on the text
      (b) Complex binary with .0 in it: `1 + tip_height(...)?.0`
    """
    t = text_of(node, source)
    return bool(_BARE_DOT0_RE.search(t))


# A minimal pattern that checks for .0 anywhere (for lhs check).
# Includes `?` in the character class to handle `expr?.0` (the try operator
# applied to a function call result before the field access).
_BARE_DOT0_RE = re.compile(r"[\w\)\?]\s*\.\s*0\b")


def _find_bare_sub_node(body_node, source: bytes):
    """
    Walk the body looking for a binary_expression whose operator is `-` and
    where the right-hand child is a `field_expression` accessing field `0`,
    AND the left-hand child also contains a `.0` access.

    This catches both:
      - Simple:   tip.0 - height.0  (both sides are field_expression)
      - Compound: 1 + tip_height(?)?.0 - height.0  (rhs is field_expression,
                  lhs is a binary containing a .0)

    Returns the first matching binary_expression node, or None.
    """
    for node in walk_no_nested_fn(body_node):
        if node.type != "binary_expression":
            continue

        # Collect named children + operator token
        named = [c for c in node.children if c.is_named]
        op_tokens = [text_of(c, source).strip() for c in node.children if not c.is_named]

        if "-" not in op_tokens:
            continue

        # Expect exactly 2 named children: left and right
        if len(named) < 2:
            continue

        lhs = named[0]
        rhs = named[-1]  # Use last named child as rhs

        # Right side must be a field_expression .0
        if not _rhs_is_dot0_field(rhs, source):
            continue

        # Left side must contain a .0 access
        if not _lhs_contains_dot0(lhs, source):
            continue

        # Must NOT have checked_sub / saturating_sub wrapping this expression
        expr_text = text_of(node, source)
        if _SAFE_SUB_RE.search(expr_text):
            continue

        return node

    return None


def run(tree, source: bytes, filepath: str):
    hits = []

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        # Skip if inside a Sub trait impl (this is the operator definition itself)
        if _is_inside_sub_impl(fn, source):
            continue

        body_text = body_text_nocomment(body, source)

        # Quick pre-filter: body must contain a .0 and a - somewhere
        if ".0" not in body_text or " - " not in body_text:
            continue

        # Find the actual AST node of the bare subtraction
        hit_node = _find_bare_sub_node(body, source)
        if hit_node is None:
            continue

        name = fn_name(fn, source)
        line, col = line_col(hit_node)

        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(hit_node, source),
            "message": (
                f"fn `{name}`: bare `.0 - .0` subtraction on Height-like newtype fields "
                "without checked_sub or saturating_sub. "
                "In debug builds this panics on underflow (tip < height after reorg or TOCTOU); "
                "in release builds it silently wraps to a large u32. "
                "The two heights are read in separate DB calls; a concurrent reorg or an "
                "attacker-supplied block hash can trigger tip < height. "
                "Fix: use `(tip - height)` (Height::Sub returns HeightDiff i64) "
                "or `.0.checked_sub(height.0).unwrap_or(0)`."
            ),
        })

    return hits
