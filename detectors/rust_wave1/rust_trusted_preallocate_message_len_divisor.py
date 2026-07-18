"""
rust_trusted_preallocate_message_len_divisor.py

Flags `impl TrustedPreallocate for T` blocks whose `fn max_allocation()`
returns a size-limit / item-size divide expression as the SOLE bound,
without an additional secondary cap from a protocol constant (such as a
`min(result, MAX_INV_IN_RECEIVED_MESSAGE)` or `min(result, MAX_ADDRS_IN_MESSAGE)`
call).

Vulnerable shape
----------------
    impl TrustedPreallocate for Foo {
        fn max_allocation() -> u64 {
            // No secondary min() narrowing the formula result
            (MAX_PROTOCOL_MESSAGE_LEN - 1) / MIN_ITEM_SIZE
        }
    }

Protected shape (does NOT fire)
---------------------------------
    impl TrustedPreallocate for Bar {
        fn max_allocation() -> u64 {
            let formula = ((MAX_PROTOCOL_MESSAGE_LEN - 1) / MIN_ITEM_SIZE) as u64;
            min(formula, MAX_PROTOCOL_ITEM_COUNT)   // <-- secondary cap present
        }
    }

Background
----------
Pre-allocation amplification in Zebra's P2P deserializer is documented in
GHSA-xr93-pcq3-pxf8 (AddrV1/V2) and the block.rs comment around
MAX_BLOCK_LOCATOR_LENGTH.  Any `TrustedPreallocate::max_allocation()` that
returns `MAX_PROTOCOL_MESSAGE_LEN / N` or `MAX_BLOCK_BYTES / N` as its
sole result lets a peer craft a compact `CompactSize`-prefixed list whose
declared count equals the formula result, causing `Vec::with_capacity(N)`
before a single item is validated.

Impls that compound the formula result with `min(result, EXPLICIT_CONSTANT)`
carry a secondary cap anchored to a protocol constant and are NOT flagged.

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
    walk,
    walk_no_nested_fn,
)

# ---------------------------------------------------------------------------
# Signal 1: the impl block must implement TrustedPreallocate
# We detect this by checking whether the impl block's trait name contains
# "TrustedPreallocate".
# ---------------------------------------------------------------------------
_TRUSTED_PREALLOCATE_RE = re.compile(r"\bTrustedPreallocate\b")

# ---------------------------------------------------------------------------
# Signal 2: the body of max_allocation() must contain a division of a
# size-limit constant by an item-size constant.
#
# We look for:
#   MAX_PROTOCOL_MESSAGE_LEN  (or with offset like - 1, - 5)
#   MAX_BLOCK_BYTES           (the Zcash block-size ceiling)
#   Any of them / CONSTANT
# expressed as a bare division (not inside a `min(...)` wrapping).
# ---------------------------------------------------------------------------
_DIVIDE_FORMULA_RE = re.compile(
    r"(?:MAX_PROTOCOL_MESSAGE_LEN|MAX_BLOCK_BYTES)"
    r"\s*(?:-\s*\d+\s*)?"   # optional subtract offset like `- 1`
    r"\)\s*/\s*\w"          # ) / WORD   (after a closing paren) OR
    r"|"
    r"(?:MAX_PROTOCOL_MESSAGE_LEN|MAX_BLOCK_BYTES)"
    r"\s*(?:-\s*\d+\s*)?"   # optional subtract offset
    r"/\s*\w"               # direct / WORD (no paren)
)

# Alternative: simpler pattern that catches `MAX_*LEN / IDENT` and
# `(MAX_*LEN - N) / IDENT` directly.
_FORMULA_RE = re.compile(
    r"(?:MAX_PROTOCOL_MESSAGE_LEN|MAX_BLOCK_BYTES)"
    r"(?:\s*-\s*\d[\w_]*)?"   # optional - offset
    r"\s*\)\s*/\s*\w"
    r"|"
    r"(?:MAX_PROTOCOL_MESSAGE_LEN|MAX_BLOCK_BYTES)"
    r"(?:\s*-\s*\d[\w_]*)?"   # optional - offset
    r"\s*/\s*\w"
)

# ---------------------------------------------------------------------------
# Guard: presence of a secondary min() call that narrows the result.
# If the body contains `min(` followed by something that looks like a
# formula result and a second protocol-constant argument, the impl is safe.
#
# We are conservative: if ANY `min(` or `cmp::min(` appears in the body,
# we treat the impl as having a secondary cap and do NOT flag it.
# ---------------------------------------------------------------------------
_MIN_CAP_RE = re.compile(r"\bmin\s*\(", re.IGNORECASE)
_CLAMP_RE = re.compile(r"\.clamp\s*\(")

# ---------------------------------------------------------------------------
# Helper: find the impl_item that directly contains a function_item.
# ---------------------------------------------------------------------------

def _enclosing_impl(fn_node):
    """Walk up to the nearest impl_item ancestor, or None."""
    n = fn_node.parent
    while n is not None:
        if n.type == "impl_item":
            return n
        n = n.parent
    return None


def _impl_trait_text(impl_node, source: bytes) -> str:
    """Return the textual representation of the trait name in the impl,
    e.g. 'TrustedPreallocate' for `impl TrustedPreallocate for Foo`."""
    # The tree-sitter impl_item has children:
    #   `impl` keyword, optional generics, optional trait (type_identifier /
    #   scoped_type_identifier / generic_type), `for` keyword, concrete type,
    #   declaration_list.
    # We just scan the text up to the declaration_list for the trait name.
    decl_list = None
    for c in impl_node.children:
        if c.type == "declaration_list":
            decl_list = c
            break
    if decl_list is None:
        return text_of(impl_node, source)
    before_body = source[impl_node.start_byte:decl_list.start_byte].decode(
        "utf-8", errors="replace"
    )
    return before_body


def run(tree, source: bytes, filepath: str):
    hits = []

    for fn in function_items(tree.root_node):
        # Only look at functions named `max_allocation`
        name = fn_name(fn, source)
        if name != "max_allocation":
            continue

        if in_test_cfg(fn, source):
            continue

        # The function must be inside an `impl TrustedPreallocate for T` block.
        impl = _enclosing_impl(fn)
        if impl is None:
            continue
        impl_header = _impl_trait_text(impl, source)
        if not _TRUSTED_PREALLOCATE_RE.search(impl_header):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        body_text = body_text_nocomment(body, source)

        # Signal 2: body must contain a size/item divide formula.
        if not _FORMULA_RE.search(body_text):
            continue

        # Guard: skip if the body has any min() call (secondary cap present).
        if _MIN_CAP_RE.search(body_text):
            continue
        if _CLAMP_RE.search(body_text):
            continue

        # Also skip if the body simply delegates to another type's max_allocation()
        # (no divide formula of its own; already covered by the formula check).

        line, col = line_col(body)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(body, source),
            "message": (
                f"TrustedPreallocate::max_allocation() in `{impl_header.strip()[:80]}` "
                "returns a size-limit / item-size divide expression as the sole "
                "pre-allocation bound, without a secondary `min(result, PROTOCOL_CONSTANT)` "
                "narrowing the result. A peer that sends a CompactSize-prefixed "
                "list whose declared count equals the formula result forces "
                "Vec::with_capacity(formula_result) before any payload bytes are "
                "validated, enabling an amplified heap pre-allocation DoS. "
                "Add a secondary cap: `min(formula_result, MAX_<ITEM>_IN_MESSAGE)`."
            ),
        })

    return hits
