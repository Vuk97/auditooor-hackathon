"""
rust_trusted_preallocate_max_delegation_overcounting.py

Flags `impl TrustedPreallocate for T` blocks where `max_allocation()` returns
`max(TypeA::max_allocation(), TypeB::max_allocation())` -- delegating to the
LARGER of two sibling types' allocation bounds -- without adjusting for the
delegating type T's own serialized item size.

The over-count means `Vec::with_capacity(max_allocation_result)` will
pre-allocate more T-sized structs than could ever fit in a maximum-size
protocol message.  A crafted peer message can therefore trigger an
over-sized heap allocation, causing a non-distributed DoS against the
receiving node.

A developer-acknowledged `// TODO: put a separate limit` comment in the
same `max_allocation()` body is treated as a strong confirmatory signal.

Structural shape (class invariant):

    impl TrustedPreallocate for T {
        fn max_allocation() -> u64 {
            // TODO: put a separate limit ...    <- optional but confirmatory
            max(
                TypeA::max_allocation(),
                TypeB::max_allocation(),
            )
        }
    }

Where the safe pattern would be:
    `(MAX_BLOCK_BYTES - 1) / T_MIN_SERIALIZED_SIZE`  -- type-specific divisor
  or
    `min(TypeA::max_allocation(), TypeB::max_allocation())`  -- take the smaller bound
  or
    delegation to a SINGLE same-sized type:
    `TypeA::max_allocation()`  -- but only when TypeA's item size == T's item size

Verified real surface:
    zebra-chain/src/sapling/shielded_data.rs  Groth16Proof::max_allocation()
    Lines 365-377: returns max(SpendPrefixInTransactionV5::max_allocation(),
                               OutputPrefixInTransactionV5::max_allocation())
    with `// TODO: put a separate limit on proofs in spends and outputs`.
    Groth16Proof is 192 bytes; the delegated bound is computed from
    ANCHOR_PER_SPEND_SIZE / SHARED_ANCHOR_SPEND_SIZE (both include the
    proof bytes plus additional per-spend/output fields), so the bound is
    derived from a larger item size and over-counts the number of proofs
    that fit in a max-size block.

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
# Signal 1 - function must be named `max_allocation`
# We check the function identifier directly to avoid false positives on
# other helpers that happen to call max().
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Signal 2 - body uses std::cmp::max or bare `max(` with two max_allocation() calls
# The pattern is: max(TypeA::max_allocation(), TypeB::max_allocation())
# where BOTH arguments are calls to max_allocation on DIFFERENT types.
#
# We match the text form of the body for:
#   max(
#       SomeType::max_allocation(),
#       AnotherType::max_allocation(),
#   )
# captured as: one or two intermediate paths before `max_allocation`.
# ---------------------------------------------------------------------------
_MAX_DELEGATION_RE = re.compile(
    r"\bmax\s*\(\s*"
    r"[\w:]+\s*::\s*max_allocation\s*\(\s*\)"    # first arg: TypeA::max_allocation()
    r"\s*,\s*"
    r"[\w:]+\s*::\s*max_allocation\s*\(\s*\)"    # second arg: TypeB::max_allocation()
    r"\s*,?\s*\)",                                # optional trailing comma (Rust style)
    re.DOTALL,
)

# ---------------------------------------------------------------------------
# Signal 3 (optional, strong confirmatory) - TODO comment acknowledging
# that the limit should be per-type.
# ---------------------------------------------------------------------------
_TODO_LIMIT_RE = re.compile(
    r"//\s*TODO\s*:.*(?:separate|own|specific|per[- ]type)\s+limit",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Guard: if the body ALSO contains a type-specific size divisor pattern,
# the developer did compute a proper type-specific bound.  Do NOT flag.
# e.g. (MAX_BLOCK_BYTES - 1) / OWN_SIZE  or  / PROOF_SIZE  or  / ITEM_SIZE
# ---------------------------------------------------------------------------
_OWN_SIZE_GUARD_RE = re.compile(
    r"MAX_BLOCK_BYTES\s*[\-]\s*1\s*/",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Guard: if max_allocation uses min() instead of max(), the developer took
# the SMALLER bound, which is conservative and not the bug pattern.
# ---------------------------------------------------------------------------
_MIN_GUARD_RE = re.compile(
    r"\bmin\s*\(\s*[\w:]+\s*::\s*max_allocation\s*\(\s*\)\s*,"
    r"\s*[\w:]+\s*::\s*max_allocation\s*\(\s*\)\s*,?\s*\)",
    re.DOTALL,
)


def run(tree, source: bytes, filepath: str):
    hits = []

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        # Signal 1: function must be named `max_allocation`
        name = fn_name(fn, source)
        if name != "max_allocation":
            continue

        body = fn_body(fn)
        if body is None:
            continue

        body_raw = text_of(body, source)
        body_nc = body_text_nocomment(body, source)

        # Signal 2: body must use max(TypeA::max_allocation(), TypeB::max_allocation())
        if not _MAX_DELEGATION_RE.search(body_nc):
            continue

        # Guard: if the body also contains its own size-divisor, skip
        if _OWN_SIZE_GUARD_RE.search(body_nc):
            continue

        # Guard: if the body uses min() instead of max(), skip
        if _MIN_GUARD_RE.search(body_nc):
            continue

        # Find the enclosing impl block's type name for a richer message
        impl_type = _enclosing_impl_type(fn, source)

        # Locate the max(...) call node as the primary anchor
        hit_node = _find_max_call(body, source)
        if hit_node is None:
            hit_node = body

        line, col = line_col(hit_node)

        # Check for the TODO confirmatory comment in the RAW body text
        has_todo = bool(_TODO_LIMIT_RE.search(body_raw))
        todo_note = (
            " A developer-acknowledged TODO comment confirms awareness of this gap."
            if has_todo else ""
        )

        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(hit_node, source),
            "message": (
                f"`{impl_type}::max_allocation()` returns "
                "`max(TypeA::max_allocation(), TypeB::max_allocation())`, "
                "delegating to the LARGER of two sibling types' allocation bounds "
                "without adjusting for the delegating type's own serialized item size. "
                "This over-counts the number of items that fit in a maximum-size message, "
                "so a crafted peer message can trigger an over-sized "
                "`Vec::with_capacity()` heap pre-allocation, causing a "
                "non-distributed DoS against the receiving node."
                + todo_note
                + " Safe fix: compute `(MAX_BLOCK_BYTES - 1) / T_MIN_SERIALIZED_SIZE` "
                "using the delegating type's own wire size, or use "
                "`min(TypeA::max_allocation(), TypeB::max_allocation())` "
                "to take the more conservative bound."
            ),
        })

    return hits


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _enclosing_impl_type(fn_node, source: bytes) -> str:
    """Walk up the parent chain looking for an impl_item and return its type name."""
    parent = fn_node.parent
    while parent is not None:
        if parent.type == "impl_item":
            # The impl type is typically the first `type_identifier` child
            for c in parent.children:
                if c.type in ("type_identifier", "generic_type", "scoped_type_identifier"):
                    return text_of(c, source).strip()
        parent = parent.parent
    return "?"


def _find_max_call(body, source: bytes):
    """Find the call_expression node that matches max(...) in the body."""
    for node in walk_no_nested_fn(body):
        if node.type != "call_expression":
            continue
        node_text = text_of(node, source)
        if _MAX_DELEGATION_RE.search(node_text):
            return node
    return None
