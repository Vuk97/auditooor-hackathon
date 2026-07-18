"""
rust_zcash_deserialize_bytes_without_consensus_precheck.py

Flags `impl ZcashDeserialize for T` bodies that perform the vulnerable
allocation pattern:

  1. Read a peer-supplied CompactSize length from the wire:
         let len: CompactSizeMessage = (...).zcash_deserialize_into()?;
  2. Convert to usize via `.into()` (explicit `let len: usize = len.into()`
     OR inline `len.into()` in the call argument).
  3. Pass the length directly to `zcash_deserialize_bytes_external_count`
     or `zcash_deserialize_external_count` WITHOUT an intervening domain-
     specific bound check of the form:
         if len > DOMAIN_BOUND { return Err(...) }
     where DOMAIN_BOUND is smaller than MAX_PROTOCOL_MESSAGE_LEN (~2 MiB).

The absence of the precheck allows a peer to force a transient allocation
of up to MAX_PROTOCOL_MESSAGE_LEN bytes (2 MiB) before the generic library
cap in `zcash_deserialize_bytes_external_count` fires.

Zebra's own documentation of the pattern is at:
  zebra-chain/src/transparent/serialize.rs:181-184

The FIXED variant (Input::zcash_deserialize for coinbase scripts) adds:
  if len < MIN_COINBASE_SCRIPT_LEN { return Err(...) }
  else if len > MAX_COINBASE_SCRIPT_LEN { return Err(...) }
BEFORE the `zcash_deserialize_bytes_external_count` call.

The generic library implementations in zcash_deserialize.rs:
  Vec<u8>::zcash_deserialize   (line 56-61)
  Vec<T>::zcash_deserialize    (line 33-38)
are the canonical vulnerable instances; protocol-level ZcashDeserialize
impls that perform the pattern inline are also caught.

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
# Signal 1 - function is inside an `impl ZcashDeserialize` block
# We scan the full source for the impl-block boundary rather than walking
# the AST impl_item, because tree-sitter represents impl items as a flat
# list and the function items we yield via function_items() already carry
# their parent chain.  A lighter approach: check that the raw source text
# surrounding the function contains "ZcashDeserialize".
# ---------------------------------------------------------------------------
_IMPL_ZCASH_DESER_RE = re.compile(
    r"\bimpl\b[^{]*\bZcashDeserialize\b[^{]*\{",
)

# ---------------------------------------------------------------------------
# Signal 2 - a CompactSizeMessage length is read from the wire
# Matches: `let <ident>: CompactSizeMessage = ...zcash_deserialize_into()?;`
# ---------------------------------------------------------------------------
_READ_COMPACT_SIZE_RE = re.compile(
    r"let\s+(\w+)\s*:\s*CompactSizeMessage\s*=",
)

# ---------------------------------------------------------------------------
# Signal 3 - the same variable is converted to usize via .into()
# Two forms:
#   (a) `let <same>: usize = <same>.into();`   (two-statement form)
#   (b) `<same>.into()` passed inline to the allocation call
# ---------------------------------------------------------------------------
_INTO_USIZE_RE = re.compile(
    r"let\s+(\w+)\s*:\s*usize\s*=\s*\w+\s*\.into\s*\(\s*\)",
)

# ---------------------------------------------------------------------------
# Signal 4 - the allocation call is present
# Matches both `zcash_deserialize_bytes_external_count(len, ...)` and
# `zcash_deserialize_external_count(len, ...)`.
# ---------------------------------------------------------------------------
_ALLOC_CALL_RE = re.compile(
    r"\bzcash_deserialize(?:_bytes)?_external_count\s*\(",
)

# Also catches the inline form: `zcash_deserialize_bytes_external_count(len.into(), ...)`
_ALLOC_CALL_INLINE_INTO_RE = re.compile(
    r"\bzcash_deserialize(?:_bytes)?_external_count\s*\(\s*\w+\s*\.into\s*\(\s*\)",
)

# ---------------------------------------------------------------------------
# Guard patterns - presence of ANY of these means a domain precheck exists
# and we should NOT flag the function.
# ---------------------------------------------------------------------------
_GUARD_PATTERNS = [
    # Explicit `if len > CONSTANT { return Err(...) }` (most common)
    r"if\s+\w+\s*(?:>|>=)\s*\w+[A-Z_]\w*",
    # `if len < CONSTANT { return Err(...) }` (lower bound also proves intent)
    r"if\s+\w+\s*(?:<|<=)\s*\w+[A-Z_]\w*",
    # `.contains(...)` range check on a constant range
    r"\.contains\s*\(&\s*\w+",
    # Direct comparison to a named constant (e.g. SOLUTION_SIZE, MAX_COINBASE_SCRIPT_LEN)
    r"(?:SOLUTION_SIZE|MAX_COINBASE_SCRIPT_LEN|MIN_COINBASE_SCRIPT_LEN"
    r"|MAX_SCRIPT_LEN|MAX_FILTERLOAD_FILTER_LENGTH|MAX_USER_AGENT_LENGTH"
    r"|MAX_REJECT_MESSAGE_LENGTH|MAX_REJECT_REASON_LENGTH"
    r"|MAX_MEMO_SIZE|MAX_SAPLING_MEMO_SIZE|MAX_ORCHARD_MEMO_SIZE"
    r"|MAX_PUSH_DATA_SIZE|MAX_OP_RETURN_DATA_SIZE"
    r"|MAX_\w+LEN|MAX_\w+SIZE|MIN_\w+LEN)",
    # `.min(...)` applied with a named bound
    r"\.min\s*\(\s*(?:MAX_|MIN_|SOLUTION_|FILTER_|SCRIPT_)\w+",
    # Body-len based math guard (codec.rs pattern: `body_len - FIELDS_LENGTH`)
    r"\bbody_len\b",
    # Saturating arithmetic before the call
    r"saturating_sub\s*\(",
    # error string mentioning "too long" / "too short" / "limit"
    r'"[^"]*too\s+long[^"]*"',
    r'"[^"]*too\s+short[^"]*"',
    r'"[^"]*too\s+large[^"]*"',
    r'"[^"]*exceeds\s+max[^"]*"',
    r'"[^"]*maximum\s+length[^"]*"',
]
_GUARD_RES = [re.compile(p, re.IGNORECASE) for p in _GUARD_PATTERNS]


def _has_domain_precheck(body_text: str) -> bool:
    return any(g.search(body_text) for g in _GUARD_RES)


def _impl_block_contains_zcash_deserialize(fn_node, source: bytes) -> bool:
    """Return True when the function is directly inside a ZcashDeserialize impl."""
    # Walk up the parent chain; check the nearest impl_item's source text.
    n = fn_node.parent
    while n is not None:
        if n.type == "impl_item":
            impl_text = source[n.start_byte:n.end_byte].decode("utf-8", errors="replace")
            if _IMPL_ZCASH_DESER_RE.search(impl_text):
                return True
            # Only check the NEAREST impl_item.
            return False
        n = n.parent
    return False


def run(tree, source: bytes, filepath: str):
    hits = []

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        # Gate 1: function must be inside `impl ZcashDeserialize for T`
        if not _impl_block_contains_zcash_deserialize(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        body_text = body_text_nocomment(body, source)

        # Gate 2: a CompactSizeMessage is read from the wire
        compact_match = _READ_COMPACT_SIZE_RE.search(body_text)
        if compact_match is None:
            continue

        # Gate 3: the allocation call is present (two-statement or inline form)
        has_alloc = _ALLOC_CALL_RE.search(body_text) or _ALLOC_CALL_INLINE_INTO_RE.search(body_text)
        if not has_alloc:
            continue

        # Gate 4: .into() conversion is present (two-statement OR inline)
        has_into = _INTO_USIZE_RE.search(body_text) or _ALLOC_CALL_INLINE_INTO_RE.search(body_text)
        if not has_into:
            continue

        # Guard: if a domain precheck exists, skip
        if _has_domain_precheck(body_text):
            continue

        name = fn_name(fn, source)

        # Anchor the hit at the CompactSizeMessage read statement
        hit_node = None
        for node in walk_no_nested_fn(body):
            if node.type in ("let_declaration",):
                node_text = text_of(node, source)
                if "CompactSizeMessage" in node_text and "zcash_deserialize_into" in node_text:
                    hit_node = node
                    break
        if hit_node is None:
            hit_node = body

        line, col = line_col(hit_node)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(hit_node, source),
            "message": (
                f"fn `{name}` in a ZcashDeserialize impl reads a peer-supplied "
                "CompactSize length and calls `zcash_deserialize_bytes_external_count` "
                "or `zcash_deserialize_external_count` WITHOUT a domain-specific bound "
                "check (`if len > DOMAIN_BOUND {{ return Err(...) }}`) before the "
                "allocation. A malicious peer can supply a CompactSize value near "
                "MAX_PROTOCOL_MESSAGE_LEN (~2 MiB) and force a transient multi-MiB "
                "allocation before the generic library cap fires. "
                "Fix: add `if len > MAX_DOMAIN_LEN {{ return Err(SerializationError::Parse(...)) }}` "
                "immediately after the `.into()` conversion and before the "
                "`zcash_deserialize_bytes_external_count` call."
            ),
        })

    return hits
