"""
rust_rpc_unbounded_height_span.py

Flags async RPC/handler functions that accept caller-supplied lower+upper
block-height bounds (start/end, start_height/end_height) from a request
struct and feed them into a state range-scan or height iteration WITHOUT any
span-cap guard.

Target shape (class-invariant, NOT a one-off literal):
  1. The function is `async fn`.
  2. The body extracts a start/end height pair from a caller-controlled
     request: `request.start` / `request.end` (or `start_height` /
     `end_height` variants, or passes them to a height-range builder).
  3. The body issues a state read / height-range scan using that range
     (`read_state`, `ReadRequest`, `height_range`, `TransactionIds`,
     `AddressUtxos`, or similar height-range consumers).
  4. The body has NO span-cap guard: no arithmetic check on
     `(end - start)`, no `.min(MAX_BLOCK_RANGE)`, no `clamp`, no
     `too_large`, no `max_span`, no explicit upper-bound on span size.

Verified real surface:
  zebra-rpc/src/methods.rs  fn get_address_tx_ids  (~line 2041)
  The `build_height_range` helper clamps each height individually to
  chain_height but never checks (end - start).  Line 436 comment only
  says the large-range guard is \"recommended\".  Attacker passes
  start=0, end=current_height => full-chain scan.
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
# Signal 1 – the function must be async
# ---------------------------------------------------------------------------
_ASYNC_RE = re.compile(r"\basync\b")

# ---------------------------------------------------------------------------
# Signal 2 – caller-supplied start/end height fields extracted from a request
#
# Matches: request.start, request.end, request.start_height, request.end_height,
#          params.start, params.end, req.start_height, etc.
# Also matches the common build_height_range(...) / height_range pattern where
# the call receives `.start` / `.end` from a request variable.
# ---------------------------------------------------------------------------
_START_FIELD_RE = re.compile(
    r"\b\w+\s*\.\s*(?:start|start_height)\b"
)
_END_FIELD_RE = re.compile(
    r"\b\w+\s*\.\s*(?:end|end_height)\b"
)

# Slightly broader: also catches `build_height_range` or analogous names that
# accept start/end arguments (range-builder function call with two positional
# heights from a request).
_HEIGHT_RANGE_BUILD_RE = re.compile(
    r"(?:build_height_range|height_range_from|make_height_range|height_range)\s*\("
)

# ---------------------------------------------------------------------------
# Signal 3 – state range-scan consumer
#
# The resulting range is used in a state read-request that performs an
# on-disk/in-memory height-span scan.
# ---------------------------------------------------------------------------
_STATE_SCAN_RE = re.compile(
    r"(?:"
    r"read_state"                          # Zebra read_state service
    r"|ReadRequest\s*::"                   # zebra_state::ReadRequest variant
    r"|TransactionIdsByAddresses"          # explicit zebra variant
    r"|AddressesTransactionIds"
    r"|UtxosByAddresses"
    r"|height_range"                       # the range variable itself fed in
    r"|\.call\s*\("                        # generic tower-service call with range
    r")",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Guard patterns – absence of ALL of these is required for a flag
#
# Any of these indicates the developer implemented a span-cap:
#   - arithmetic comparison on the span: end - start > N, span > N
#   - .min(MAX_...), .clamp(
#   - explicit constant names like MAX_BLOCK_RANGE, MAX_RANGE, MAX_HEIGHT_SPAN
#   - error-path: "range too large", "span too large", "too many blocks"
#   - saturating_sub used in a comparison (span = end.saturating_sub(start))
# ---------------------------------------------------------------------------
_GUARD_PATTERNS = [
    # arithmetic span comparison: (end - start) > N  /  span > N  /  len > N
    r"(?:end|end_height)\s*[\-\.]\s*(?:start|start_height)[\s\S]{0,40}(?:>|>=|<|<=)\s*\d",
    r"\bspan\s*(?:>|>=)\s*\d",
    r"\.len\s*\(\s*\)\s*(?:>|>=)\s*\d",
    r"height_range\.(?:len|count)\s*\(",
    # .min() / .clamp() applied to a span or to end
    r"\.min\s*\(\s*(?:MAX_BLOCK_RANGE|MAX_HEIGHT|MAX_SPAN|MAX_RANGE|max_range|max_height|max_span)",
    r"\.clamp\s*\(",
    # explicit span-cap constant names
    r"\bMAX_BLOCK_RANGE\b",
    r"\bMAX_HEIGHT_RANGE\b",
    r"\bMAX_HEIGHT_SPAN\b",
    r"\bMAX_SPAN\b",
    r"\bmax_span\b",
    r"\bmax_range\b",
    # error strings indicating a range-size check
    r"range\s+too\s+large",
    r"span\s+too\s+large",
    r"too\s+many\s+blocks",
    r"exceeds.*(?:max|limit|cap)",
    r"(?:max|limit|cap).*(?:exceeded|too large)",
    # saturating_sub in a guard context
    r"saturating_sub\s*\([^)]*\)\s*(?:>|>=)\s*\d",
]
_GUARD_RES = [re.compile(p, re.IGNORECASE) for p in _GUARD_PATTERNS]


def _is_async_fn(fn_node, source: bytes) -> bool:
    """Return True if the function_item has the `async` keyword."""
    fn_text = source[fn_node.start_byte:fn_node.end_byte].decode("utf-8", errors="replace")
    # Only look at the signature (before the block body), not the body
    body = fn_body(fn_node)
    if body is not None:
        sig_text = source[fn_node.start_byte:body.start_byte].decode("utf-8", errors="replace")
    else:
        sig_text = fn_text
    return bool(_ASYNC_RE.search(sig_text))


def _has_span_cap_guard(body_text: str) -> bool:
    return any(g.search(body_text) for g in _GUARD_RES)


def _find_range_build_node(body, source: bytes):
    """Return the first call_expression node that looks like a height-range
    builder or a state-scan call that references height_range, or None."""
    for node in walk_no_nested_fn(body):
        if node.type not in ("call_expression", "macro_invocation"):
            continue
        call_text = text_of(node, source)
        if _HEIGHT_RANGE_BUILD_RE.search(call_text) or _STATE_SCAN_RE.search(call_text):
            return node
    return None


def run(tree, source: bytes, filepath: str):
    hits = []

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        # Must be async
        if not _is_async_fn(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        body_text = body_text_nocomment(body, source)

        # Must have both start-field and end-field references from a request
        if not (_START_FIELD_RE.search(body_text) and _END_FIELD_RE.search(body_text)):
            continue

        # Must reference a state scan consumer (height_range fed to state)
        if not _STATE_SCAN_RE.search(body_text):
            continue

        # Must NOT have any span-cap guard
        if _has_span_cap_guard(body_text):
            continue

        name = fn_name(fn, source)

        # Find the best node to point at for the hit location
        hit_node = _find_range_build_node(body, source)
        if hit_node is None:
            hit_node = body

        line, col = line_col(hit_node)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(hit_node, source),
            "message": (
                f"async fn `{name}` accepts caller-supplied start/end block-height "
                "fields from a request and feeds them into a state range-scan "
                "without any span-cap guard. An attacker can set start=0 and "
                "end=chain_tip to trigger an unbounded full-chain scan, causing "
                "denial of service (OOM / stall). Add a MAX_BLOCK_RANGE constant "
                "and reject requests where (end - start) exceeds it."
            ),
        })

    return hits
