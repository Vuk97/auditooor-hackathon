"""
rust_rpc_unbounded_result_accumulation.py

Flags RPC handler functions that accumulate results into a Vec/collection from a
query whose size is attacker-influenced (user-supplied addresses, height range,
identifiers, etc.) with NO result-count cap (no .take(n), no max_results limit,
no pagination guard) before returning.

Target shape (class-invariant):
  1. Async function whose return type contains `Vec<` (or builds a Vec inside
     that wraps an RPC response).
  2. Body accumulates results via:
       a. `.iter() ... .collect()` or `.into_iter() ... .collect()`, OR
       b. a `for` loop with `.push(...)` building a local vec.
  3. The query/accumulation is driven by attacker-influenced input — detected by
     presence of `request`, `addresses`, `valid_addresses`, `height_range`,
     `utxos_request`, or similar user-parameter names in the body.
  4. No result-count cap exists: no `.take(`, no `max_results`, no
     `max_entries`, no `page_size`, no `limit` variable/call near the
     accumulation, and no explicit count bound check before returning.

This is intentionally narrow: it requires BOTH the accumulation pattern AND the
absence of every common guard form.  Plain administrative queries with no
user-supplied dimension (e.g. get_peer_info whose domain is the node's own
address book, not caller-supplied) are excluded by the user-input presence
requirement.

Fires on:
  zebra-rpc/src/methods.rs  get_address_tx_ids  (line 2041)
  zebra-rpc/src/methods.rs  get_address_utxos   (line 2090)
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
# Pattern: function return type contains Vec<  (in the raw fn node text before
# the body block).  We extract the pre-body signature text and scan it.
# ---------------------------------------------------------------------------
_RETURN_VEC_RE = re.compile(r"Result\s*<\s*Vec\s*<|Vec\s*<")

# ---------------------------------------------------------------------------
# Accumulation patterns — either:
#   a) iterator chain ending in .collect()
#   b) for-loop with vec.push(
# ---------------------------------------------------------------------------
_ITER_COLLECT_RE = re.compile(
    r"(?:\.iter\s*\(\s*\)|\.into_iter\s*\(\s*\)|\.values\s*\(\s*\)|\.keys\s*\(\s*\))"
    r"[\s\S]{0,600}?\.collect\s*\(\s*\)",
    re.DOTALL,
)
# Also catch bare .map(...).collect() chains (e.g. .map(PeerInfo::from).collect())
_MAP_COLLECT_RE = re.compile(
    r"\.map\s*\([^)]{0,200}\)\s*\.collect\s*\(\s*\)",
    re.DOTALL,
)
# for-loop accumulation
_FOR_PUSH_RE = re.compile(
    r"\bfor\b[\s\S]{0,400}?\.push\s*\(",
    re.DOTALL,
)

# ---------------------------------------------------------------------------
# User-input presence: body must reference caller-supplied data to be in scope
# ---------------------------------------------------------------------------
_USER_INPUT_RE = re.compile(
    r"\b(?:request\b|valid_addresses|addresses\b|height_range\b|utxos_request\b"
    r"|addr_list\b|txids\b|query_addresses\b|params\b)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Guard patterns — any of these disqualify the finding
# ---------------------------------------------------------------------------
_GUARD_PATTERNS = [
    r"\.take\s*\(",                      # Iterator::take(n)
    r"\bmax_results\b",
    r"\bmax_entries\b",
    r"\bpage_size\b",
    r"\bpagination\b",
    r"\bmax_items\b",
    r"\blimit\s*[:<(=]",                 # limit: n, limit(n), limit = n
    r"\bMAX_RESULTS\b",
    r"\bMAX_ENTRIES\b",
    r"\bRESULT_LIMIT\b",
    r"\bcount_limit\b",
    r"if\s+\w+\s*>=\s*\w*(?:max|limit|cap)",  # if count >= max_count
    r"\.truncate\s*\(",
]

_GUARD_RES = [re.compile(p) for p in _GUARD_PATTERNS]


def _fn_return_has_vec(fn_node, source: bytes) -> bool:
    """Return True if the function's return type text contains Vec<."""
    # Walk the function's children looking for type nodes before the block
    body = fn_body(fn_node)
    if body is None:
        full = text_of(fn_node, source)
    else:
        # Only look at the signature part (before the body block)
        sig_end = body.start_byte
        full = source[fn_node.start_byte:sig_end].decode("utf-8", errors="replace")
    return bool(_RETURN_VEC_RE.search(full))


def _has_accumulation(body_text: str) -> bool:
    return bool(
        _ITER_COLLECT_RE.search(body_text)
        or _MAP_COLLECT_RE.search(body_text)
        or _FOR_PUSH_RE.search(body_text)
    )


def _has_user_input(body_text: str) -> bool:
    return bool(_USER_INPUT_RE.search(body_text))


def _has_guard(body_text: str) -> bool:
    return any(pat.search(body_text) for pat in _GUARD_RES)


def _accumulation_node(body, source: bytes):
    """Return the first node that looks like the accumulation site, for
    line/col reporting."""
    for node in walk_no_nested_fn(body):
        if node.type not in ("call_expression", "for_expression"):
            continue
        t = text_of(node, source)
        if ".collect()" in t or ".push(" in t:
            return node
    return body


def run(tree, source: bytes, filepath: str) -> list[dict]:
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        # Must be a function that returns Vec (directly or wrapped in Result)
        if not _fn_return_has_vec(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        body_text = body_text_nocomment(body, source)

        # Must accumulate results from an iterator or loop
        if not _has_accumulation(body_text):
            continue

        # Must reference user-supplied input as the query dimension
        if not _has_user_input(body_text):
            continue

        # Must NOT have any result-count cap guard
        if _has_guard(body_text):
            continue

        name = fn_name(fn, source)
        report_node = _accumulation_node(body, source)
        line, col = line_col(report_node)

        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(report_node, source),
            "message": (
                f"fn `{name}` accumulates an unbounded number of results into a Vec "
                "from a query whose size is driven by attacker-controlled input "
                "(addresses / height-range / request parameters) with no "
                ".take(n) / max_results / pagination cap before returning. "
                "A crafted request covering many addresses or a wide block range "
                "can force the node to allocate and serialize an arbitrarily large "
                "response, enabling a memory-exhaustion or bandwidth-amplification DoS."
            ),
        })

    return hits
