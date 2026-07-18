"""
rust_rpc_address_result_uncapped_accumulation.py

Flags async RPC functions that:
  1. Issue a state query for all UTXOs/transactions belonging to an
     attacker-supplied address set (ReadRequest::UtxosByAddresses or
     equivalent address-aggregation read), AND
  2. Accumulate every returned item into a local Vec via a `for` loop
     with `.push(entry)`, AND
  3. Have NO intermediate result-size guard inside the loop body
     (no `if response_vec.len() >= MAX_ITEMS { break }`, no `.take(n)`,
     no `max_utxos`, no `count_limit`, no `truncate`).

The address set is caller-controlled and unbounded; each address can have
many UTXOs/transactions; their product drives unbounded Vec growth,
enabling memory-exhaustion DoS on the serving node.

Verified real surface:
  zebra-rpc/src/methods.rs  fn get_address_utxos  (~line 2090)
  - `valid_addresses` from `utxos_request.valid_addresses()` (no count cap)
  - `ReadRequest::UtxosByAddresses(valid_addresses)` passes all addresses
  - `for utxo_data in utxos.utxos() { ... response_utxos.push(entry); }`
    with zero length-check inside the loop.

This detector is intentionally narrower than rust_rpc_unbounded_result_accumulation:
  - Requires the specific address-based state-read variant
    (UtxosByAddresses / AddressesTx* / AddressUtxos), not just any Vec return.
  - Requires the for-loop-plus-push shape (not iterator collect chains).
  - Absent both signals, it passes cleanly - no FP on administrative or
    range-scan endpoints that use .collect().

Generalizes to: any Rust blockchain RPC that aggregates per-address
state (UTXO / tx / balance / note sets) into an unbounded Vec response
without a server-side result cap.
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
# Signal 1: the function must be async
# ---------------------------------------------------------------------------
_ASYNC_RE = re.compile(r"\basync\b")

# ---------------------------------------------------------------------------
# Signal 2: body issues a state query keyed on a caller-supplied address set.
# We look for the UtxosByAddresses / AddressUtxos variant name (the specific
# read-request enum variant that drives an all-address UTXO scan), or
# the more generic TransactionIdsByAddresses / AddressesTransactionIds forms.
# ---------------------------------------------------------------------------
_ADDRESS_QUERY_RE = re.compile(
    r"(?:"
    r"UtxosByAddresses"
    r"|AddressUtxos"
    r"|TransactionIdsByAddresses"
    r"|AddressesTransactionIds"
    r"|addresses\s*:\s*valid_addresses"   # struct-init of a state request with the address set
    r")",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Signal 3: for-loop that pushes each item into a local result Vec.
# Match `for <pat> in <expr>` followed (anywhere in the loop body) by `.push(`.
# We use a DOTALL window capped at 1200 bytes - the real zebra get_address_utxos
# loop body spans ~900 chars between the `for` keyword and the `.push(` call.
# ---------------------------------------------------------------------------
_FOR_PUSH_RE = re.compile(
    r"\bfor\b[\s\S]{0,1200}?\.push\s*\(",
    re.DOTALL,
)

# ---------------------------------------------------------------------------
# Guard patterns - presence of ANY of these means the developer capped results.
# Absence of ALL of them is the bug signal.
#
# Covers:
#   - explicit length-check before push: if vec.len() >= N { break }
#   - .take(n) on the iterator
#   - named cap constants: MAX_UTXOS, MAX_RESULTS, MAX_ENTRIES, RESULT_LIMIT
#   - .truncate(n) after accumulation
#   - pagination guard: page_size, max_entries, limit =, limit:
# ---------------------------------------------------------------------------
_GUARD_PATTERNS = [
    # if len >= cap before push
    r"\.len\s*\(\s*\)\s*(?:>=|>)\s*\d",
    r"\.len\s*\(\s*\)\s*(?:>=|>)\s*\w*(?:MAX|max|LIMIT|limit|CAP|cap)",
    # break/return inside loop based on count
    r"\bif\s+\w+\s*(?:>=|>)\s*\w*(?:max|MAX|limit|LIMIT|cap|CAP)[\s\S]{0,80}break",
    # iterator cap
    r"\.take\s*\(",
    # named cap constants
    r"\bMAX_UTXOS\b",
    r"\bMAX_RESULTS\b",
    r"\bMAX_ENTRIES\b",
    r"\bRESULT_LIMIT\b",
    r"\bMAX_ITEMS\b",
    r"\bcount_limit\b",
    r"\bmax_results\b",
    r"\bmax_entries\b",
    r"\bmax_utxos\b",
    r"\bmax_items\b",
    r"\bpage_size\b",
    r"\bpagination\b",
    r"\.truncate\s*\(",
]
_GUARD_RES = [re.compile(p, re.IGNORECASE) for p in _GUARD_PATTERNS]


def _is_async_fn(fn_node, source: bytes) -> bool:
    """Return True if the function declaration has the `async` keyword."""
    body = fn_body(fn_node)
    if body is not None:
        sig_text = source[fn_node.start_byte:body.start_byte].decode("utf-8", errors="replace")
    else:
        sig_text = text_of(fn_node, source)
    return bool(_ASYNC_RE.search(sig_text))


def _has_address_query(body_text: str) -> bool:
    return bool(_ADDRESS_QUERY_RE.search(body_text))


def _has_for_push(body_text: str) -> bool:
    return bool(_FOR_PUSH_RE.search(body_text))


def _has_guard(body_text: str) -> bool:
    return any(g.search(body_text) for g in _GUARD_RES)


def _find_for_push_node(body, source: bytes):
    """Return the `for_expression` node that contains a `.push(` call, or body."""
    for node in walk_no_nested_fn(body):
        if node.type == "for_expression":
            t = text_of(node, source)
            if ".push(" in t:
                return node
    return body


def run(tree, source: bytes, filepath: str) -> list[dict]:
    hits = []

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        # Gate 1: async fn
        if not _is_async_fn(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        body_text = body_text_nocomment(body, source)

        # Gate 2: issues an address-keyed state query (UtxosByAddresses etc.)
        if not _has_address_query(body_text):
            continue

        # Gate 3: accumulates results with for+push
        if not _has_for_push(body_text):
            continue

        # Gate 4: no result-size cap anywhere in the body
        if _has_guard(body_text):
            continue

        name = fn_name(fn, source)
        report_node = _find_for_push_node(body, source)
        line, col = line_col(report_node)

        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(report_node, source),
            "message": (
                f"async fn `{name}` issues a state query keyed on a caller-supplied "
                "address set (UtxosByAddresses / TransactionIdsByAddresses) and "
                "accumulates every returned item into a Vec via `for ... push` with "
                "no intermediate result-size cap. An attacker supplying many addresses "
                "with many UTXOs/transactions each can force unbounded Vec growth, "
                "exhausting node memory (DoS). Add a MAX_UTXOS / MAX_RESULTS constant "
                "and either cap the address count at intake, add a "
                "`if response_utxos.len() >= MAX_UTXOS { break }` guard inside the "
                "loop, or use pagination."
            ),
        })

    return hits
