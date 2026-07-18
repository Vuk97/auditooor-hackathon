"""
rust_rpc_handler_expect_on_block_field_parse.py

Flags async RPC handler functions that call .expect() or .unwrap() directly
on the return value of a block-header or block-field parsing method
(commitment, coinbase_height, parse, from_bytes, try_into, zcash_deserialize,
block_hash).  A panic here aborts the async task and can crash or poison the
RPC service for any caller-supplied hash or height.

Target shape (class-invariant):
  1. The function is `async fn`.
  2. The function name matches a public RPC handler naming convention
     (get_block*, get_transaction*, z_get_*, send_raw_transaction,
     get_raw_transaction) OR the function's return type signature contains
     `jsonrpc_core::Error` / `ErrorObject` (JSON-RPC server return types).
  3. The body contains a chained call of the form
       <receiver>.<block_parse_method>(...).<expect|unwrap>(
     where `block_parse_method` is one of the enumerated parse/interpret
     methods that can fail on non-canonical block data.
  4. The expression is NOT inside a comment, and the function is NOT
     test-gated (#[test] / #[cfg(test)] / mod tests).

Verified real surface:
  zebra-rpc/src/methods.rs  `get_block_header` (~line 1532)
    header.commitment(&network, height)
          .expect("Unexpected failure while parsing the blockcommitments field
                   in get_block_header")
  The `commitment()` method returns Result<Commitment, CommitmentError> and
  can legitimately return Err for certain commitment byte patterns. Calling
  .expect() inside the public get_block_header RPC handler means any block
  whose header produces an unexpected Commitment variant panics the async
  worker, potentially terminating the RPC service thread.
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
# Signal 2: RPC handler name pattern
#
# Matches standard Zcash/Bitcoin-compatible RPC names for block/transaction
# queries.  The detector also accepts any function whose return type includes
# a JSON-RPC Error type (jsonrpc_core::Error, ErrorObject) as an alternative
# indicator of a public RPC method.
# ---------------------------------------------------------------------------
_RPC_NAME_RE = re.compile(
    r"^(?:"
    r"get_block(?:_header|_hash|_template|_count)?"
    r"|get_transaction"
    r"|get_raw_transaction"
    r"|send_raw_transaction"
    r"|z_get_[a-z_]+"
    r"|get_best_block"
    r"|invalidate_block"
    r"|reconsider_block"
    r")$",
    re.IGNORECASE,
)

# Return type keywords that indicate a JSON-RPC server method.
_RPC_RETURN_RE = re.compile(
    r"jsonrpc_core\s*::\s*Error"
    r"|ErrorObject"
    r"|\bResult\s*<[^>]*(?:jsonrpc|RpcError|LegacyCode)"
)

# ---------------------------------------------------------------------------
# Signal 3: block-field parse method chained with .expect / .unwrap
#
# The pattern matches a call chain such as:
#   receiver.commitment(...).expect(
#   receiver.coinbase_height().expect(
#   receiver.zcash_deserialize(...).unwrap()
#   block.commitment(&network, height).expect(
#
# We look for:
#   .<block_parse_method>(<anything>).<expect_or_unwrap>(
# allowing optional whitespace/newlines.
# ---------------------------------------------------------------------------
_BLOCK_PARSE_METHODS = (
    r"commitment"
    r"|coinbase_height"
    r"|block_hash"
    r"|zcash_deserialize"
    r"|from_bytes"
    r"|try_into"
    r"|parse"
)

# The chained .expect / .unwrap immediately after the parse call result.
# We allow an arbitrary argument list between the parentheses of the
# parse method call (greedy but bounded by newline-restricted span).
_CHAIN_PANIC_RE = re.compile(
    r"\.\s*(?:" + _BLOCK_PARSE_METHODS + r")\s*\([^)]*\)\s*\.\s*(?:expect|unwrap)\s*\(",
    re.DOTALL,
)

# Also catch the pattern where the parse call spans multiple lines via a
# match arm or let binding, and expect() appears on the next statement on
# the same value.  We detect the simpler form: method call immediately
# followed (within ~3 lines) by .expect/.unwrap with a block-field message.
_EXPECT_BLOCK_MSG_RE = re.compile(
    r"\.(?:expect|unwrap)\s*\(\s*"
    r"(?:\"[^\"]*(?:commitment|coinbase_height|block_hash|block_header|blockcommitments"
    r"|block.*field|header.*field)[^\"]*\"|[^)]*(?:commitment|coinbase_height|block))",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_async(fn_node, source: bytes) -> bool:
    """True if the function_item has the `async` keyword in its signature."""
    body = fn_body(fn_node)
    if body is not None:
        sig_text = source[fn_node.start_byte:body.start_byte].decode("utf-8", errors="replace")
    else:
        sig_text = text_of(fn_node, source)
    return bool(_ASYNC_RE.search(sig_text))


def _is_rpc_handler(fn_node, source: bytes) -> bool:
    """True if the function looks like a public RPC handler by name or return type."""
    name = fn_name(fn_node, source)
    if _RPC_NAME_RE.match(name):
        return True
    # Check return type in the signature (before body)
    body = fn_body(fn_node)
    if body is not None:
        sig_text = source[fn_node.start_byte:body.start_byte].decode("utf-8", errors="replace")
    else:
        sig_text = text_of(fn_node, source)
    return bool(_RPC_RETURN_RE.search(sig_text))


def _find_chain_panic_node(body_node, source: bytes):
    """Return the first AST node (call_expression) whose text matches the
    chained block-field-parse + .expect/.unwrap pattern, or None."""
    for node in walk_no_nested_fn(body_node):
        if node.type != "call_expression":
            continue
        call_text = text_of(node, source)
        if _CHAIN_PANIC_RE.search(call_text):
            return node
    return None


def _body_has_chain_panic(body_text: str) -> bool:
    """Fast pre-filter on stripped body text."""
    return bool(_CHAIN_PANIC_RE.search(body_text))


def _body_has_expect_block_msg(body_text: str) -> bool:
    """Catch the multi-line variant where the message string names a block field."""
    return bool(_EXPECT_BLOCK_MSG_RE.search(body_text))


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run(tree, source: bytes, filepath: str):
    hits = []

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        # Must be async
        if not _is_async(fn, source):
            continue

        # Must look like a public RPC handler
        if not _is_rpc_handler(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        body_text = body_text_nocomment(body, source)

        # Must have a block-field parse chained with .expect/.unwrap
        has_chain = _body_has_chain_panic(body_text)
        has_msg   = _body_has_expect_block_msg(body_text)
        if not (has_chain or has_msg):
            continue

        name = fn_name(fn, source)

        # Try to find the specific call node for a precise source location.
        hit_node = _find_chain_panic_node(body, source)
        if hit_node is None:
            # Fall back to the function body open brace
            hit_node = body

        line, col = line_col(hit_node)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(hit_node, source),
            "message": (
                f"async RPC handler `{name}` calls .expect() or .unwrap() on the result "
                "of a block-header or block-field parsing method "
                "(commitment / coinbase_height / block_hash / zcash_deserialize / ...). "
                "If the parse fails for a caller-supplied block hash or height the async "
                "task panics, potentially crashing the RPC worker or poisoning service "
                "state. Replace .expect()/.unwrap() with proper error propagation "
                "(e.g. `.map_error(...)?) so the error becomes a JSON-RPC error response."
            ),
        })

    return hits
