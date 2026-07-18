"""
rust_std_sync_mutex_in_tokio_spawn_async_block.py

Flags `.lock()` / `.read()` / `.write()` calls on std::sync / parking_lot
blocking primitives that appear INSIDE a `tokio::spawn(async ...)` or
`tokio::task::spawn(async ...)` async block (NOT spawn_blocking).

The async block is scheduled on the tokio async thread pool.  Calling a
blocking lock primitive inside it stalls a worker thread for the duration
of the critical section, potentially stalling the entire executor under
contention.

Structural shape that fires:
    tokio::spawn(
        async move {
            some_mutex.lock().expect("msg").send(val)  // <-- BLOCKS thread
        }
        .map_err(|e| ...)   // async block may be chained; still flagged
    );

The safe pattern (tokio::sync::Mutex) uses `.lock().await` -- the parent of
the lock call_expression in the AST is an `await_expression`.  This detector
EXCLUDES that pattern.

Additional exclusion: closures passed to `tokio::task::spawn_blocking` -- the
callee ends with `spawn_blocking`, which is the correct wrapping idiom.

Algorithm (bottom-up):
  1. Find every `call_expression` node whose direct callee field_identifier is
     one of: lock, read, write.
  2. Skip if the immediate parent of this call is an `await_expression` (safe
     tokio async lock pattern).
  3. Walk up the parent chain from this call_expression, passing through
     field_expression / call_expression nodes (method chain), until:
     (a) We hit an `async_block` node -- the lock is inside an async block.
         Continue walking up to check if that async_block is inside
         `tokio::spawn`.
     (b) We leave the async block context (hit function_item, closure_expression
         that is NOT an async block, or a statement boundary) -- stop, no flag.
  4. From the `async_block`, walk further up through the method chain to find
     whether it eventually appears as an argument to a `tokio::spawn` call
     (allowing arbitrary depth of method chaining between the async_block and
     the spawn call).
  5. Verify the spawn callee does NOT end with `spawn_blocking`.
  6. Skip nodes in test configuration.

Real anchor: zebrad/src/components/sync/downloads.rs lines 479 and 499:
    past_lookahead_limit_sender.lock().expect("...").send(true/false)
    inside `tokio::spawn(async move { ... }.in_current_span().map_err(...))`.
The zebra comment acknowledges: "It is ok to block here, because we're going
to pause new downloads anyway." -- a maintenance hazard.

Severity: HIGH
Rubric: Non-distributed DoS against an individual node or wallet.
"""

from __future__ import annotations

import re

from _util import (
    fn_name,
    function_items,
    in_test_cfg,
    line_col,
    snippet_of,
    text_of,
    walk,
    IDENT,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SPAWN_BLOCKING_RE = re.compile(r"\bspawn_blocking\s*$")
_TOKIO_SPAWN_RE = re.compile(r"(?:^|::)spawn\s*$")


def _is_tokio_spawn_callee(callee: str) -> bool:
    """True if callee is tokio::spawn or tokio::task::spawn (not spawn_blocking)."""
    if _SPAWN_BLOCKING_RE.search(callee):
        return False
    if "tokio" not in callee:
        return False
    return bool(_TOKIO_SPAWN_RE.search(callee))


def _callee_text(call_node, source: bytes) -> str:
    """Return the text of the callee (function/method reference) of a call_expression."""
    if call_node.children:
        return text_of(call_node.children[0], source)
    return ""


def _is_in_test_cfg_node(node) -> bool:
    """Walk up parent chain checking for #[test] / #[cfg(test)] ancestors."""
    n = node
    while n is not None:
        if n.type == "attribute_item":
            # Heuristic: check if this attribute contains "test"
            pass
        n = n.parent
    return False


# Boundary node types at which we stop the upward walk.
# We do NOT stop at call_expression or field_expression (those are method chains).
_ASYNC_STOP_TYPES = frozenset({
    "function_item",        # different function context
    "source_file",          # top level
    "impl_item",
    "trait_item",
    "let_declaration",      # assignment is a statement boundary for our purposes
    "match_arm",
    # closure_expression that is NOT an async_block; we handle async_block specially
})

# Node types that are transparent for walking "up through method chain" into spawn.
# Note: call_expression is NOT included here; it is handled separately in
# _is_async_block_under_tokio_spawn so we can check the callee for tokio::spawn.
_CHAIN_TYPES = frozenset({
    "field_expression",
    "arguments",
    "await_expression",
    "try_expression",
    "reference_expression",
    "parenthesized_expression",
    "block",          # async_block > block boundary
})


def _enclosing_async_block(node):
    """Walk up parent chain and return the first async_block ancestor,
    or None if we first hit a function_item or non-async closure."""
    parent = node.parent
    while parent is not None:
        t = parent.type
        if t == "async_block":
            return parent
        if t in ("function_item", "source_file", "impl_item", "trait_item"):
            return None
        # closure_expression that is NOT an async_block is a boundary
        if t == "closure_expression":
            return None
        parent = parent.parent
    return None


def _is_async_block_under_tokio_spawn(async_block_node, source: bytes) -> bool:
    """Return True if async_block_node is eventually passed as an argument
    (possibly via method chaining) to a tokio::spawn call."""
    node = async_block_node
    while node is not None:
        parent = node.parent
        if parent is None:
            return False
        pt = parent.type
        # If this node appears as the callee-receiver of a method chain or
        # directly inside arguments, keep walking up.
        if pt in _CHAIN_TYPES:
            node = parent
            continue
        # If parent is a call_expression AND this node is NOT the callee...
        # The callee is parent.children[0]; the args are parent.children[1].
        # We need to check: is `node` the argument (or part of an argument chain)?
        if pt == "call_expression":
            callee_text = _callee_text(parent, source)
            if _is_tokio_spawn_callee(callee_text):
                return True
            # Keep walking up through method chains
            node = parent
            continue
        # Hit a statement or non-chain boundary
        return False
    return False


def _find_enclosing_fn(node):
    """Return the enclosing function_item node or None."""
    n = node.parent
    while n is not None:
        if n.type == "function_item":
            return n
        n = n.parent
    return None


# ---------------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------------

LOCK_METHODS = frozenset({"lock", "read", "write"})


def run(tree, source: bytes, filepath: str):
    hits = []
    seen = set()

    for node in walk(tree.root_node):
        if node.type != "call_expression":
            continue

        # The callee of this call must be a field_expression ending in lock/read/write
        if not node.children:
            continue
        head = node.children[0]
        if head.type != "field_expression":
            continue

        # Extract the method name
        method = None
        for fc in head.children:
            if fc.type == "field_identifier":
                method = text_of(fc, source)
                break
        if method not in LOCK_METHODS:
            continue

        # Safe pattern: .lock().await -- immediate parent is await_expression
        parent = node.parent
        if parent is not None and parent.type == "await_expression":
            continue

        # Find enclosing async_block
        async_block = _enclosing_async_block(node)
        if async_block is None:
            continue

        # Check that the async_block is under a tokio::spawn call
        if not _is_async_block_under_tokio_spawn(async_block, source):
            continue

        # Skip test code
        enclosing_fn = _find_enclosing_fn(node)
        if enclosing_fn is not None and in_test_cfg(enclosing_fn, source):
            continue

        # Deduplicate by (line, col)
        line, col = line_col(node)
        if (line, col) in seen:
            continue
        seen.add((line, col))

        fn_node = _find_enclosing_fn(node)
        fname = fn_name(fn_node, source) if fn_node is not None else "?"

        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(node, source),
            "message": (
                f"fn `{fname}`: `.{method}()` on a blocking "
                "std::sync / parking_lot primitive called inside "
                "`tokio::spawn(async ...)` -- this stalls a tokio "
                "worker thread for the duration of the lock hold, "
                "causing denial of service under contention. "
                "Use `tokio::task::spawn_blocking` to wrap the "
                "lock acquisition, or switch to "
                "`tokio::sync::Mutex` / `tokio::sync::RwLock` and "
                "call `.lock().await`."
            ),
        })

    return hits
