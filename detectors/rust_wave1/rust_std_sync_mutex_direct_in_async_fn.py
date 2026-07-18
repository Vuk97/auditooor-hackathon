"""
rust_std_sync_mutex_direct_in_async_fn.py

Flags async fn bodies that call .lock() on a std::sync::Mutex (or RwLock)
directly - without wrapping the call in a tokio::task::spawn_blocking closure.

Structural shape (class-invariant):

    async fn handler(&self) -> Result<SomeResponse> {
        // BAD: self.address_book is Arc<std::sync::Mutex<AddressBook>>
        // recently_live_peers internally calls self.lock() on a std::sync::Mutex
        let connections = self.address_book.recently_live_peers(Utc::now()).len();
        // ...
    }

    // Also flags the direct form:
    async fn download_and_verify(&mut self, ...) -> Result<...> {
        // BAD: direct .lock() in async fn body, no spawn_blocking wrapping
        let _ = self.past_lookahead_limit_sender
            .lock().expect("...").send(true);
    }

CORRECT fix:

    async fn handler_fixed(&self) -> Result<SomeResponse> {
        let address_book = self.address_book.clone();
        let connections = tokio::task::spawn_blocking(move || {
            address_book.lock().unwrap().recently_live_peers(Utc::now()).len()
        }).await?;
        // ...
    }

Why this matters:
  std::sync::Mutex::lock() is a BLOCKING OS syscall (futex/pthread_mutex_lock).
  When called from an async fn running on a tokio worker thread, it blocks that
  thread for as long as the OS schedules. When the thread pool is saturated and
  another task holds the mutex and needs a tokio worker thread to make progress,
  this produces a deadlock. Even without deadlock, it starves all other async
  tasks scheduled on that worker thread.

  Zebra documents this risk explicitly in issue #1976 and fixed candidate_set.rs
  and peer_cache_updater.rs with spawn_blocking - but left several RPC handlers
  and the sync downloader with direct .lock() calls.

Verified real surfaces:
  zebra-rpc/src/methods.rs  async fn get_info   (calls self.address_book.recently_live_peers
                                                  which internally calls Mutex::lock)
  zebra-rpc/src/methods.rs  async fn get_peer_info (same)
  zebra-network/src/peer_set/candidate_set.rs  NOTE: ALREADY FIXED with spawn_blocking
  zebrad/src/components/sync/downloads.rs  async fn download_and_verify (direct .lock())

Exclusions:
  - .lock().await calls: parent is await_expression, meaning this is a
    futures::lock::Mutex or tokio::sync::Mutex (async-aware), safe.
  - Calls inside a spawn_blocking(move || { ... }) closure: intentionally
    delegated to a blocking thread, correct pattern.
  - Non-async fn bodies: blocking in a sync thread is acceptable.
  - #[test] / #[cfg(test)] annotated functions: test code.

Severity: HIGH
Rubric: Non-distributed DoS against an individual node or wallet.
"""

from __future__ import annotations

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
    IDENT,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_async_fn(fn_node, source: bytes) -> bool:
    """Return True iff the function_item has the async modifier."""
    for c in fn_node.children:
        if c.type == "function_modifiers":
            if b"async" in source[c.start_byte:c.end_byte]:
                return True
    return False


def _is_await_lock(lock_call_node) -> bool:
    """Return True if the .lock() call_expression is the direct child of an
    await_expression, i.e. the form `expr.lock().await` which indicates an
    async-aware Mutex (futures::lock::Mutex, tokio::sync::Mutex).

    Tree shape:
        await_expression
          call_expression      <- lock_call_node
            field_expression
              ...
              field_identifier  "lock"
    """
    parent = lock_call_node.parent
    return parent is not None and parent.type == "await_expression"


def _in_spawn_blocking_closure(node, source: bytes) -> bool:
    """Walk up from node.  If we cross a closure_expression that is directly
    passed as an argument to a call whose function expression contains the
    text 'spawn_blocking', return True.

    Tree shape for spawn_blocking(move || { ... .lock() ... }).await:
        await_expression
          call_expression                           <- outer chain
            call_expression                         <- spawn_blocking(...)
              field_expression  spawn_blocking      <- gp_func
              arguments
                closure_expression                  <- n (closure ancestor)
                  block
                    ... .lock() ...
    """
    inside_any_closure = False
    n = node.parent
    while n is not None:
        if n.type == "function_item":
            # Reached the enclosing function without finding spawn_blocking
            break
        if n.type == "closure_expression":
            inside_any_closure = True
            # Is this closure an argument directly to spawn_blocking?
            parent = n.parent
            if parent is not None and parent.type == "arguments":
                gp = parent.parent
                if gp is not None and gp.type == "call_expression":
                    gp_func = gp.children[0] if gp.children else None
                    if gp_func is not None:
                        func_text = source[gp_func.start_byte:gp_func.end_byte].decode(
                            "utf-8", errors="replace"
                        )
                        if "spawn_blocking" in func_text:
                            return True
        n = n.parent

    # Indirect pattern: closure stored as a variable then passed to spawn_blocking.
    # E.g.: let worker = move || { mutex.lock() }; spawn_blocking(move || worker()).await
    # If the lock is inside ANY closure AND the enclosing async fn uses spawn_blocking,
    # treat conservatively as safe to avoid FPs.
    if inside_any_closure:
        n2 = node.parent
        while n2 is not None:
            if n2.type == "function_item":
                fn_text = source[n2.start_byte:n2.end_byte].decode("utf-8", errors="replace")
                if "spawn_blocking" in fn_text:
                    return True
                break
            n2 = n2.parent

    return False


def _find_direct_lock_calls(body_node, source: bytes) -> list:
    """Walk the body and return call_expression nodes that directly call .lock()
    without spawn_blocking wrapping and without being .lock().await."""
    hits = []
    for node in walk(body_node):
        if node.type != "call_expression":
            continue
        if len(node.children) < 2:
            continue
        head = node.children[0]
        if head.type != "field_expression":
            continue
        # Extract the direct method name from the field_expression
        method_name = None
        for c in head.children:
            if c.type == "field_identifier":
                method_name = source[c.start_byte:c.end_byte].decode("utf-8", errors="replace")
                break
        if method_name not in ("lock", "read", "write"):
            continue
        # Exclude .lock().await (async-aware mutex)
        if _is_await_lock(node):
            continue
        # Exclude calls inside spawn_blocking closures
        if _in_spawn_blocking_closure(node, source):
            continue
        hits.append(node)
    return hits


# ---------------------------------------------------------------------------
# Main detector entry point
# ---------------------------------------------------------------------------

def run(tree, source: bytes, filepath: str):
    hits = []

    for fn in function_items(tree.root_node):
        # Only flag async fn
        if not _is_async_fn(fn, source):
            continue

        # Skip test code
        if in_test_cfg(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        lock_calls = _find_direct_lock_calls(body, source)
        if not lock_calls:
            continue

        name = fn_name(fn, source)

        # Report each distinct lock call (de-dup by line to avoid chained
        # a.lock().unwrap().method() reporting twice)
        reported_lines = set()
        for call_node in lock_calls:
            line, col = line_col(call_node)
            if line in reported_lines:
                continue
            reported_lines.add(line)

            hits.append({
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(call_node, source),
                "message": (
                    f"async fn `{name}` calls `.lock()` (or `.read()`/`.write()`) "
                    "directly without wrapping in `tokio::task::spawn_blocking`. "
                    "This is a blocking OS syscall on a tokio worker thread. "
                    "If the thread pool is saturated and the mutex holder needs "
                    "a worker thread to make progress, a self-deadlock occurs; "
                    "at minimum it starves other async tasks on the same worker. "
                    "Fix: move the critical section into "
                    "`tokio::task::spawn_blocking(move || { ... }).await`."
                ),
            })

    return hits
