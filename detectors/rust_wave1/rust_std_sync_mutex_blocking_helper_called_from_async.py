"""
rust_std_sync_mutex_blocking_helper_called_from_async.py

Flags async fn bodies that call a SYNC helper function which internally
acquires a std::sync::Mutex / RwLock guard, without wrapping that call in
tokio::task::spawn_blocking.

Unlike the direct-hold-across-await pattern caught by async_await_after_lock,
the lock acquisition here is INVISIBLE at the async call site: the async fn
calls a sync helper, and only by tracing into the callee is the blocking
mutex acquisition visible.

Structural shape (class-invariant):
    fn sync_helper(book: &Arc<Mutex<T>>) -> Vec<Item> {
        book.lock().expect("...").cacheable(now)   // blocks here
    }

    async fn async_caller(...) {
        let items = sync_helper(&self.address_book);  // tokio thread blocks!
        config.update_cache(items).await;
    }

The risk: when sync_helper() blocks waiting for the mutex, it occupies the
tokio executor thread for the full lock-wait duration. Under high contention
(many peers, slow cacheable() O(n) scan) this can starve other futures on
the thread, causing latency spikes or temporary unresponsiveness.

Verified real surface:
    zebra-network/src/peer_cache_updater.rs
        fn cacheable_peers(address_book: &Arc<Mutex<AddressBook>>) -> Vec<MetaAddr>
            calls address_book.lock().expect(...).cacheable(now)

        async fn update_peer_cache_once(config, address_book) -> io::Result<()>
            calls cacheable_peers(address_book)  // <-- flagged site

    The TODO comment in the file explicitly acknowledges:
    // TODO: use spawn_blocking() here, if needed to handle address book mutex load

Severity: HIGH
Rubric: Non-distributed DoS against an individual node or wallet.

Algorithm (within-file, single-pass):
  Phase 1 - collect sync locking helpers:
    For each non-async function_item in the file:
      If its body contains a direct .lock() / .write() / .read() call on
      an Arc/Mutex/RwLock expression (not wrapped in spawn_blocking),
      record the function's name.

  Phase 2 - scan async fn bodies for calls to those helpers:
    For each async function_item in the file:
      Walk its body (no nested functions) looking for call_expression nodes
      whose callee name matches a collected sync-locking helper name.
      If the async fn body also contains an .await at any point (proving it
      is actually using async I/O alongside the sync call), flag the call.
      Exclusion: call wrapped in a spawn_blocking closure.

False-positive controls:
  - Sync helpers that are called exclusively from other sync fns are fine;
    we only flag them when called from an async fn.
  - spawn_blocking wrappers are excluded.
  - Test functions are excluded.
  - Short-duration locks (locks that release before any I/O) are partially
    addressed by the .await-present check (if the async fn never awaits,
    there is no concurrency issue).
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
# Regex: does a function body directly call .lock() / .write() / .read()?
# We look for the bare method call (not preceded by spawn_blocking).
# ---------------------------------------------------------------------------
_DIRECT_LOCK_RE = re.compile(
    r"(?<!\bspawn_blocking)\s*\."
    r"(?P<method>lock|write|read)\s*\(\s*\)"
    r"(?!\s*\.\s*await)",  # exclude async-lock .lock().await
)

# ---------------------------------------------------------------------------
# Regex: is there any .await in the async fn body?
# If there are no .await points the function is technically a sync caller
# wearing an async hat — no executor starvation risk.
# ---------------------------------------------------------------------------
_AWAIT_RE = re.compile(r"\.\s*await\b")

# ---------------------------------------------------------------------------
# Regex: is the call wrapped in spawn_blocking?
# spawn_blocking(move || ... helper_call ... ) or
# spawn_blocking(|| ... helper_call ...)
# We look for spawn_blocking somewhere before the helper call name in a
# window of text to avoid flagging safe wrappers.
# ---------------------------------------------------------------------------
_SPAWN_BLOCKING_RE = re.compile(r"\bspawn_blocking\s*\(")

# ---------------------------------------------------------------------------
# Helpers to detect whether a function_item node has the `async` keyword.
# tree-sitter-rust: async fn has a child token `async` before `fn`.
# ---------------------------------------------------------------------------

def _is_async_fn(fn_node, source: bytes) -> bool:
    """Return True if fn_node is declared `async fn`."""
    for child in fn_node.children:
        if child.type == "async":
            return True
        # The `async` keyword appears as a named child token before `fn`.
        # In some tree-sitter grammars it is an unnamed/text child.
        if child.is_named and text_of(child, source).strip() == "async":
            return True
    # Fallback: inspect raw text before the first `fn` token
    raw = source[fn_node.start_byte:fn_node.end_byte].decode("utf-8", errors="replace")
    fn_kw = raw.find("fn ")
    if fn_kw < 0:
        fn_kw = raw.find("fn\t")
    if fn_kw < 0:
        fn_kw = raw.find("fn\n")
    if fn_kw > 0:
        preamble = raw[:fn_kw]
        if re.search(r"\basync\b", preamble):
            return True
    return False


def _call_names_in_body(body_node, source: bytes) -> list[tuple]:
    """Return list of (call_name, call_node) for direct (non-method) call
    expressions in the async fn body (excluding nested functions).

    We want calls of the shape `helper_fn(args)` — where the callee is a
    bare identifier or path, not a method call `self.method(args)`.
    """
    results = []
    for node in walk_no_nested_fn(body_node):
        if node.type != "call_expression":
            continue
        if len(node.children) == 0:
            continue
        callee = node.children[0]
        # Direct function call: callee is an identifier or scoped path
        if callee.type == "identifier":
            results.append((text_of(callee, source).strip(), node))
        elif callee.type == "scoped_identifier":
            # e.g. module::helper_fn(...)  — extract the final segment
            for c in reversed(callee.children):
                if c.type == "identifier":
                    results.append((text_of(c, source).strip(), node))
                    break
    return results


def run(tree, source: bytes, filepath: str) -> list[dict]:
    hits = []

    # -------------------------------------------------------------------
    # Phase 1: collect names of sync (non-async) functions in this file
    # whose body calls .lock() / .write() / .read() directly.
    # -------------------------------------------------------------------
    sync_locking_helpers: set[str] = set()

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if _is_async_fn(fn, source):
            continue  # only interested in sync helpers here

        body = fn_body(fn)
        if body is None:
            continue

        body_text = body_text_nocomment(body, source)

        # Must have a direct .lock() / .write() / .read() call
        if not _DIRECT_LOCK_RE.search(body_text):
            continue

        # Exclude helpers that are themselves called only inside spawn_blocking
        # (we can't know the call site at this phase, so we just collect the name)
        name = fn_name(fn, source)
        if name and name != "?":
            sync_locking_helpers.add(name)

    if not sync_locking_helpers:
        return []

    # -------------------------------------------------------------------
    # Phase 2: scan async fn bodies for calls to collected helper names.
    # -------------------------------------------------------------------
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if not _is_async_fn(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        body_text = body_text_nocomment(body, source)

        # The async fn must actually have at least one .await (if it never
        # awaits, blocking the thread briefly is not a real concurrency issue
        # for the tokio executor since no other task can interleave).
        if not _AWAIT_RE.search(body_text):
            continue

        caller_name = fn_name(fn, source)

        # Walk the body for call_expression nodes whose callee matches a helper
        for call_name, call_node in _call_names_in_body(body, source):
            if call_name not in sync_locking_helpers:
                continue

            # Exclude: call inside a spawn_blocking closure.
            # Heuristic: look for spawn_blocking in a 200-char window before the call.
            call_offset = call_node.start_byte - body.start_byte
            window_start = max(0, call_offset - 200)
            window = body_text[window_start:call_offset]
            if _SPAWN_BLOCKING_RE.search(window):
                continue

            line, col = line_col(call_node)
            snip = snippet_of(call_node, source)

            hits.append({
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snip,
                "message": (
                    f"async fn `{caller_name}` calls sync helper `{call_name}` "
                    f"which internally acquires a std::sync::Mutex / RwLock guard, "
                    f"blocking the tokio executor thread for the lock-wait duration. "
                    f"Wrap the call in `tokio::task::spawn_blocking(move || "
                    f"{call_name}(...)).await` to offload the blocking work, "
                    f"or restructure so the lock is not held during I/O. "
                    f"(Pattern: indirect mutex-blocking-helper in async context.)"
                ),
            })

    return hits
