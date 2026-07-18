"""
rust_spawn_blocking_expect_panics_async_task.py

Flags the double-panic pattern in async functions:

    tokio::task::spawn_blocking(move || {
        expr.expect("inner msg")       // panic A: inside blocking thread
    })
    .await
    .expect("outer msg")               // panic B: propagated into async task

When the closure panics (panic A), tokio wraps it in a JoinError.
The outer .expect/.unwrap on the JoinHandle then re-panics (panic B) in the
calling async task context.  If the async fn is an RPC handler, any
caller who can trigger the inner failure crashes that handler task.

Also catches the indirect form (closure variable):

    let f = |...| {
        tokio::task::spawn_blocking(move || { expr.expect(...) })
    };
    f(...).await.expect(...)

Detection signals (ALL must be present, no test code):

1. The enclosing function is `async fn`.
2. The body text (comment-stripped) contains `spawn_blocking`.
3. The body contains an inner .expect() or .unwrap() call that appears
   BEFORE the closing `})` of the spawn_blocking closure.  Approximated by
   requiring .expect/.unwrap to appear inside the `spawn_blocking(` ... `})`
   sub-string in the comment-stripped body.
4. The body contains `.await` followed within 80 chars by `.expect(` or
   `.unwrap(` — i.e., the JoinHandle is immediately awaited and the
   result is unwrapped without error handling.

Guard (suppressor): if the body contains `.wait_for_panics()` (Zebra's own
helper that converts panics to errors) we skip, as the team has already
applied a structured mitigation.  Also skip the pattern when the outer
.await.unwrap() is part of an `Ok(...)` or `?`-chain (i.e. the outer
consumer is already error-checking via `?`).
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
    IDENT,
)

# ---------------------------------------------------------------------------
# Signal 1 - async fn signature
# ---------------------------------------------------------------------------
_ASYNC_SIG_RE = re.compile(r"\basync\b")


def _is_async_fn(fn_node, source: bytes) -> bool:
    body = fn_body(fn_node)
    if body is not None:
        sig_text = source[fn_node.start_byte:body.start_byte].decode("utf-8", errors="replace")
    else:
        sig_text = source[fn_node.start_byte:fn_node.end_byte].decode("utf-8", errors="replace")
    return bool(_ASYNC_SIG_RE.search(sig_text))


# ---------------------------------------------------------------------------
# Signal 2 - spawn_blocking present in body
# ---------------------------------------------------------------------------
_SPAWN_BLOCKING_RE = re.compile(r"\bspawn_blocking\s*\(")


# ---------------------------------------------------------------------------
# Signal 3 - inner .expect/.unwrap inside the spawn_blocking closure
#
# Strategy: locate the `spawn_blocking(` token, then scan forward for the
# first `})` that closes the closure (crude but robust enough for the common
# patterns we target).  Check if `.expect(` or `.unwrap(` appears before it.
# ---------------------------------------------------------------------------
_INNER_PANIC_RE = re.compile(r"\.(?:expect|unwrap)\s*\(")


def _find_closure_end(text: str, start: int) -> int:
    """Find the index of the '}' that closes the move closure passed to
    spawn_blocking, starting from ``start`` (the position of the opening
    '(' of spawn_blocking).

    We do a simple brace-counting pass: enter on '{', exit on '}'.
    The spawn_blocking closure looks like:
        spawn_blocking(move || { ... })
    We look for the first '(' to get into the argument list, then count
    '{' / '}' to find the balanced end.  Returns -1 if not found.
    """
    # Skip to the '(' that opens the argument list of spawn_blocking
    paren_open = text.find('(', start)
    if paren_open < 0:
        return -1

    depth = 0
    brace_depth = 0
    in_closure_brace = False
    i = paren_open + 1
    while i < len(text):
        c = text[i]
        if c == '(':
            depth += 1
        elif c == ')':
            if depth == 0:
                # Closed the spawn_blocking argument list
                # The '}' before this is the closure end
                return i - 1
            depth -= 1
        elif c == '{':
            brace_depth += 1
            in_closure_brace = True
        elif c == '}':
            if brace_depth > 0:
                brace_depth -= 1
                if brace_depth == 0 and in_closure_brace:
                    # This '}' closes the closure body; next ')' closes spawn_blocking
                    return i
        i += 1
    return -1


def _has_inner_panic_in_closure(body_text: str) -> tuple[bool, int]:
    """Return (found, approx_offset_in_body_text) for the first spawn_blocking
    whose CLOSURE BODY (before the closing '}') contains an .expect/.unwrap."""
    pos = 0
    while True:
        m_sb = _SPAWN_BLOCKING_RE.search(body_text, pos)
        if not m_sb:
            return False, -1
        sb_start = m_sb.start()
        # Find the end of the closure body using brace counting
        closure_end = _find_closure_end(body_text, sb_start)
        if closure_end < 0:
            pos = sb_start + 1
            continue
        # The segment is from spawn_blocking( up to and including the closing }
        segment = body_text[sb_start:closure_end + 1]
        if _INNER_PANIC_RE.search(segment):
            return True, sb_start
        pos = closure_end + 1
    return False, -1


# ---------------------------------------------------------------------------
# Signal 4 - outer .await + immediate .expect/.unwrap
#
# Matches `.await.expect(` or `.await.unwrap(` with up to 80 chars between
# them (allows line breaks, the `?` operator is NOT one of these).
# ---------------------------------------------------------------------------
_OUTER_AWAIT_PANIC_RE = re.compile(
    r"\.await[\s\S]{0,80}?\.(?:expect|unwrap)\s*\("
)

# ---------------------------------------------------------------------------
# Guard - wait_for_panics() converts JoinError to a proper error Result.
# If present anywhere in the function body after spawn_blocking, the team has
# already mitigated the direct propagation path.
# ---------------------------------------------------------------------------
_WAIT_FOR_PANICS_RE = re.compile(r"\bwait_for_panics\s*\(")


def run(tree, source: bytes, filepath: str) -> list[dict]:
    hits = []

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        # Signal 1: async fn
        if not _is_async_fn(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        body_text = body_text_nocomment(body, source)

        # Signal 2: spawn_blocking present
        if not _SPAWN_BLOCKING_RE.search(body_text):
            continue

        # Guard: wait_for_panics present => already mitigated
        if _WAIT_FOR_PANICS_RE.search(body_text):
            continue

        # Signal 3: inner .expect/.unwrap inside the spawn_blocking closure
        inner_found, inner_offset = _has_inner_panic_in_closure(body_text)
        if not inner_found:
            continue

        # Signal 4: outer .await followed by .expect/.unwrap
        if not _OUTER_AWAIT_PANIC_RE.search(body_text):
            continue

        name = fn_name(fn, source)

        # Point the hit at the spawn_blocking call expression in the body
        # by finding the first spawn_blocking node (type=call_expression or
        # macro_invocation) in the body tree.
        hit_node = body
        from _util import walk_no_nested_fn, text_of as _text_of
        for n in walk_no_nested_fn(body):
            if n.type in ("call_expression", "macro_invocation"):
                t = _text_of(n, source)
                if "spawn_blocking" in t:
                    hit_node = n
                    break

        line, col = line_col(hit_node)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(hit_node, source),
            "message": (
                f"async fn `{name}` calls `tokio::task::spawn_blocking` with an "
                "inner `.expect()`/`.unwrap()` inside the closure, then does "
                "`.await.expect()`/`.await.unwrap()` on the JoinHandle. "
                "When the closure panics, tokio wraps it in a JoinError; the outer "
                "`.expect()`/`.unwrap()` re-panics in the calling async task context. "
                "If this fn is an RPC handler, any caller who can trigger the inner "
                "failure can crash the handler task (node DoS). "
                "Fix: replace the outer `.await.expect()` with "
                "`.await.map_err(|e| RpcError::internal(e))?` and propagate the "
                "JoinError as a recoverable RPC error."
            ),
        })

    return hits
