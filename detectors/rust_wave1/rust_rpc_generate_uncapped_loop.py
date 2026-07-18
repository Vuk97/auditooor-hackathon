"""
rust_rpc_generate_uncapped_loop.py

Flags async RPC/handler functions that accept a caller-supplied numeric
count parameter (u32 / u64 / usize / i32) and drive a `for _ in 0..param`
(or `0..*param`) loop whose body contains at least one `.await` or `.push(`
call, without a preceding cap guard (`if param > CONST { return Err(...) }`
or `.min(CONST)` clamping on the param).

This is an O(N)-work-per-request DoS surface: a caller can supply a large
count and force the server to perform an unbounded number of async round-
trips or heap pushes proportional to the attacker-controlled value.

Verified real surface:
  zebra-rpc/src/methods.rs  `async fn generate(&self, num_blocks: u32)`
  Line ~2937: `for _ in 0..num_blocks { rpc.get_block_template(...).await }`.
  No guard on `num_blocks` other than a PoW-disabled check (not a count cap).

Match conditions (ALL required, comment-stripped body):
  1. Function has `async` keyword in signature.
  2. Signature declares exactly one plain numeric parameter (u32 / u64 /
     usize / i32); the parameter name is captured.
  3. Body contains a bare `for _ in 0..PARAM` or `for _ in 0..*PARAM`
     loop where PARAM matches the captured parameter name.
  4. The loop body (inner braces) contains at least one `.await` or
     `.push(` call, confirming expensive O(N) work per iteration.
  5. Body has NO preceding cap guard:
       - `if PARAM > N { return Err(...) }` / `if PARAM >= N`
       - `.min(` applied to PARAM
       - named constant patterns: MAX_*, MAX_COUNT, MAX_BLOCKS, etc.
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
# Signal 1 — async function
# ---------------------------------------------------------------------------
_ASYNC_RE = re.compile(r"\basync\b")

# ---------------------------------------------------------------------------
# Signal 2 — numeric parameter in signature
#
# Captures the parameter name from a signature like:
#   fn generate(&self, num_blocks: u32)
#   fn foo(count: u64)
#   fn handler(&self, n: usize, ...)
#
# We allow one or more params in the signature but capture the first plain
# numeric-typed one (u32 / u64 / usize / i32).  We deliberately exclude
# Option<u32> patterns to avoid optional-height params that are always
# checked before use.
# ---------------------------------------------------------------------------
_NUMERIC_PARAM_RE = re.compile(
    r"\b(\w+)\s*:\s*(?:u32|u64|usize|i32)\b"
    r"(?!\s*>)"  # exclude generic like `Option<u32>` by not matching > after the type
)

# ---------------------------------------------------------------------------
# Signal 3 — bare `for _ in 0..PARAM` loop (or `0..*PARAM`)
#
# We build this dynamically after capturing the param name.
# ---------------------------------------------------------------------------
def _for_loop_re(param: str) -> re.Pattern:
    """Return a compiled regex matching `for _ in 0..PARAM` or `0..*PARAM`."""
    escaped = re.escape(param)
    return re.compile(
        rf"\bfor\s+_\s+in\s+0\s*\.\.\s*\*?\s*{escaped}\s*\{{",
        re.DOTALL,
    )

# ---------------------------------------------------------------------------
# Signal 4 — expensive O(N) work inside the loop body
#
# We look for .await or .push( anywhere in the loop body text.
# ---------------------------------------------------------------------------
_LOOP_WORK_RE = re.compile(r"\.await\b|\.push\s*\(")

# ---------------------------------------------------------------------------
# Guard patterns — any one present means the function has a cap
#
# We look in the body text BEFORE the loop for:
#   - `if PARAM > N` / `if PARAM >= N` (early return check)
#   - `.min(` applied somewhere with PARAM context
#   - Explicit MAX_* constant names
# ---------------------------------------------------------------------------
def _guard_res(param: str) -> list[re.Pattern]:
    escaped = re.escape(param)
    return [
        # if param > N (literal int) or if param > MAX_CONST (named constant)
        re.compile(
            rf"\bif\s+\*?\s*{escaped}\s*(?:>|>=)\s*(?:\d|\w+)",
            re.IGNORECASE,
        ),
        # param.min( or .min(MAX or param clamped
        re.compile(
            rf"\b{escaped}\s*\.\s*min\s*\(",
            re.IGNORECASE,
        ),
        # generic cap constants
        re.compile(
            r"\b(?:MAX_COUNT|MAX_BLOCKS?|MAX_LIMIT|MAX_NUM|MAX_SIZE|MAX_ITERATIONS?|MAX_REQUESTS?)\b",
            re.IGNORECASE,
        ),
    ]


def _sig_text(fn_node, source: bytes) -> str:
    """Return the function signature text (before the body block)."""
    body = fn_body(fn_node)
    if body is not None:
        return source[fn_node.start_byte:body.start_byte].decode("utf-8", errors="replace")
    return text_of(fn_node, source)


def _is_async_fn(fn_node, source: bytes) -> bool:
    return bool(_ASYNC_RE.search(_sig_text(fn_node, source)))


def _capture_numeric_param(fn_node, source: bytes) -> str | None:
    """Return the name of the first plain numeric (u32/u64/usize/i32) parameter,
    or None if none found."""
    sig = _sig_text(fn_node, source)
    # Exclude Option<u32> shapes: those contain `<` right after the type
    # The regex already guards via negative lookahead; find the first match.
    m = _NUMERIC_PARAM_RE.search(sig)
    if m:
        return m.group(1)
    return None


def _for_loop_body_text(body_text: str, loop_re: re.Pattern) -> str | None:
    """Find the for-loop matched by loop_re and return the text of its brace body.
    Returns None if no loop found. This is a simple brace-counting extractor."""
    m = loop_re.search(body_text)
    if not m:
        return None
    # Find the opening brace position (the loop_re ends at '{')
    brace_start = m.end() - 1  # position of '{'
    depth = 0
    i = brace_start
    while i < len(body_text):
        c = body_text[i]
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return body_text[brace_start:i + 1]
        i += 1
    # Unclosed brace — return remainder
    return body_text[brace_start:]


def _has_cap_guard(body_text: str, param: str) -> bool:
    guards = _guard_res(param)
    return any(g.search(body_text) for g in guards)


def run(tree, source: bytes, filepath: str):
    hits = []

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        # Gate 1: must be async
        if not _is_async_fn(fn, source):
            continue

        # Gate 2: must have a plain numeric parameter
        param = _capture_numeric_param(fn, source)
        if param is None:
            continue

        body = fn_body(fn)
        if body is None:
            continue

        body_text = body_text_nocomment(body, source)

        # Gate 3: must have `for _ in 0..param` (or `0..*param`) loop
        loop_re = _for_loop_re(param)
        if not loop_re.search(body_text):
            continue

        # Gate 4: loop body must contain .await or .push(
        loop_body = _for_loop_body_text(body_text, loop_re)
        if loop_body is None:
            continue
        if not _LOOP_WORK_RE.search(loop_body):
            continue

        # Gate 5: must NOT have a cap guard anywhere in the body
        if _has_cap_guard(body_text, param):
            continue

        name = fn_name(fn, source)

        # Find the for-loop node for a precise location
        hit_node = body
        for node in walk_no_nested_fn(body):
            if node.type == "for_expression":
                node_text = text_of(node, source)
                if f"0..{param}" in node_text or f"0..*{param}" in node_text:
                    hit_node = node
                    break

        line, col = line_col(hit_node)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(hit_node, source),
            "message": (
                f"async fn `{name}` accepts caller-supplied `{param}: u32/u64/usize` "
                f"and runs `for _ in 0..{param} {{ ... .await }}` with no upper-bound cap. "
                "An attacker can pass an arbitrarily large count to trigger O(N) "
                "async work and heap growth, causing denial of service (resource "
                "exhaustion / node stall). Add a cap guard: "
                f"`if {param} > MAX_COUNT {{ return Err(...) }}`."
            ),
        })

    return hits
