"""
rust_consensus_heightdiff_i64_to_u32_panicking_expect.py

Flags functions that:
  (1) Perform signed height arithmetic producing an i64 / HeightDiff value
      via subtraction of a height parameter from another height (e.g.
      `height - network.height_for_first_halving()`).
  (2) Optionally do further arithmetic on that i64 result (addition,
      multiplication, division, assignment to a local `address_period`-style
      variable).
  (3) Call `.try_into().expect(<msg>)` or `.try_into().unwrap()` on the
      resulting i64 value without a prior negativity guard
      (`if <val> < 0 { return }`, `< 0 =>`, `.checked_*`, `assert!(...>= 0)`).

This panics at runtime when the intermediate i64 value is negative, which
can occur when `height_for_first_halving` (or an analogous network-parameter
height) exceeds the `height` argument -- a condition that arises on custom
test-networks or misconfigured consensus parameters.

Structural shape (class-invariant):
  pub fn funding_stream_address_period(height: Height, network: &N) -> u32 {
      let height_after = height - network.height_for_first_halving(); // i64
      let address_period = (height_after + halving_interval) / change_interval;
      address_period               // i64
          .try_into()
          .expect("all values are positive ...")  // panics if negative!
  }

Verified real surface:
  zebra-chain/src/parameters/network/subsidy.rs  fn funding_stream_address_period
  Lines 292-299: height subtraction to HeightDiff (i64), arithmetic, then
  `.try_into().expect(...)` with no sign guard.

Severity: HIGH
Rubric row: Non-distributed DoS against an individual node (consensus panic).
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
# Signal 1 - height subtraction assignment in body
# The function body must contain a `let <var> = ... - ...` expression where
# the subtraction involves a height-related variable or method chain.
# Patterns cover:
#   let height_after = height - network.height_for_first_halving()
#   let height_after = (height as i64) - (network.height_for_first_halving() as i64)
#   let diff = height - halving_height
# ---------------------------------------------------------------------------
_HEIGHT_DIFF_ASSIGN_RE = re.compile(
    r"let\s+\w+\s*=\s*[\w\(\) \t]*-\s*[\w\(\)\. \t]+",
)

# ---------------------------------------------------------------------------
# Signal 2 - .try_into().expect() or .try_into().unwrap() in the body
# This is the narrowing step that panics on negative values.
# ---------------------------------------------------------------------------
_TRY_INTO_PANIC_RE = re.compile(
    r"\.try_into\s*\(\s*\)\s*\.(?:expect|unwrap)\s*\(",
)

# ---------------------------------------------------------------------------
# Signal 3 - the function return type narrows to u32, usize, or u64.
# We check for "-> u32" or "-> usize" in the signature text.
# ---------------------------------------------------------------------------
_RETURN_NARROW_RE = re.compile(
    r"->\s*(?:u32|usize|u64)\b",
)

# ---------------------------------------------------------------------------
# Guard patterns - presence of ANY of these before the try_into call means
# the developer DID add a negativity check, so we skip the function.
# ---------------------------------------------------------------------------
_GUARD_PATTERNS = [
    # Explicit negativity check: `if <val> < 0`
    r"if\s+\w+\s*<\s*0",
    # Match arm for negative: `_ if <val> < 0 =>`
    r"if\s+\w[\w\.]*\s*<\s*0\s*=>",
    # checked_add / checked_sub / checked_mul / checked_div on the variable
    r"\.checked_(?:add|sub|mul|div)\b",
    # saturating_sub
    r"\.saturating_sub\b",
    # assert positive: assert!(x >= 0) or debug_assert!(x > 0)
    r"(?:debug_)?assert!\s*\(\s*\w[\w\.]*\s*(?:>=|>)\s*0",
    # max(0, ...)  / .max(0)
    r"\.max\s*\(\s*0\s*\)",
    r"\bmax\s*\(\s*0\s*,",
    # i64::try_from guard + ? operator (returns None/Err on overflow)
    r"\.try_into\s*\(\s*\)\s*\?",
    # NonNegative or .is_negative() guard
    r"\.is_negative\s*\(\s*\)",
    r"\bNonNegative\b",
]
_GUARD_RES = [re.compile(p, re.IGNORECASE) for p in _GUARD_PATTERNS]


def _fn_sig_text(fn_node, source: bytes) -> str:
    body = fn_body(fn_node)
    if body is not None:
        return source[fn_node.start_byte:body.start_byte].decode("utf-8", errors="replace")
    return source[fn_node.start_byte:fn_node.end_byte].decode("utf-8", errors="replace")


def _has_negativity_guard(body_text: str) -> bool:
    return any(g.search(body_text) for g in _GUARD_RES)


def run(tree, source: bytes, filepath: str):
    hits = []

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        # Signal 3: return type must narrow to u32 / usize / u64
        sig_text = _fn_sig_text(fn, source)
        if not _RETURN_NARROW_RE.search(sig_text):
            continue

        body_text = body_text_nocomment(body, source)

        # Signal 1: body must contain a height subtraction assignment
        if not _HEIGHT_DIFF_ASSIGN_RE.search(body_text):
            continue

        # Signal 2: body must call .try_into().expect() or .try_into().unwrap()
        if not _TRY_INTO_PANIC_RE.search(body_text):
            continue

        # Guard: skip if any negativity guard is present before the conversion
        if _has_negativity_guard(body_text):
            continue

        name = fn_name(fn, source)

        # Locate the .try_into().expect call as the anchor node
        hit_node = body
        for node in walk_no_nested_fn(body):
            if node.type == "call_expression":
                node_text = text_of(node, source)
                if _TRY_INTO_PANIC_RE.search(node_text):
                    hit_node = node
                    break

        line, col = line_col(hit_node)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(hit_node, source),
            "message": (
                f"fn `{name}` performs signed height subtraction (i64/HeightDiff) "
                "and then narrows the result to u32/usize via `.try_into().expect()` "
                "or `.try_into().unwrap()` without a prior sign-check guard. "
                "If the subtracted height exceeds the argument (e.g. on a custom "
                "testnet or misconfigured network parameters), the intermediate i64 "
                "is negative, `i64::try_into::<u32>()` returns `Err`, and "
                "`.expect()` / `.unwrap()` panics, crashing the node process. "
                "Fix: return `None`/`Err` when the intermediate value is < 0, "
                "or use `.try_into().ok()?` instead."
            ),
        })

    return hits
