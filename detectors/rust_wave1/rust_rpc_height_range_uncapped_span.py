"""
rust_rpc_height_range_uncapped_span.py

Flags functions that construct a RangeInclusive<Height> (or equivalent
block-index range) from two caller-supplied optional integers (start and
end) where:

  (1) A missing or zero `end` value is silently defaulted to the current
      chain tip height via a `match end { Some(0) | None => chain_height ... }`
      arm.
  (2) The range span `(end - start)` is NEVER checked against a constant
      maximum window (no `if end - start > MAX_WINDOW { return Err }` guard,
      no `.min(MAX_...)` on the span, no `too_large` / `max_span` pattern).
  (3) The function returns `Ok(start..=end)` - forwarding the uncapped range
      directly to the caller.

Structural shape (class-invariant):
  fn build_height_range(start: Option<u32>, end: Option<u32>, chain_height: Height)
      -> Result<RangeInclusive<Height>> {
      let end = match end { Some(0) | None => chain_height, ... };
      // NO: if end - start > MAX { return Err(...) }
      Ok(start..=end)
  }

Verified real surface:
  zebra-rpc/src/methods.rs  fn build_height_range  (line ~4441)
  The function silently sets end to chain_height when None or 0, then
  returns Ok(start..=end) with no span-width cap. An attacker passes
  start=0 / end=None to trigger a full-chain O(N) state scan.

Severity: HIGH
Rubric: Non-distributed DoS against an individual node or wallet.
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
# Signal 1 - return type includes RangeInclusive
# The function must return something that contains a RangeInclusive (or a
# Result wrapping one), confirming this is a block-height range builder.
# ---------------------------------------------------------------------------
_RETURN_RANGE_RE = re.compile(
    r"RangeInclusive\s*<",
)

# ---------------------------------------------------------------------------
# Signal 2 - both optional parameters (start + end as Option<...>)
# The function signature must accept Option-typed start and end parameters.
# ---------------------------------------------------------------------------
_PARAM_OPTION_RE = re.compile(
    r"Option\s*<[^>]+>\s*,[\s\S]*?Option\s*<[^>]+>",
)

# ---------------------------------------------------------------------------
# Signal 3 - tip-default arm: `match end { Some(0) | None => chain_height`
# This is the distinctive structural smell: silently defaulting a missing or
# zero `end` to the chain tip rather than rejecting or capping it.
# ---------------------------------------------------------------------------
_TIP_DEFAULT_ARM_RE = re.compile(
    r"match\s+\w+\s*\{[^}]*Some\s*\(\s*0\s*\)\s*\|\s*None\s*=>",
)

# ---------------------------------------------------------------------------
# Signal 4 - uncapped return: Ok(start..=end)
# The range is returned directly to the caller without any width restriction.
# ---------------------------------------------------------------------------
_UNCAPPED_RETURN_RE = re.compile(
    r"Ok\s*\(\s*\w+\s*\.{2}=\s*\w+\s*\)",
)

# ---------------------------------------------------------------------------
# Guard patterns - presence of ANY of these means the developer DID cap the
# span, so we should NOT flag the function.
# ---------------------------------------------------------------------------
_GUARD_PATTERNS = [
    # Arithmetic span comparison: (end - start) > N, span > N
    r"(?:end|end_height)\s*[\-\.]\s*(?:start|start_height)[\s\S]{0,60}(?:>|>=)\s*\d",
    r"\bspan\b[\s\S]{0,20}(?:>|>=)\s*\d",
    # .min() applied to a span-size constant
    r"\.min\s*\(\s*(?:MAX_BLOCK_RANGE|MAX_HEIGHT|MAX_SPAN|MAX_RANGE|MAX_HEIGHT_RANGE|max_range|max_span|max_height)",
    r"\.clamp\s*\(",
    # Explicit span-cap constant names
    r"\bMAX_BLOCK_RANGE\b",
    r"\bMAX_HEIGHT_RANGE\b",
    r"\bMAX_HEIGHT_SPAN\b",
    r"\bMAX_SPAN\b",
    r"\bmax_span\b",
    r"\bmax_range\b",
    # Error strings indicating a range-size check
    r"range\s+too\s+large",
    r"span\s+too\s+large",
    r"too\s+many\s+blocks",
    r"exceeds.*(?:max|limit|cap)",
    r"(?:max|limit|cap).*(?:exceeded|too large)",
    # Saturating subtraction in a guard comparison
    r"saturating_sub\s*\([^)]*\)\s*(?:>|>=)\s*\d",
    # len/count check on the range
    r"(?:height_range|range)\s*\.\s*(?:len|count)\s*\(\s*\)\s*(?:>|>=)\s*\d",
]
_GUARD_RES = [re.compile(p, re.IGNORECASE) for p in _GUARD_PATTERNS]


def _fn_signature_text(fn_node, source: bytes) -> str:
    """Return the function signature text (before the body block)."""
    body = fn_body(fn_node)
    if body is not None:
        return source[fn_node.start_byte:body.start_byte].decode("utf-8", errors="replace")
    return source[fn_node.start_byte:fn_node.end_byte].decode("utf-8", errors="replace")


def _has_span_cap_guard(body_text: str) -> bool:
    return any(g.search(body_text) for g in _GUARD_RES)


def run(tree, source: bytes, filepath: str):
    hits = []

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        # Signal 1: return type must include RangeInclusive
        sig_text = _fn_signature_text(fn, source)
        if not _RETURN_RANGE_RE.search(sig_text):
            continue

        # Signal 2: must have two Option-typed parameters (start + end)
        if not _PARAM_OPTION_RE.search(sig_text):
            continue

        body_text = body_text_nocomment(body, source)

        # Signal 3: tip-default arm in a match on end/start
        if not _TIP_DEFAULT_ARM_RE.search(body_text):
            continue

        # Signal 4: returns Ok(start..=end) directly
        if not _UNCAPPED_RETURN_RE.search(body_text):
            continue

        # Guard: if any span-cap guard is present, skip
        if _has_span_cap_guard(body_text):
            continue

        name = fn_name(fn, source)

        # Find the tip-default match arm as the anchor for the hit location
        hit_node = None
        for node in walk_no_nested_fn(body):
            if node.type == "match_expression":
                node_text = text_of(node, source)
                if _TIP_DEFAULT_ARM_RE.search(node_text):
                    hit_node = node
                    break
        if hit_node is None:
            hit_node = body

        line, col = line_col(hit_node)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(hit_node, source),
            "message": (
                f"fn `{name}` builds a `RangeInclusive<Height>` from optional "
                "caller-supplied start/end integers and silently defaults a missing "
                "or zero `end` to the chain tip height, but never checks that the "
                "span `(end - start)` is below a maximum window. An attacker passes "
                "start=0 / end=None to trigger a full-chain O(N) state scan, "
                "causing denial of service (OOM or node stall). Add a "
                "MAX_SCAN_WINDOW constant and reject requests where "
                "`(end - start) > MAX_SCAN_WINDOW`."
            ),
        })

    return hits
