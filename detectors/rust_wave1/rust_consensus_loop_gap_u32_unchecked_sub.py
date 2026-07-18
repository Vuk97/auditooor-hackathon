"""
rust_consensus_loop_gap_u32_unchecked_sub.py

Flags functions that walk a sorted-key map (BTreeMap::range or similar) and
compute a gap or distance between two adjacent height values by directly
subtracting raw u32 newtype fields (`height.0 - pending_height.0`) without
`checked_sub` or `saturating_sub`, where the only protection against
underflow is an earlier `if height == ...(pending_height.0 + 1)` branch -
i.e., the invariant is maintained by loop logic, not the type system.

Structural shape (class-invariant):
  let mut pending_height = start_height;
  for (&height, _) in map.range((Excluded(pending_height), Unbounded)) {
      if height == SomeType(pending_height.0 + 1) {
          pending_height = height;
      } else {
          let gap = height.0 - pending_height.0;   // VULN: bare u32 sub
          ...
          break;
      }
  }

If the loop invariant that `height > pending_height` is violated (duplicate
keys, hash-collision, future refactoring of the early-return branch, or
alternative callers of the map that bypass the range filter), the subtraction
panics in debug builds or silently wraps in release, producing a fabricated gap
value that may skip or miscount checkpoint blocks.

The correct fix is `height.0.saturating_sub(pending_height.0)` or
`(height - pending_height)` returning a signed HeightDiff.

Verified real surface:
  zebra-consensus/src/checkpoint.rs  fn target_checkpoint_height  line ~441
  `let gap = height.0 - pending_height.0;`

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
    walk_no_nested_fn,
    text_of,
    IDENT,
)

# ---------------------------------------------------------------------------
# Signal 1 - a for-loop iterating over a sorted map range
# Must contain a `.range(` call in the for-expression, indicating a sorted
# BTreeMap/BTreeSet range walk.
# ---------------------------------------------------------------------------
_FOR_RANGE_RE = re.compile(
    r"\bfor\s*\(\s*[&\*]?\s*\w+\s*,\s*[_\w]+\s*\)\s+in\s+[\w\.]+\s*\.\s*range\s*\(",
    re.DOTALL,
)

# ---------------------------------------------------------------------------
# Signal 2 - the loop body contains a bare .0 - .0 subtraction on a
# height-named variable pair.  Accepts:
#   height.0 - pending_height.0
#   h.0 - prev.0
#   current.0 - last.0
# (any two distinct field-access .0 expressions separated by a bare minus)
# We require at least one side to be a height-flavoured name.
# ---------------------------------------------------------------------------
_BARE_SUB_RE = re.compile(
    r"\b(\w+)\.0\s*-\s*(\w+)\.0\b",
)

_HEIGHT_NAME_RE = re.compile(
    r"(?i)height|block_height|blk_height",
)

# ---------------------------------------------------------------------------
# Signal 3 - an if-equality guard that encodes the +1 continuity check:
#   if height == SomeType(pending_height.0 + 1)
#   if height == block::Height(pending_height.0 + 1)
#   if h == Height(prev.0 + 1)
# This confirms the loop relies on a logic invariant, not the type system.
# ---------------------------------------------------------------------------
_CONTINUITY_GUARD_RE = re.compile(
    r"\bif\s+\w+\s*==\s*[\w:]+\s*\(\s*\w+\.0\s*\+\s*1\s*\)",
    re.DOTALL,
)

# ---------------------------------------------------------------------------
# Guard patterns - presence of ANY of these means the subtraction is already
# safe; skip the function.
# ---------------------------------------------------------------------------
_GUARD_PATTERNS = [
    # checked_sub anywhere between the range binding and the subtraction
    r"\bchecked_sub\s*\(",
    # saturating_sub
    r"\bsaturating_sub\s*\(",
    # wrapping_sub
    r"\bwrapping_sub\s*\(",
    # an ordering assert before the sub (assert!(a > b) / assert!(a >= b))
    r"\bassert!\s*\(\s*\w+\s*(?:>|>=)\s*\w+",
    # a cmp::Ordering or explicit > guard assigned before the sub
    r"cmp\s*::\s*Ordering",
]
_GUARD_RES = [re.compile(p, re.IGNORECASE) for p in _GUARD_PATTERNS]


def _has_safe_guard(body_text: str) -> bool:
    return any(g.search(body_text) for g in _GUARD_RES)


def _find_bare_sub_node(body_node, source: bytes):
    """Walk body to find the first binary_expression node whose text matches
    the bare .0 - .0 pattern on height-flavoured names."""
    for node in walk_no_nested_fn(body_node):
        if node.type != "binary_expression":
            continue
        node_text = text_of(node, source)
        m = _BARE_SUB_RE.search(node_text)
        if m is None:
            continue
        lhs, rhs = m.group(1), m.group(2)
        # At least one side must be height-flavoured
        if _HEIGHT_NAME_RE.search(lhs) or _HEIGHT_NAME_RE.search(rhs):
            return node
    return None


def run(tree, source: bytes, filepath: str):
    hits = []

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        body_text = body_text_nocomment(body, source)

        # Signal 1: must have a for-loop over a .range( call
        if not _FOR_RANGE_RE.search(body_text):
            continue

        # Signal 2: must have a bare .0 - .0 height subtraction
        if not _BARE_SUB_RE.search(body_text):
            continue

        # Check at least one side is height-flavoured
        found_height_sub = False
        for m in _BARE_SUB_RE.finditer(body_text):
            lhs, rhs = m.group(1), m.group(2)
            if _HEIGHT_NAME_RE.search(lhs) or _HEIGHT_NAME_RE.search(rhs):
                found_height_sub = True
                break
        if not found_height_sub:
            continue

        # Signal 3: must have the continuity +1 guard (confirms the invariant
        # is logic-only, not type-enforced)
        if not _CONTINUITY_GUARD_RE.search(body_text):
            continue

        # Guard: if any safe subtraction is already present, skip
        if _has_safe_guard(body_text):
            continue

        name = fn_name(fn, source)

        # Find the bare subtraction node for precise location
        hit_node = _find_bare_sub_node(body, source)
        if hit_node is None:
            hit_node = body

        line, col = line_col(hit_node)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(hit_node, source),
            "message": (
                f"fn `{name}` walks a sorted-map range and computes the gap "
                "between adjacent height values via bare `.0 - .0` u32 subtraction. "
                "The only protection is a `if height == ...(pending.0 + 1)` "
                "branch whose invariant is maintained by loop logic, not the "
                "type system. A future refactoring, duplicate-key edge case, or "
                "callers bypassing the range filter could make the subtrahend "
                "larger, causing a panic in debug builds or silent u32 wrap in "
                "release. Fix: replace with `height.0.saturating_sub(pending_height.0)` "
                "or the signed `(height - pending_height)` returning `HeightDiff`."
            ),
        })

    return hits
