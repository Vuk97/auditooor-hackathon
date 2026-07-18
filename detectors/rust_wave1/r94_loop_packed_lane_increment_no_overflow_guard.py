"""
r94_loop_packed_lane_increment_no_overflow_guard.py

Flags increment/bump/advance fns on a MarketData/Packed/Bitmap/
Registry/Layout/Storage-style struct that mutate a fixed-width lane
inside a packed u256/u128 slot (bit-shift literals, shift-assigns,
bitmask ops, slot[i] indexing) WITHOUT a `< u8::MAX / < u16::MAX /
< MAX_LANE` guard. At lane saturation the next call either panics
(`overflow_error!`, Anchor's `CheckedMath`, Solana SBF abort) or
silently carries into the neighbouring packed field — bricking the
entry-point permanently.

This is the Rust sibling of Solidity pattern
`packed-lane-increment-no-overflow-guard` (Polymarket Draft 7 —
NegRiskAdapter MarketDataLib.incrementQuestionCount overflows at the
256th prepareQuestion). Solana/Anchor packed account layouts
(MarketData, RegistryV2, BitmapState) hit the same primitive.

Source: Polymarket Draft 7 (phase 37c).
Class: packed-lane-increment-no-overflow-guard (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name, line_col,
    snippet_of, is_pub, body_text_nocomment,
)

# Fn-name: *increment* / *advance* / *bump* / *_add1
_FN_NAME_RE = re.compile(
    r"(?i)^(increment[_a-z0-9]*|advance[_a-z0-9]*|"
    r"bump[_a-z0-9]*|_add1|inc_[_a-z0-9]+)$"
)

# Packed-lane indicators: bit-shift literals, shift-assigns, bitmask
# ops, slot[i] indexing — any of these signals the fn is touching a
# packed lane rather than a plain u64 counter.
_PACKED_LANE_RE = re.compile(
    r"(?i)(<<\s*\d+|>>\s*\d+|<<=|>>=|&\s*0x[0-9a-f]{2,}|"
    r"\|=\s*\(|slot\[\s*\d+\s*\]|data\[\s*\d+\s*\]\s*=|"
    r"bitand|bitor|packed|INCREMENT\s*[:=])"
)

# Safe forms — any of these defuses the finding:
#   require!/assert_eq!/if ... < u8::MAX / < u16::MAX / < MAX_LANE / < 255 / < 65535
#   explicit checked_add + err branch
#   emit of Overflow / LaneSaturated
_SAFE_GUARD_RE = re.compile(
    r"(?i)(<\s*(u8|u16|u32)::MAX|"
    r"<\s*(255|65535|MAX_LANE|MAX_QUESTIONS|MAX_COUNT)\b|"
    r"==\s*(u8|u16|u32)::MAX|"
    r"checked_add\s*\([^)]*\)\s*\.\s*(ok_or|expect|unwrap_or_else)|"
    r"\.is_none\s*\(\s*\)\s*\{\s*return\s+Err|"
    r"OVERFLOW|LaneSaturated|MaxQuestionsExceeded|MaxLaneReached)"
)

# Context precondition: struct name / filepath mentions packed-layout.
_CONTEXT_RE = re.compile(
    r"(?i)(MarketData|Packed|Bitmap|Registry|Layout|Storage)"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    src_head = source[:4096].decode("utf-8", errors="replace")
    if not (_CONTEXT_RE.search(src_head) or _CONTEXT_RE.search(filepath)):
        return hits
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if not _PACKED_LANE_RE.search(body_nc):
            continue
        if _SAFE_GUARD_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "medium",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` on a Packed/Bitmap/MarketData/Registry-"
                f"style struct increments a fixed-width packed lane "
                f"(bit-shift / mask / slot-indexed write) with no "
                f"`< u8::MAX` / `< MAX_LANE` / checked_add guard — at "
                f"lane saturation the entry-point either panics or "
                f"silently carries into a neighbouring packed field, "
                f"bricking the fn permanently "
                f"(packed-lane-increment-no-overflow-guard). "
                f"See Polymarket Draft 7 (NegRiskAdapter "
                f"MarketDataLib.incrementQuestionCount)."
            ),
        })
    return hits
