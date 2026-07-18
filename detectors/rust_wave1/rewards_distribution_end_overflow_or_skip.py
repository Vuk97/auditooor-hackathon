"""
rewards_distribution_end_overflow_or_skip.py

`distribution_end` arithmetic bugs:
  - `distribution_end - current_time` without saturating_sub / checked_sub
    → under-/over-flow if `distribution_end < current_time` OR if
    `distribution_end == u64::MAX` causing add-elapsed overflow.
  - `current_time - last_update` similarly.

Heuristic:
  - A function involved in rewards (name contains `distribut`, `accru`,
    `reward`) contains an arithmetic expression matching
    `<ident>_end - <ident>` or `<ident>_time - <ident>` using raw `-`
    (not saturating_sub / checked_sub / wrapping_sub) AND the left-hand
    side references `distribution_end` / `end_time` / `finish_at`.
"""

from __future__ import annotations

import re

from _util import (
    function_items, fn_body, fn_name, text_of, line_col, snippet_of,
    in_test_cfg,
)


_REWARD_FN_RE = re.compile(r"(distribut|accru|reward|emission)",
                            re.IGNORECASE)

_RAW_SUB_RE = re.compile(
    r"\b(distribution_end|end_time|finish_at|dist_end|emission_end)\s*-\s*"
    r"[a-zA-Z_][a-zA-Z_0-9]*"
)

_SAFE_SUB_TOKENS = ("saturating_sub", "checked_sub", "wrapping_sub",
                     ".saturating_sub(", ".checked_sub(")


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        name = fn_name(fn, source)
        if not _REWARD_FN_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_text = text_of(body, source)

        matches = list(_RAW_SUB_RE.finditer(body_text))
        if not matches:
            continue

        for m in matches:
            # Only flag if there is NO saturating_sub/checked_sub in same fn
            # specifically near the match (±60 chars)
            start = max(0, m.start() - 60)
            end = min(len(body_text), m.end() + 60)
            window = body_text[start:end]
            if any(tok in window for tok in _SAFE_SUB_TOKENS):
                continue
            # Find a rough line for the hit — use fn line + newlines before
            # match
            before = body_text[:m.start()]
            line_offset = before.count("\n")
            fn_line, col = line_col(fn)
            hits.append({
                "severity": "medium",
                "line": fn_line + line_offset,
                "col": col,
                "snippet": m.group(0),
                "message": (
                    f"fn `{name}` subtracts time from `distribution_end` "
                    f"with raw `-` — use `saturating_sub` to guard against "
                    f"u64::MAX / past-end overflow."
                ),
            })
    return hits
