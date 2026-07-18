"""
r94_loop_stale_snapshot_refund.py

Flags refund/withdraw functions that read a "total snapshot" field
(e.g. `last_total_shares_minted`, `total_minted_snapshot`,
`locked_supply_at_round`) and compute a per-user share from it without
DECREMENTING that field after the refund — so subsequent refunds reuse
an inflated total, over-refunding or under-refunding users.

Source: Solodit #61618 (Quantstamp / Neutral Trade).
Rust side of `stale-snapshot-accounting` canonical class.

Heuristic:
  1. Function name matches /refund|withdraw|redeem|reclaim/.
  2. Body reads a field whose name matches
     /(last|snapshot|saved)_total|total_(mint|minted|deposit)_at|
     locked_supply|total_supply_snapshot|total_shares_minted/.
  3. Body uses this field in a multiply-divide (user-share computation).
  4. Body does NOT contain a mutation of that same field (no
     `storage.set(... FIELD, new_total - amount)` / `*FIELD -= ` / etc.).
"""

from __future__ import annotations

import re

from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
)


_FN_NAME_RE = re.compile(r"(?i)(refund|withdraw|redeem|reclaim|unwind)")

_SNAPSHOT_FIELD_RE = re.compile(
    r"(last|saved|snapshot)_(total|aggregate|minted|supply|shares|"
    r"deposits|collateral)[_a-z]*|"
    r"total_(mint|minted|deposit|shares_minted|supply)_at_[_a-z]+|"
    r"total_(shares_)?minted|"
    r"locked_supply_at[_a-z]*|"
    r"total_supply_snapshot[_a-z]*",
    re.IGNORECASE,
)


def _mutates_field(body_text: str, field: str) -> bool:
    """Heuristic: did the fn write `field` back?  Look for any of:
       - field = X
       - field -= / field +=
       - .set( ..., field_key_matching_field, ...)
       - *field_ref -= X
    """
    patterns = [
        rf"\b{re.escape(field)}\s*=\s*[^;=]",
        rf"\b{re.escape(field)}\s*[-+*/]=\s*",
        rf"\.set\s*\([^)]*{re.escape(field)}",
        rf"\*\w*{re.escape(field)}\w*\s*[-+]=",
        # Any setter that looks like set_last_*, update_last_*, write_*,
        # decrement_*, persist_* taking the field (or its compact form) as arg.
        r"(set_last_|update_last_|write_last_|decrement_|persist_last_)\w*\s*\(",
        # Self::set_total_*, Self::set_snapshot_*
        r"Self::set_\w*(total|snapshot|last)\w*\s*\(",
    ]
    for pat in patterns:
        if re.search(pat, body_text):
            return True
    return False


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    for fn, _impl in functions_in_contractimpl(root, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_text = text_of(body, source)

        # Find all snapshot-like field references
        fields = set(m.group(0) for m in _SNAPSHOT_FIELD_RE.finditer(body_text))
        if not fields:
            continue

        # For each, check if the field is read in a share-math expression
        # AND not decremented.
        for field in fields:
            # Must be used as a multiplier/divisor alongside another token
            if not re.search(
                rf"{re.escape(field)}\s*[*/]\s*\w|\w\s*[*/]\s*{re.escape(field)}",
                body_text,
            ):
                continue
            if _mutates_field(body_text, field):
                continue

            line, col = line_col(fn)
            hits.append({
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:200],
                "message": (
                    f"fn `{name}` computes a per-user share using field "
                    f"`{field}` but never decrements/updates it after the "
                    f"refund path. Subsequent callers reuse the same "
                    f"inflated snapshot — over-refund / accounting drift. "
                    f"See Solodit #61618 (Neutral Trade)."
                ),
            })
            break  # one hit per fn
    return hits
