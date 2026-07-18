"""
r94_loop_reversed_comparison_operator.py

Flags functions whose name is *_expired / is_valid / is_active and whose
return expression uses a suspiciously inverted comparison to a timestamp
or expiration field.

Class: reversed-comparison-operator (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)

_FN_NAME_RE = re.compile(r"^(is_expired|is_valid|is_active|has_expired|is_stale|is_fresh)$", re.IGNORECASE)
_BODY_RE = re.compile(
    r"(?:block_timestamp|now|current_time|env\.ledger\(\)\.timestamp\(\)|env\.block\.timestamp)"
    r"\s*(?P<op>[<>]=?)\s*"
    r"(?:expiration|deadline|expiry|end_time|expires_at|close_time|maturity)"
)


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
        body_nc = body_text_nocomment(body, source)
        m = _BODY_RE.search(body_nc)
        if m is None:
            continue
        op = m.group("op")
        # For `is_expired` / `has_expired`: expect `now >= expiration` or `now > expiration`.
        # Reversed would be `now < expiration` or `now <= expiration`.
        # For `is_active` / `is_valid`: expect `now <= deadline` etc.
        # If the fn semantics conflict with the operator, flag.
        expected_side = "greater" if name.lower() in ("is_expired", "has_expired", "is_stale") else "less"
        actually_greater = op in (">", ">=")
        if expected_side == "greater" and not actually_greater:
            detected = "reversed"
        elif expected_side == "less" and actually_greater:
            detected = "reversed"
        else:
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` returns `timestamp {op} expiration_field` "
                f"— operator appears reversed relative to the fn name's "
                f"semantics. `{name}` should be true when {'time passed' if expected_side == 'greater' else 'time before'} "
                f"expiry. See Solodit #55280 (Initia)."
            ),
        })
    return hits
