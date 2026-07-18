"""
r94_loop_post_liquidation_borrow_no_health_check.py

Flags borrow/utilize fns that take on new debt without checking
health factor / is_liquidated flag — just-liquidated operator can
immediately borrow again.

Source: Solodit #53694 (Stader Labs SDUtilityPool).
Class: post-liquidation-borrow-no-health-check (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(
    r"(?i)(utilize|borrow|take_loan|open_loan|draw_credit|issue_debt)"
)
_MUTATES_DEBT_RE = re.compile(
    r"(debt|borrow_amount|principal|loan_amount|utilized)\s*[+=-]|"
    r"\.insert\s*\(\s*&?(debt|borrow|principal|loan)|"
    r"self\.(debt|borrow_amount|principal|loan_amount)\s*(?:\+=|=)"
)
_HEALTH_CHECK_RE = re.compile(
    r"(health_factor|is_liquidated|is_solvent|check_health|is_underwater|"
    r"above_liquidation_threshold|require_healthy|assert_healthy)"
)


def run(tree, source: bytes, filepath: str):
    hits = []
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
        if not _MUTATES_DEBT_RE.search(body_nc):
            continue
        if _HEALTH_CHECK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` mutates debt without checking "
                f"health-factor / is_liquidated — just-liquidated "
                f"operator can immediately borrow again (post-"
                f"liquidation-borrow-no-health-check). See Solodit "
                f"#53694 (Stader Labs)."
            ),
        })
    return hits
