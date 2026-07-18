"""
r94_loop_ledger_delta_unmeasured_fot_drift.py

Flags lender/vault fns that mutate an internal ledger with `+= amount`
after transferFrom without first measuring the real balance delta —
FoT/rebasing tokens drift accounting until insolvency.

Source: Solodit #34506 (Beedle Lender).
Class: ledger-delta-unmeasured-fot-drift (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(r"(?i)(deposit|supply|lend|credit|repay|fund)")
_TRANSFER_IN_RE = re.compile(
    r"(safe_transfer_from|safeTransferFrom|token\.transfer_from|transferFrom)\s*\("
)
_LEDGER_ADD_RE = re.compile(
    fr"(pool|vault|lender)\.\s*total\s*\+=\s*{IDENT}amount|"
    fr"pool_balance\s*\+=\s*{IDENT}amount|"
    fr"\b(debt|total_deposits|total_supply_tokens|ledger|principal|pool_total)\s*\+=\s*{IDENT}amount"
)
_DELTA_MEASURED_RE = re.compile(
    r"(balance_before|prev_balance|before_bal|initial_bal)\s*=|"
    r"\bdelta\s*=|\breceived\s*=|"
    r"balance_of\s*\([^)]+\)\s*-\s*(balance_before|prev_balance|before)"
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
        if not _TRANSFER_IN_RE.search(body_nc):
            continue
        if not _LEDGER_ADD_RE.search(body_nc):
            continue
        if _DELTA_MEASURED_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` mutates internal ledger with += "
                f"amount after transferFrom without measuring balance "
                f"delta — FoT/rebasing tokens drift accounting "
                f"(ledger-delta-unmeasured-fot-drift). See Solodit "
                f"#34506 (Beedle Lender)."
            ),
        })
    return hits
