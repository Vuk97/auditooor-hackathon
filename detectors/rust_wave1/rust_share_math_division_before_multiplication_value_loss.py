"""
rust_share_math_division_before_multiplication_value_loss.py

Flags public Rust accounting functions that compute a value-moving share,
debt, liquidity, asset, or collateral amount by dividing before multiplying.

Heuristic:
  1. The function name or body carries accounting context.
  2. The body contains same-expression `a / b * c` math, or a quotient
     assigned from `a / b` and then multiplied into another amount.
  3. The rounded result is used in a balance, transfer, mint, burn, debt,
     collateral, share, liquidity, or reserve update.
  4. Explicit fixed-point or checked multiply-before-divide APIs are ignored.

This is narrower than the generic `division_before_multiplication` detector:
generic arithmetic without an asset/accounting sink is intentionally silent.
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    is_pub,
    line_col,
    snippet_of,
)


_FN_CONTEXT_RE = re.compile(
    r"(?i)(share|redeem|withdraw|deposit|mint|burn|borrow|repay|debt|"
    r"collateral|liquidat|liquidity|reserve|vault|stake|unstake|asset)"
)

_ACCOUNTING_CONTEXT_RE = re.compile(
    r"(?i)(shares?|debt|collateral|liquidity|assets?|tokens?|balances?|"
    r"reserves?|principal|liabilities|supply|vault|position|payout|"
    r"withdraw|redeem|repay|seize|borrow|mint|burn)"
)

_SAFE_MATH_RE = re.compile(
    r"(?i)(mul_div|muldiv|fixedu?128|fixedi?128|fixed_point|decimal|perbill|permill|"
    r"rounding\s*::|roundingmode|round_up|round_down|ceil_div|div_ceil|"
    r"floor_div|checked_fixed|ratio::)"
)

_DIRECT_DIV_FIRST_RE = re.compile(
    r"(?P<prefix>(?:let\s+(?:mut\s+)?|self\.)?)"
    r"(?P<var>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*"
    r"(?P<expr>\(?[^;\n]{1,180}/[^;\n]{1,180}\)?\s*\*\s*[^;\n]{1,180})\s*;",
    re.MULTILINE,
)

_QUOTIENT_ASSIGN_RE = re.compile(
    r"let\s+(?:mut\s+)?(?P<q>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*"
    r"(?P<expr>\(?[^;\n]{1,160}/[^;\n]{1,160}\)?)\s*;",
    re.MULTILINE,
)

_VALUE_MOVE_RE = re.compile(
    r"(?i)(transfer|mint|burn|credit|debit|withdraw|redeem|repay|borrow|"
    r"seize|payout|release|balances?\.insert|balances?\.set|"
    r"self\.[A-Za-z0-9_]*(?:share|debt|collateral|liquidity|asset|"
    r"reserve|balance|supply)[A-Za-z0-9_]*\s*(?:\+=|-=|=))"
)


def _has_accounting_context(name: str, body: str) -> bool:
    return bool(_FN_CONTEXT_RE.search(name) or _ACCOUNTING_CONTEXT_RE.search(body))


def _has_value_sink(body: str, var: str, start: int) -> bool:
    window = body[start : start + 900]
    if not re.search(rf"\b{re.escape(var)}\b", window):
        return False
    return bool(_VALUE_MOVE_RE.search(window))


def _direct_div_first_hit(body: str) -> tuple[re.Match[str], str] | None:
    for match in _DIRECT_DIV_FIRST_RE.finditer(body):
        var = match.group("var")
        expr = match.group("expr")
        if not _ACCOUNTING_CONTEXT_RE.search(var) and not _ACCOUNTING_CONTEXT_RE.search(expr):
            continue
        if _has_value_sink(body, var, match.end()):
            return match, var
    return None


def _split_quotient_hit(body: str) -> tuple[re.Match[str], str] | None:
    for match in _QUOTIENT_ASSIGN_RE.finditer(body):
        q = match.group("q")
        expr = match.group("expr")
        if not _ACCOUNTING_CONTEXT_RE.search(q) and not _ACCOUNTING_CONTEXT_RE.search(expr):
            continue
        tail = body[match.end() : match.end() + 700]
        multiplied = re.search(
            rf"\b{re.escape(q)}\b\s*\*\s*[^;\n]{{1,160}}|"
            rf"[^;\n]{{1,160}}\*\s*\b{re.escape(q)}\b",
            tail,
        )
        if multiplied and _has_value_sink(body, q, match.end()):
            return match, q
    return None


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    for fn in function_items(tree.root_node):
        if not is_pub(fn, source):
            continue
        body = fn_body(fn)
        if body is None:
            continue

        name = fn_name(fn, source)
        body_nc = body_text_nocomment(body, source)
        if not _has_accounting_context(name, body_nc):
            continue
        if _SAFE_MATH_RE.search(body_nc):
            continue

        hit = _direct_div_first_hit(body_nc) or _split_quotient_hit(body_nc)
        if hit is None:
            continue

        _match, var = hit
        line, col = line_col(fn)
        hits.append(
            {
                "severity": "medium",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:200],
                "message": (
                    f"pub fn `{name}` computes value-moving `{var}` via "
                    "division before multiplication, then applies the rounded "
                    "result to share/debt/liquidity/collateral accounting. "
                    "Flooring before the value movement can leak assets to the "
                    "rounding-favored side."
                ),
            }
        )
    return hits
