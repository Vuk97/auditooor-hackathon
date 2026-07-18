"""
financial_precision_loss_or_unchecked_arithmetic_fire17.py

Flags public Rust financial entrypoints where arithmetic can move assets,
shares, debt, reserves, liquidity, or fees to the wrong side.

Heuristic:
  1. The function carries financial context by name or body.
  2. It contains one of these value-accounting shapes:
     - division before multiplication whose rounded output reaches a value sink
     - wrapping or unchecked arithmetic in the financial amount path
     - repeated debit of the same accounting sink without one checked delta
  3. Pure generic arithmetic and checked multiply-before-divide flows stay
     silent.
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    in_test_cfg,
    is_pub,
    line_col,
    snippet_of,
)


_FINANCIAL_WORD_RE = re.compile(
    r"(?i)(assets?|tokens?|balances?|shares?|debts?|fees?|reserves?|"
    r"liquidity|collateral|principal|supply|vault|pool|market|position|"
    r"borrow|repay|redeem|withdraw|deposit|mint|burn|payout|treasury|"
    r"protocol|escrow|notional|amount)"
)

_FN_CONTEXT_RE = re.compile(
    r"(?i)(fee|debt|share|asset|reserve|liquidity|collateral|vault|"
    r"withdraw|redeem|deposit|mint|burn|borrow|repay|liquidat|settle|"
    r"claim|payout|accrue|distribute|swap)"
)

_SAFE_MATH_HINT_RE = re.compile(
    r"(?i)(mul_div|muldiv|checked_mul\s*\(|checked_div\s*\(|"
    r"fixedu?128|fixedi?128|fixed_point|decimal|perbill|permill|"
    r"rounding\s*::|round_up|div_ceil|ceil_div)"
)

_VALUE_SINK_RE = re.compile(
    r"(?i)(transfer|mint|burn|credit|debit|withdraw|redeem|repay|borrow|"
    r"seize|payout|release|insert|push|set|balances?|fees?|debts?|"
    r"collateral|shares?|assets?|reserves?|liquidity|supply|treasury|"
    r"protocol|self\.[A-Za-z0-9_]*(?:asset|share|debt|fee|reserve|"
    r"liquidity|collateral|balance|supply)[A-Za-z0-9_]*\s*(?:\+=|-=|=))"
)

_DIRECT_DIV_FIRST_RE = re.compile(
    r"(?:let\s+(?:mut\s+)?|self\.)?"
    r"(?P<var>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*"
    r"(?P<expr>\(?[^;\n]{1,180}/[^;\n]{1,180}\)?\s*\*\s*"
    r"[^;\n]{1,180})\s*;",
    re.MULTILINE,
)

_QUOTIENT_ASSIGN_RE = re.compile(
    r"let\s+(?:mut\s+)?(?P<q>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*"
    r"(?P<expr>\(?[^;\n]{1,180}/[^;\n]{1,180}\)?)\s*;",
    re.MULTILINE,
)

_UNCHECKED_ASSIGN_RE = re.compile(
    r"(?P<stmt>(?:let\s+(?:mut\s+)?(?P<var>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=;]+)?|(?P<field>self\s*\.\s*[A-Za-z_][A-Za-z0-9_]*))"
    r"\s*=\s*[^;\n]{0,260}\.(?:wrapping|unchecked)_"
    r"(?:add|sub|mul|div|neg|shl|shr)\s*\([^;\n]{0,260}\)\s*;)",
    re.MULTILINE,
)

_UNCHECKED_DIRECT_RE = re.compile(
    r"\.(?:wrapping|unchecked)_(?:add|sub|mul|div|neg|shl|shr)\s*\(",
    re.MULTILINE,
)

_DIRECT_DEBIT_RE = re.compile(
    r"(?P<target>\b(?:self|state|pool|vault|market|ledger|position|account)"
    r"\s*\.\s*[A-Za-z_][A-Za-z0-9_]*(?:\s*\[[^\]]+\])?)"
    r"\s*-=\s*(?P<amount>[^;\n]+);",
    re.MULTILINE,
)

_MAP_DEBIT_RE = re.compile(
    r"(?P<target>\b(?:self|state|pool|vault|market|ledger|position|account)"
    r"\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*\.\s*(?:insert|set)\s*\("
    r"(?P<body>[\s\S]{0,420}?(?:\s-\s|\.checked_sub\s*\(|"
    r"\.saturating_sub\s*\()[\s\S]{0,420}?)\)\s*;",
    re.MULTILINE,
)

_CHECKED_COMBINED_DELTA_RE = re.compile(
    r"\blet\s+(?:mut\s+)?(?P<var>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*[^;]{0,260}\.checked_add\s*\(",
    re.MULTILINE,
)


def _normalise_target(target: str) -> str:
    return re.sub(r"\s+", "", target)


def _has_financial_context(name: str, body: str) -> bool:
    return bool(_FN_CONTEXT_RE.search(name) or _FINANCIAL_WORD_RE.search(body))


def _has_value_sink(body: str, var: str, start: int) -> bool:
    window = body[start : start + 900]
    if not re.search(rf"\b{re.escape(var)}\b", window):
        return False
    return bool(_VALUE_SINK_RE.search(window))


def _division_before_multiplication_hit(body: str) -> tuple[str, str] | None:
    for match in _DIRECT_DIV_FIRST_RE.finditer(body):
        var = match.group("var")
        expr = match.group("expr")
        if not _FINANCIAL_WORD_RE.search(var + " " + expr):
            continue
        if _has_value_sink(body, var, match.end()):
            return var, "division before multiplication"

    for match in _QUOTIENT_ASSIGN_RE.finditer(body):
        q = match.group("q")
        expr = match.group("expr")
        if not _FINANCIAL_WORD_RE.search(q + " " + expr):
            continue
        tail = body[match.end() : match.end() + 900]
        multiplied = re.search(
            rf"\blet\s+(?:mut\s+)?(?P<out>[A-Za-z_][A-Za-z0-9_]*)"
            rf"(?:\s*:\s*[^=;]+)?\s*=\s*[^;\n]{{0,220}}\b"
            rf"{re.escape(q)}\b[^;\n]{{0,220}}\*[^;\n]{{0,220}};",
            tail,
            re.MULTILINE,
        )
        if multiplied is None:
            continue
        out = multiplied.group("out")
        if not _FINANCIAL_WORD_RE.search(out):
            continue
        absolute_start = match.end() + multiplied.end()
        if _has_value_sink(body, out, absolute_start):
            return out, "division before multiplication"
    return None


def _unchecked_arithmetic_hit(body: str) -> tuple[str, str] | None:
    for match in _UNCHECKED_ASSIGN_RE.finditer(body):
        target = match.group("var") or match.group("field") or "financial amount"
        stmt = match.group("stmt")
        if not _FINANCIAL_WORD_RE.search(target + " " + stmt):
            continue
        if target.startswith("self.") or _has_value_sink(body, target, match.end()):
            return _normalise_target(target), "unchecked or wrapping arithmetic"

    if _UNCHECKED_DIRECT_RE.search(body) and _VALUE_SINK_RE.search(body):
        return "financial amount", "unchecked or wrapping arithmetic"
    return None


def _has_single_checked_delta(body: str) -> bool:
    for match in _CHECKED_COMBINED_DELTA_RE.finditer(body):
        var = match.group("var")
        if not _FINANCIAL_WORD_RE.search(var):
            if not re.search(r"(?i)(delta|debit|burn|withdraw|repay|amount)", var):
                continue
        tail = body[match.end() : match.end() + 1200]
        if re.search(
            rf"(?:checked_sub|saturating_sub)\s*\(\s*{re.escape(var)}\b|"
            rf"-=\s*{re.escape(var)}\b|"
            rf"-\s*{re.escape(var)}\b",
            tail,
        ):
            return True
    return False


def _collect_debits(body: str) -> list[tuple[int, str]]:
    debits: list[tuple[int, str]] = []

    for match in _DIRECT_DEBIT_RE.finditer(body):
        target = _normalise_target(match.group("target"))
        amount = match.group("amount")
        if not _FINANCIAL_WORD_RE.search(target + " " + amount):
            continue
        debits.append((match.start(), target))

    for match in _MAP_DEBIT_RE.finditer(body):
        target = _normalise_target(match.group("target"))
        if not _FINANCIAL_WORD_RE.search(target + " " + match.group("body")):
            continue
        debits.append((match.start(), target))

    return sorted(debits, key=lambda item: item[0])


def _double_debit_hit(body: str) -> tuple[str, str] | None:
    if _has_single_checked_delta(body):
        return None
    seen: dict[str, int] = {}
    for _pos, target in _collect_debits(body):
        if target in seen:
            return target, "repeated debit"
        seen[target] = 1
    return None


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if not is_pub(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        name = fn_name(fn, source)
        body_nc = body_text_nocomment(body, source)
        if not _has_financial_context(name, body_nc):
            continue

        hit = None
        if not _SAFE_MATH_HINT_RE.search(body_nc):
            hit = _division_before_multiplication_hit(body_nc)
        hit = hit or _unchecked_arithmetic_hit(body_nc)
        hit = hit or _double_debit_hit(body_nc)
        if hit is None:
            continue

        target, reason = hit
        line, col = line_col(fn)
        hits.append(
            {
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"pub fn `{name}` has {reason} in value-bearing "
                    f"financial accounting for `{target}`. This can mis-account "
                    "assets, debt, shares, reserves, liquidity, or fees."
                ),
            }
        )
    return hits
