"""
rounding_direction_attack_fire6.py

Flags public Rust financial accounting functions that use floor-style
division in contexts where the confirmed Solidity source bugs required
protocol-favorable rounding or multiply-before-divide precision.

Confirmed anchors only:
  - Solodit #5806: accepted HIGH rounding-direction abuse in Juicebox.
  - Solodit #5785: division before multiplication can zero receiver and
    treasury payout in Y2K Finance.
  - Solodit #44231: floor-rounded fee percentage lets borrowers underpay
    protocol fees in Debita Finance V3.

Synthetic cross-language rows are intentionally not used as source anchors.
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
    r"(?i)(fee|debt|decay|withdraw|redeem|payout|claim|borrow|repay|"
    r"premium|interest|share|collateral|vault|treasury|protocol|settle)"
)

_FINANCIAL_BODY_RE = re.compile(
    r"(?i)(fees?|protocol_fee|treasury|debt|decay|duration|premium|"
    r"interest|payout|entitled|withdraw|redeem|claim|borrow|repay|"
    r"shares?|collateral|assets?|principal|balances?|transfer|mint|burn)"
)

_ROUND_UP_RE = re.compile(
    r"(?i)(mul_div_up|muldiv_up|muldivup|ceil_div|div_ceil|round_up|"
    r"rounding\s*::\s*up|roundingmode\s*::\s*up|"
    r"checked_add\s*\([^;]{0,140}(?:-\s*1|saturating_sub\s*\(\s*1\s*\))|"
    r"saturating_add\s*\([^;]{0,140}(?:-\s*1|saturating_sub\s*\(\s*1\s*\)))"
)

_FLOOR_ASSIGN_RE = re.compile(
    r"(?:let\s+(?:mut\s+)?|self\.)?"
    r"(?P<var>[A-Za-z_][A-Za-z0-9_]*"
    r"(?:fee|fees|debt|decay|increment|percentage|rate|payout|"
    r"entitled|amount|share|shares|premium|interest|collateral)"
    r"[A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*"
    r"(?P<expr>[^;\n]{1,260}(?:/|\.checked_div\s*\(|mul_div(?:_down|_floor)?\s*\(|"
    r"div_wad_down)[^;\n]{0,260})\s*;",
    re.MULTILINE,
)

_QUOTIENT_ASSIGN_RE = re.compile(
    r"let\s+(?:mut\s+)?(?P<q>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*(?P<expr>[^;\n]{1,180}/[^;\n]{1,180})\s*;",
    re.MULTILINE,
)

_VALUE_SINK_RE = re.compile(
    r"(?i)(transfer|mint|burn|credit|debit|withdraw|redeem|repay|borrow|"
    r"seize|payout|release|push|insert|protocol_fees?|treasury|"
    r"balances?|fees?|debt|collateral|shares?|assets?|reserve|supply|"
    r"\+=|-=|=)"
)


def _has_financial_context(name: str, body: str) -> bool:
    return bool(_FN_CONTEXT_RE.search(name) or _FINANCIAL_BODY_RE.search(body))


def _has_value_sink(body: str, var: str, start: int) -> bool:
    window = body[start : start + 900]
    if not re.search(rf"\b{re.escape(var)}\b", window):
        return False
    return bool(_VALUE_SINK_RE.search(window))


def _floor_assign_hit(body: str) -> tuple[re.Match[str], str] | None:
    for match in _FLOOR_ASSIGN_RE.finditer(body):
        var = match.group("var")
        expr = match.group("expr")
        if not _FINANCIAL_BODY_RE.search(var) and not _FINANCIAL_BODY_RE.search(expr):
            continue
        if _has_value_sink(body, var, match.end()):
            return match, var
    return None


def _split_div_before_mul_hit(body: str) -> tuple[re.Match[str], str] | None:
    for match in _QUOTIENT_ASSIGN_RE.finditer(body):
        q = match.group("q")
        pattern = re.compile(
            r"let\s+(?:mut\s+)?(?P<out>[A-Za-z_][A-Za-z0-9_]*"
            r"(?:fee|debt|payout|entitled|amount|share|shares|premium|interest|collateral)"
            r"[A-Za-z0-9_]*)"
            r"(?:\s*:\s*[^=;]+)?\s*=\s*[^;\n]{0,180}\b"
            + re.escape(q)
            + r"\b[^;\n]{0,180}\*[^;\n]{0,180};",
            re.MULTILINE,
        )
        tail = body[match.end() : match.end() + 700]
        result = pattern.search(tail)
        if not result:
            continue
        out = result.group("out")
        absolute_start = match.end() + result.end()
        if _has_value_sink(body, out, absolute_start):
            return match, out
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
        if not _has_financial_context(name, body_nc):
            continue
        if _ROUND_UP_RE.search(body_nc):
            continue

        hit = _floor_assign_hit(body_nc) or _split_div_before_mul_hit(body_nc)
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
                    f"pub fn `{name}` computes value-moving `{var}` with "
                    "floor-style financial division and no round-up hint. "
                    "Confirmed anchors: Solodit #5806, #5785, #44231."
                ),
            }
        )
    return hits
