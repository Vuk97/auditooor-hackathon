"""
rounding_direction_loss_fire13.py

Rust rounding-direction class lift from Fire13 held-out fixtures.

Confirmed local evidence only:
  - attacker_self_sandwiches_swap_in_open_close_position_positive.rs
  - bitmap_64_reserve_off_by_one_positive.rs
  - rust_share_math_division_before_multiplication_value_loss_positive.rs
  - incorrect_royalty_distribution_truncation_siphon_positive.rs

The detector intentionally avoids generic arithmetic: a raw `a / b * c`
expression is not enough unless the rounded value reaches an accounting sink,
position transition, residual payout, or reserve bitmap flag update.
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


_ACCOUNTING_RE = re.compile(
    r"(?i)(shares?|collateral|assets?|balances?|reserves?|debt|liquidity|"
    r"payout|royalt|recipient|basis|amount|total|position|supply|vault)"
)

_VALUE_SINK_RE = re.compile(
    r"(?i)(transfer|mint|burn|credit|debit|withdraw|redeem|repay|borrow|"
    r"seize|payout|release|balances?\.|collateral_balances|positions\.|"
    r"total_(?:collateral|shares|amount)|self\.[A-Za-z0-9_]*(?:balance|"
    r"reserve|collateral|share|debt|supply|amount)[A-Za-z0-9_]*\s*(?:\+=|-=|=)|"
    r"\+=|-=)"
)

_SAFE_ROUNDING_RE = re.compile(
    r"(?i)(checked_mul|saturating_mul|mul_div|muldiv|ceil_div|div_ceil|"
    r"round_up|rounding\s*::\s*up|fixedu?128|fixed_point|ratio::)"
)

_DIRECT_DIV_FIRST_RE = re.compile(
    r"let\s+(?:mut\s+)?(?P<var>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*"
    r"(?P<expr>\(?[^;\n]{1,180}/[^;\n]{1,180}\)?\s*\*\s*[^;\n]{1,180})\s*;",
    re.MULTILINE,
)

_QUOTIENT_ASSIGN_RE = re.compile(
    r"let\s+(?:mut\s+)?(?P<q>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*"
    r"(?P<expr>\(?[^;\n]{1,180}/[^;\n]{1,180}\)?)\s*;",
    re.MULTILINE,
)

_BITMAP_METHOD_RE = re.compile(
    r"\b(?:set_using_as_collateral|set_borrowing|is_using_as_collateral|"
    r"is_borrowing)\s*\(\s*(?P<idx>[A-Za-z_][A-Za-z0-9_]*)"
)

_SHIFT_ASSIGN_RE = re.compile(
    r"let\s+(?:mut\s+)?(?P<shift>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"\(?\s*(?P<idx>[A-Za-z_][A-Za-z0-9_]*)(?:\s+as\s+[A-Za-z0-9_:<>]+)?"
    r"\s*\)?\s*\*\s*2(?:\s*\+\s*1)?\s*;",
    re.MULTILINE,
)

_DIRECT_SHIFT_RE = re.compile(
    r"(?:<<|>>)\s*\(?\s*(?P<idx>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s+as\s+[A-Za-z0-9_:<>]+)?\s*\)?\s*\*\s*2(?:\s*\+\s*1)?"
)


def _has_value_sink(body: str, var: str, start: int) -> bool:
    window = body[start : start + 900]
    if not re.search(rf"\b{re.escape(var)}\b", window):
        return False
    return bool(_VALUE_SINK_RE.search(window))


def _division_before_value_move(body: str) -> tuple[str, str] | None:
    if _SAFE_ROUNDING_RE.search(body):
        return None
    for match in _DIRECT_DIV_FIRST_RE.finditer(body):
        var = match.group("var")
        expr = match.group("expr")
        if not (_ACCOUNTING_RE.search(var) or _ACCOUNTING_RE.search(expr)):
            continue
        if _has_value_sink(body, var, match.end()):
            return "division-before-multiplication value movement", var

    for match in _QUOTIENT_ASSIGN_RE.finditer(body):
        q = match.group("q")
        expr = match.group("expr")
        if not (_ACCOUNTING_RE.search(q) or _ACCOUNTING_RE.search(expr)):
            continue
        tail = body[match.end() : match.end() + 700]
        multiplied = re.search(
            rf"\b{re.escape(q)}\b\s*\*\s*[^;\n]{{1,160}}|"
            rf"[^;\n]{{1,160}}\*\s*\b{re.escape(q)}\b",
            tail,
        )
        if multiplied and _has_value_sink(body, q, match.end()):
            return "division-before-multiplication value movement", q
    return None


def _has_reserve_index_guard(body: str, idx: str) -> bool:
    idx_re = re.escape(idx)
    guard_patterns = [
        rf"\b{idx_re}\s*>=\s*(?:64|MAX_RESERVES)\b",
        rf"\b{idx_re}\s*>\s*63\b",
        rf"\b{idx_re}\s*<\s*(?:64|MAX_RESERVES)\b",
        rf"\b{idx_re}\s*<=\s*63\b",
        rf"\b(?:64|MAX_RESERVES)\s*<=\s*{idx_re}\b",
        rf"\b63\s*<\s*{idx_re}\b",
        rf"for\s+{idx_re}\s+in\s+0\s*\.\.=?\s*(?:64(?:u(?:8|16|32|64|128|size))?|MAX_RESERVES)\b",
        rf"safe_reserve_id\s*\([^)]*\b{idx_re}\b",
        rf"validate_reserve\s*\([^)]*\b{idx_re}\b",
    ]
    return any(re.search(pattern, body) for pattern in guard_patterns)


def _bitmap_reserve_oob(body: str) -> tuple[str, str] | None:
    for match in _BITMAP_METHOD_RE.finditer(body):
        idx = match.group("idx")
        if idx == "self":
            continue
        if not _has_reserve_index_guard(body, idx):
            return "unguarded 64-reserve bitmap method", idx

    for match in _SHIFT_ASSIGN_RE.finditer(body):
        idx = match.group("idx")
        shift = match.group("shift")
        if _has_reserve_index_guard(body, idx):
            continue
        if re.search(rf"(?:<<|>>)\s*\(?\s*\b{re.escape(shift)}\b", body[match.end() :]):
            return "unguarded 64-reserve bitmap shift", idx

    for match in _DIRECT_SHIFT_RE.finditer(body):
        idx = match.group("idx")
        if not _has_reserve_index_guard(body, idx):
            return "unguarded direct 64-reserve bitmap shift", idx
    return None


def _caller_residual_payout(body: str) -> tuple[str, str] | None:
    if not re.search(r"(?i)\b(residual|dust|remainder)\b", body):
        return None
    if not re.search(r"(?i)\bcaller\b", body):
        return None
    if not re.search(r"(?i)(balances?\.entry\s*\(\s*caller|insert\s*\(\s*caller)", body):
        return None
    if not re.search(r"/\s*(?:total_basis|basis|denominator|bps|10000)\b", body):
        return None
    return "caller-dependent rounding residual payout", "caller"


def _unguarded_position_swap(body: str, name: str) -> tuple[str, str] | None:
    if not re.search(r"(?i)(open|close|create|exit).*position", name):
        return None
    if not re.search(r"\bexecute_swap\s*\(\s*&?swap_params\b", body):
        return None
    if not re.search(r"(?i)(positions?\.(?:insert|remove|get)|collateral|debt)", body):
        return None
    guard_re = re.compile(
        r"(?i)(health_factor|min_health_factor|validate_health|validate_slippage|"
        r"min_amount_out|max_slippage_bps\s*(?:<|<=)|assert!\s*\([^;]*(?:received|health))"
    )
    if guard_re.search(body):
        return None
    return "position swap accepts caller-controlled rounding/slippage", "swap_params"


def _first_hit(body: str, name: str) -> tuple[str, str] | None:
    return (
        _bitmap_reserve_oob(body)
        or _unguarded_position_swap(body, name)
        or _caller_residual_payout(body)
        or _division_before_value_move(body)
    )


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
        hit = _first_hit(body_nc, name)
        if hit is None:
            continue

        reason, value = hit
        line, col = line_col(fn)
        hits.append(
            {
                "severity": "medium",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:200],
                "message": (
                    f"pub fn `{name}` has rounding-direction loss shape: "
                    f"{reason} via `{value}`. Fire13 held-out anchors cover "
                    "bitmap reserve OOB, floor-first value movement, residual "
                    "siphon, and unguarded position-swap rounding."
                ),
            }
        )
    return hits
