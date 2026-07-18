"""
financial_precision_loss_div_before_mul_or_float_cast.py

Flags Rust financial/accounting math that:

1. Divides before multiplying in fee/rate/price/amount paths, causing
   truncation before scale-up, or
2. Converts through f32/f64 and then back to integers in fee/rate/price/
   amount paths, especially around sqrt/rounding math.

This is intentionally narrower than the generic arithmetic detectors. It
requires financial context so routine geometry / sizing / buffer math stays
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
    line_col,
    snippet_of,
)


_PRIMARY_CTX_RE = re.compile(
    r"(?i)\b[A-Za-z0-9_]*(?:fee|rate|price|amount|quote|premium|cost|"
    r"share|debt|collateral|sqrt_price|notional)[A-Za-z0-9_]*\b"
)
_SECONDARY_CTX_RE = re.compile(
    r"(?i)\b[A-Za-z0-9_]*(?:gas|reserve|liquidity|asset|value|input|output)"
    r"[A-Za-z0-9_]*\b"
)
_FN_CTX_RE = re.compile(
    r"(?i)(fee|rate|price|amount|quote|premium|cost|share|"
    r"sqrt_price|notional|collateral|debt)"
)

_ASSIGN_OR_RETURN_RE = re.compile(
    r"(?is)"
    r"(?:"
    r"(?:let\s+(?:mut\s+)?)?(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=;]+)?=\s*(?P<rhs>[^;]{1,260})"
    r"|return\s+(?P<ret>[^;]{1,260})"
    r")"
)

_DIV_THEN_MUL_INFIX_RE = re.compile(
    r"(?is)"
    r"\b[A-Za-z_][A-Za-z0-9_\.]*\b"
    r"\s*/\s*"
    r"(?:"
    r"\b[A-Za-z_][A-Za-z0-9_\.]*\b|"
    r"\d[\d_]*(?:u(?:8|16|32|64|128|size))?\b|"
    r"\d[\d_]*\.\d+\b"
    r")"
    r"(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*\s*\([^)]*\)\s*){0,2}"
    r"\s*(?:\*|/\* impossible \*/)"
)
_DIV_THEN_MUL_METHOD_RE = re.compile(
    r"(?is)"
    r"\.(?:checked_div|saturating_div|wrapping_div|div_euclid)\s*\([^)]*\)"
    r"[\s\S]{0,160}?"
    r"\.(?:checked_mul|saturating_mul|wrapping_mul|mul)\s*\("
)
_MULDIV_SAFE_RE = re.compile(
    r"(?i)\b(?:mul_div|muldiv|full_math|fullmath|math::mul_div|"
    r"checked_mul_div|saturating_mul_div)\b"
)

_FLOAT_TO_INT_RE = re.compile(
    r"(?is)"
    r"(?:as\s+f(?:32|64)\b|to_f(?:32|64)\s*\(\)|f(?:32|64)::from\s*\()"
    r"[^;\n]{0,180}"
    r"(?:\.sqrt\s*\(\)|\.powf\s*\(|\.powi\s*\(|\.round\s*\(\)|"
    r"\.floor\s*\(\)|\.ceil\s*\()"
    r"[^;\n]{0,180}"
    r"(?:as\s+[iu](?:32|64|128|size)\b|to_[iu](?:32|64|128)\s*\(\))"
)


def _has_financial_context(name: str, text: str, lhs: str | None) -> bool:
    primary = {m.group(0).lower() for m in _PRIMARY_CTX_RE.finditer(text)}
    secondary = {m.group(0).lower() for m in _SECONDARY_CTX_RE.finditer(text)}

    lhs_text = lhs or ""
    lhs_primary = bool(_PRIMARY_CTX_RE.search(lhs_text))
    fn_ctx = bool(_FN_CTX_RE.search(name))

    if lhs_primary and (primary or secondary or fn_ctx):
        return True
    if len(primary) >= 2:
        return True
    if primary and fn_ctx:
        return True
    return False


def _div_before_mul_shape(expr: str) -> bool:
    if _MULDIV_SAFE_RE.search(expr):
        return False
    if _DIV_THEN_MUL_METHOD_RE.search(expr):
        return True

    if not _DIV_THEN_MUL_INFIX_RE.search(expr):
        return False

    div_pos = expr.find("/")
    mul_pos = expr.find("*", div_pos + 1)
    return div_pos >= 0 and mul_pos > div_pos


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        body = fn_body(fn)
        if body is None:
            continue

        name = fn_name(fn, source)
        body_nc = body_text_nocomment(body, source)

        found_div_before_mul = False
        found_float_cast = False

        for match in _ASSIGN_OR_RETURN_RE.finditer(body_nc):
            lhs = match.group("lhs")
            expr = match.group("rhs") or match.group("ret") or ""
            if len(expr) < 5:
                continue
            window = f"{lhs or ''} {expr}"
            if not _has_financial_context(name, window, lhs):
                continue

            if not found_div_before_mul and _div_before_mul_shape(expr):
                found_div_before_mul = True
            if not found_float_cast and _FLOAT_TO_INT_RE.search(expr):
                found_float_cast = True

            if found_div_before_mul and found_float_cast:
                break

        if not found_div_before_mul and not found_float_cast:
            continue

        issues = []
        if found_div_before_mul:
            issues.append("divide-before-multiply truncation")
        if found_float_cast:
            issues.append("unchecked float-to-int round-trip")

        line, col = line_col(fn)
        hits.append(
            {
                "severity": "med",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:200],
                "message": (
                    f"fn `{name}` uses {' and '.join(issues)} in a "
                    "fee/rate/price/amount-style path. Financial math "
                    "should keep multiplication before division and avoid "
                    "f32/f64 round-trips before integer settlement."
                ),
            }
        )
    return hits
