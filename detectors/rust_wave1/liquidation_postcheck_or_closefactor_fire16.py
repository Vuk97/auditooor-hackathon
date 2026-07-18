"""
Fire16 Rust recall lift for liquidation-trigger-poison.

Flags three same-class liquidation shapes:
  1. Underfunded collateral reverts because bonus is included in the
     required collateral amount instead of capping the seize amount.
  2. Close-factor or health-factor liquidation boundaries use strict
     `<` or `>` comparisons where inclusive boundaries are expected.
  3. A liquidation mutates debt or collateral after a pre-health check
     but never performs a post-mutation health validation.

Detector hits are candidate evidence only. They are not submission proof.
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
    text_of,
)


_LIQ_FN_RE = re.compile(
    r"(?i)(liquidat|close_position|seize_and_repay|repay_liquidat)"
)

_BONUS_CALC_RE = re.compile(
    r"(?is)"
    r"("
    r"bonus\w*\s*=\s*[^;\n]*(?:debt_to_cover|debt|repay|amount)[^;\n]*"
    r"(?:bonus|basis|bps)"
    r"|total_required\s*=\s*[^;\n]*(?:debt_to_cover|debt|repay|amount)"
    r"[^;\n]*\+\s*bonus\w*"
    r")"
)
_BONUS_TOTAL_RE = re.compile(
    r"(?is)(total_required|collateral_needed|debt_to_cover\s*\+\s*bonus|debt\s*\+\s*bonus)"
)
_UNDERFUNDED_RE = re.compile(
    r"(?is)"
    r"(?:deposited_collateral|available_collateral|collateral_value|collateral|position\.collateral)"
    r"[^;\n{}]*<[^;\n{}]*"
    r"(?:collateral_needed|total_required|debt_to_cover\s*\+\s*bonus\w*|debt\s*\+\s*bonus\w*)"
)
_REVERT_RE = re.compile(
    r"(?is)(return\s+Err|Err\s*\(|panic_with_error!\s*\(|panic!\s*\(|Insufficient\s+collateral)"
)

_BOUNDARY_IDENTS = (
    "close_factor",
    "CLOSE_FACTOR",
    "closeFactor",
    "health_factor",
    "HEALTH_FACTOR",
    "healthFactor",
    r"\bhf\b",
    r"\bHF\b",
    "liquidation_threshold",
    "LIQUIDATION_THRESHOLD",
)
_BOUNDARY_LITERALS = (
    r"\b5000\b",
    r"\b1e18\b",
    r"1_000_000_000_000_000_000",
)
_BOUNDARY_RE = re.compile("|".join(_BOUNDARY_IDENTS + _BOUNDARY_LITERALS))

_MUTATION_RE = re.compile(
    r"(?is)"
    r"("
    r"\.set\s*\(|\.burn\s*\(|\.transfer\s*\(|\.transfer_from\s*\(|\.seize\s*\(|"
    r"\.remove\s*\(|\.mint\s*\(|"
    r"(?:position\.)?(?:debt|borrowed|principal|collateral|debt_amount)\s*(?:=|\-=|\+=)"
    r")"
)
_PRE_HEALTH_RE = re.compile(
    r"(?is)(compute_hf|compute_health|health_factor|collateralization|is_solvent|is_underwater)"
)
_POST_HEALTH_RE = re.compile(
    r"(?is)"
    r"(post_hf|hf_after|hf_post|health_factor_after|calculate_health_factor|"
    r"validate_health_factor|check_health_factor|assert_health_factor|"
    r"require_health_factor_improves|assert!\s*\([^)]*(?:hf|health|solvent))"
)


def _line_from_offset(fn_node, text: str, offset: int) -> tuple[int, int]:
    fn_line, fn_col = line_col(fn_node)
    return fn_line + text[:offset].count("\n"), fn_col


def _strict_boundary_expressions(body_text: str) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for idx, line in enumerate(body_text.splitlines()):
        code = line.split("//", 1)[0].strip()
        if not code or not _BOUNDARY_RE.search(code):
            continue
        if re.search(r"(?<![<=!])<(?![=<])", code) and "<=" not in code:
            out.append((idx, code))
            continue
        if re.search(r"(?<![>=!])>(?![=>])", code) and ">=" not in code:
            out.append((idx, code))
    return out


def _has_inclusive_boundary_guard(body_text: str) -> bool:
    for line in body_text.splitlines():
        code = line.split("//", 1)[0]
        if _BOUNDARY_RE.search(code) and re.search(r"(<=|>=)", code):
            return True
    return False


def _hit(fn_node, source: bytes, line: int, col: int, snippet: str, variant: str, detail: str):
    name = fn_name(fn_node, source)
    return {
        "severity": "high",
        "line": line,
        "col": col,
        "snippet": snippet[:200],
        "message": (
            f"fn `{name}` matches Fire16 liquidation-trigger-poison variant "
            f"`{variant}`: {detail}"
        ),
    }


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        name = fn_name(fn, source)
        if not _LIQ_FN_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue

        body_text = text_of(body, source)
        body_nc = body_text_nocomment(body, source)

        underfunded = _UNDERFUNDED_RE.search(body_nc)
        if (
            underfunded
            and _BONUS_CALC_RE.search(body_nc)
            and _BONUS_TOTAL_RE.search(body_nc)
            and _REVERT_RE.search(body_nc)
        ):
            line, col = _line_from_offset(fn, body_nc, underfunded.start())
            hits.append(_hit(
                fn,
                source,
                line,
                col,
                underfunded.group(0).strip(),
                "underfunded-bonus-revert",
                "collateral insufficiency includes liquidation bonus and reverts instead of capping partial seize",
            ))

        if not _has_inclusive_boundary_guard(body_nc):
            for line_idx, expr in _strict_boundary_expressions(body_nc):
                fn_line, fn_col = line_col(fn)
                hits.append(_hit(
                    fn,
                    source,
                    fn_line + line_idx + 1,
                    fn_col,
                    expr,
                    "strict-closefactor-boundary",
                    "strict liquidation boundary can strand dust or skip the exact close-factor edge",
                ))

        mutation = _MUTATION_RE.search(body_nc)
        if mutation and re.search(r"(?i)liquidat", name):
            before_mutation = body_nc[: mutation.start()]
            after_mutation = body_nc[mutation.start():]
            if _PRE_HEALTH_RE.search(before_mutation) and not _POST_HEALTH_RE.search(after_mutation):
                line, col = _line_from_offset(fn, body_nc, mutation.start())
                hits.append(_hit(
                    fn,
                    source,
                    line,
                    col,
                    mutation.group(0).strip(),
                    "missing-post-liquidation-health-check",
                    "state changes after a pre-health check but no post-mutation health validation is enforced",
                ))

    return hits
