"""
liquidation_stale_liabilities_fire39.py

Fire39 Rust lift for liquidation-trigger-poison stale liability paths.

verification_tier: tier-3-synthetic-taxonomy-anchored
attack_class: liquidation-trigger-poison
context_pack_id: auditooor.vault_context_pack.v1:resume:cbdd9eeb5255863c
context_pack_hash: cbdd9eeb5255863c4870d83e88642e9c4a3eef8e7cdfb8b5fb9a8ee7ac5a25d8
MCP receipt: .auditooor/memory_context_receipt.json
NOT_SUBMIT_READY

Flags liquidation entrypoints that:
  1. use stored or cached borrower liabilities without same-path accrual,
     reload, checkpoint, or fresh debt recomputation;
  2. strictly revert on debt plus liquidation bonus when collateral is
     underfunded, instead of capping the seized collateral or partial repay;
  3. partially settle debt from an available pool, seize collateral, and save
     borrower state without full-cover guard, zeroing, closeout, or bad-debt
     accounting.

R40/R76/R80 caveat: detector hits are source-review candidates only, not proof.
They require source existence, real in-scope execution, mutation-verified
non-vacuous evidence, and non-mock contract-under-test validation before filing.
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


DETECTOR_ID = "rust_wave1.liquidation_stale_liabilities_fire39"
SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
VERIFICATION_TIER = "tier-3-synthetic-taxonomy-anchored"
ATTACK_CLASS = "liquidation-trigger-poison"


_LIQ_ENTRY_RE = re.compile(
    r"(?i)(liquidat|liquidate|close_?position|seize|repay_?bad|"
    r"health|solvent|underwater|unsafe|margin|borrow)"
)

_STORED_LIABILITY_RE = re.compile(
    r"(?i)(borrow_?balance_?stored|stored_?(?:borrow|debt|liabilit)|"
    r"cached_?(?:borrow|debt|liabilit)|debt_?snapshot|liabilit(?:y|ies)_?snapshot|"
    r"principal_?debt|borrow_?principal|last_?debt|stale_?debt|"
    r"account_?debt_?stored|stored_?borrow_?balance)"
)
_FRESH_LIABILITY_RE = re.compile(
    r"(?i)(accrue_?(?:interest|borrow|debt|market|account)|"
    r"update_?(?:interest|borrow_?index|debt|liabilit|account)|"
    r"refresh_?(?:borrow|debt|liabilit|position|account)|"
    r"reload_?(?:borrow|debt|liabilit|position|account)|"
    r"sync_?(?:borrow|debt|liabilit|position|account|index)|"
    r"checkpoint_?(?:borrow|debt|liabilit|position|account)|"
    r"current_?(?:borrow|debt|liabilit|balance)|"
    r"borrow_?balance_?current|load_?current_?borrow|recompute_?(?:debt|liabilit))"
)

_BONUS_CONTEXT_RE = re.compile(
    r"(?is)(liquidation_?bonus|liq_?bonus|bonus_?bps|bonus_?basis|"
    r"bonus_?basis_?points|\bbonus\b|liquidation_?incentive|discount)"
)
_REQUIRED_ASSIGN_RE = re.compile(
    r"(?is)(?:let\s+)?(?P<var>required|total_required|collateral_needed|"
    r"repay_required|required_collateral|debt_with_bonus)\s*(?::[^=;]+)?=\s*"
    r"(?P<expr>[^;]*(?:debt|repay|amount|debt_to_cover)[^;]*"
    r"(?:bonus|bonus_basis|basis_points|bonus_bps|liquidation_incentive|discount)[^;]*);"
)
_STRICT_REQUIRED_RE = re.compile(
    r"(?is)("
    r"require\s*\(\s*(?:\w+\.)?(?P<req_a>required|total_required|collateral_needed|"
    r"repay_required|required_collateral|debt_with_bonus)\s*<=\s*"
    r"(?P<col_a>[\w\.]*collateral[\w\.]*)\s*\)"
    r"|assert!\s*\(\s*(?:\w+\.)?(?P<req_b>required|total_required|collateral_needed|"
    r"repay_required|required_collateral|debt_with_bonus)\s*<=\s*"
    r"(?P<col_b>[\w\.]*collateral[\w\.]*)"
    r"|if\s+(?P<col_c>[\w\.]*collateral[\w\.]*)\s*<\s*"
    r"(?P<req_c>required|total_required|collateral_needed|repay_required|"
    r"required_collateral|debt_with_bonus)\s*\{(?P<branch>[^{}]{0,260})"
    r")"
)
_REVERT_RE = re.compile(
    r"(?is)(return\s+Err|Err\s*\(|panic!\s*\(|panic_with_error!\s*\(|"
    r"require\s*\(|assert!\s*\(|insufficient)"
)
_CAP_BEFORE_RE = re.compile(
    r"(?is)(?:std::cmp::)?min\s*\(|\.min\s*\(|clamp\s*\(|"
    r"saturating_sub\s*\(|partial_?liquidat|cap_?(?:seize|repay|collateral)"
)

_PARTIAL_SETTLE_RE = re.compile(
    r"(?is)(?P<debt>[\w\.]*debt[\w\.]*)\s*-=\s*"
    r"(?P<settle>[^;\n]*(?:\.min\s*\(|(?:std::cmp::|cmp::)?min\s*\(|"
    r"available|pool|reserve|buffer|liquidit)[^;\n]*);"
)
_FULL_COVER_GUARD_RE = re.compile(
    r"(?is)(assert!\s*\([^;\n{}]*(?:pool|available|reserve|buffer|liquidit)"
    r"[^;\n{}]*>=\s*[\w\.]*debt|require\s*\([^;\n{}]*(?:pool|available|reserve|buffer|liquidit)"
    r"[^;\n{}]*>=\s*[\w\.]*debt|if\s+(?:pool|available|reserve|buffer|liquidit)[\w\.]*"
    r"\s*<\s*[\w\.]*debt\s*\{[^{}]{0,220}(?:return\s+Err|panic|revert))"
)
_SEIZE_OR_CLOSE_RE = re.compile(
    r"(?is)(seize_?collateral|transfer_?collateral|liquidat\w*collateral|"
    r"close_?position|remove_?position|burn_?collateral|foreclose)"
)
_SAVE_BORROWER_RE = re.compile(
    r"(?is)(save_?(?:borrower|position|account)|store_?(?:borrower|position|account)|"
    r"write_?(?:borrower|position|account)|\.set\s*\(|\.insert\s*\()"
)
_BAD_DEBT_OR_ZERO_RE = re.compile(
    r"(?is)([\w\.]*debt[\w\.]*\s*=\s*0\b|clear_?debt|zero_?debt|"
    r"record_?bad_?debt|bad_?debt|write_?off|sociali[sz]e_?debt|"
    r"absorb_?loss|record_?deficit|insurance_?fund|close_?borrower|"
    r"delete_?borrower|remove_?borrower|mark_?liquidated)"
)


def _line_from_offset(fn_node, body: str, offset: int) -> tuple[int, int]:
    fn_line, fn_col = line_col(fn_node)
    return fn_line + body[:offset].count("\n"), fn_col


def _first(pattern: re.Pattern[str], body: str) -> re.Match[str] | None:
    return pattern.search(body)


def _matches_stale_stored_liability(name: str, body: str) -> re.Match[str] | None:
    if not _LIQ_ENTRY_RE.search(name):
        return None
    stale = _first(_STORED_LIABILITY_RE, body)
    if stale is None:
        return None
    if _FRESH_LIABILITY_RE.search(body[:stale.start()]):
        return None
    return stale


def _matches_strict_underfunded_bonus(name: str, body: str) -> re.Match[str] | None:
    if not _LIQ_ENTRY_RE.search(name):
        return None
    if _BONUS_CONTEXT_RE.search(body) is None:
        return None
    assignment = _first(_REQUIRED_ASSIGN_RE, body)
    if assignment is None:
        return None
    strict = _first(_STRICT_REQUIRED_RE, body[assignment.end():])
    if strict is None:
        return None
    strict_start = assignment.end() + strict.start()
    branch = strict.groupdict().get("branch") or strict.group(0)
    if _REVERT_RE.search(branch) is None:
        return None
    if _CAP_BEFORE_RE.search(body[assignment.end():strict_start]):
        return None
    return strict


def _matches_partial_zombie_debt(name: str, body: str) -> re.Match[str] | None:
    if not _LIQ_ENTRY_RE.search(name):
        return None
    partial = _first(_PARTIAL_SETTLE_RE, body)
    if partial is None:
        return None
    if _FULL_COVER_GUARD_RE.search(body[:partial.start()]):
        return None
    after = body[partial.end():]
    if _BAD_DEBT_OR_ZERO_RE.search(after):
        return None
    if _SEIZE_OR_CLOSE_RE.search(after) is None:
        return None
    if _SAVE_BORROWER_RE.search(after) is None:
        return None
    return partial


def _hit(fn_node, source: bytes, body: str, match: re.Match[str], variant: str, detail: str):
    line, col = _line_from_offset(fn_node, body, match.start())
    name = fn_name(fn_node, source)
    return {
        "severity": "medium",
        "line": line,
        "col": col,
        "snippet": match.group(0).strip()[:220],
        "message": (
            f"fn `{name}` matches Fire39 liquidation stale liabilities "
            f"`{variant}`: {detail}"
        ),
    }


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        body_node = fn_body(fn)
        if body_node is None:
            continue
        name = fn_name(fn, source)
        body = body_text_nocomment(body_node, source)

        stale = _matches_stale_stored_liability(name, body)
        if stale is not None:
            hits.append(_hit(
                fn,
                source,
                body,
                stale,
                "stored-liability-without-accrual",
                "stored borrower liability is read in liquidation logic without same-path accrual, reload, or checkpoint",
            ))

        strict = _matches_strict_underfunded_bonus(name, body)
        if strict is not None:
            hits.append(_hit(
                fn,
                source,
                body,
                strict,
                "strict-underfunded-bonus-revert",
                "debt plus liquidation bonus is enforced as an all-or-nothing collateral requirement",
            ))

        partial = _matches_partial_zombie_debt(name, body)
        if partial is not None:
            hits.append(_hit(
                fn,
                source,
                body,
                partial,
                "partial-settlement-zombie-debt",
                "partial pool settlement seizes collateral and saves borrower state without zeroing or bad-debt accounting",
            ))

    return hits
