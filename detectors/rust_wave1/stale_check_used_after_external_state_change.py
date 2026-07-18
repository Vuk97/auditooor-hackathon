"""
stale_check_used_after_external_state_change.py

Flags Rust functions that cache a critical state value, validate it, make an
external mutable call, and then consume the stale cached value without a
post-call reload or revalidation.

This detector is scoped to the state-change-between-check-and-use recall
family. It is intentionally narrower than generic reentrancy: the hit needs a
local state cache, a pre-call guard over that cache, an external state-changing
boundary, and a post-boundary use of the same cache in value movement or state
finalization.
"""

from __future__ import annotations

import pathlib
import re

from _util import (
    body_text_nocomment,
    crate_name_from_path,
    fn_body,
    fn_module_path,
    fn_name,
    fn_signature_normalized,
    function_items,
    in_test_cfg,
    is_pub,
    line_col,
    snippet_of,
)


DETECTOR_ID = "rust_wave1.stale_check_used_after_external_state_change"

_CACHE_ASSIGN_RE = re.compile(
    r"(?is)\blet\s+(?:mut\s+)?(?P<var>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?:\:[^=;]+)?=\s*(?P<rhs>[^;]{1,800});"
)

_STATE_SOURCE_RE = re.compile(
    r"(?ix)"
    r"(?:"
    r"\bself\s*\.|"
    r"\bctx\s*\.\s*accounts\s*\.|"
    r"\baccounts?\s*\.|"
    r"\bstate\s*\.|"
    r"\bledger\s*\.|"
    r"\bvault\s*\.|"
    r"\bmarket\s*\.|"
    r"\bpool\s*\.|"
    r"\border[s]?\s*\.|"
    r"\broute[s]?\s*\.|"
    r"\bposition[s]?\s*\.|"
    r"\bbalance[s]?\s*\.|"
    r"\ballowance[s]?\s*\.|"
    r"\breserve[s]?\s*\.|"
    r"\bstorage\s*\(\s*\)|"
    r"\.get\s*\(|"
    r"\.load\s*\(|"
    r"\.borrow\s*\(|"
    r"\.try_borrow\s*\(|"
    r"\.balance_of\s*\(|"
    r"\.allowance\s*\(|"
    r"\.remaining\s*\b|"
    r"\.available\s*\b|"
    r"\.status\s*\b|"
    r"\.limit\s*\b|"
    r"\.nonce\s*\b"
    r")"
)

_CRITICAL_VALUE_RE = re.compile(
    r"(?i)"
    r"(balance|available|remaining|reserve|allowance|quota|limit|cap|"
    r"credit|debit|debt|collateral|share|shares|asset|assets|amount|"
    r"supply|liquidity|position|order|route|escrow|settle|settlement|"
    r"reward|payout|refund|nonce|status|used|processed|fillable)"
)

_CHECK_FORM_RE = re.compile(
    r"(?is)"
    r"(?:"
    r"\bif\s+[^\{;]{0,620}\{|"
    r"\b(?:ensure|require|assert|debug_assert)!\s*\([^;]{0,720}\)|"
    r"\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*"
    r"(?:checked_sub|checked_add|saturating_sub|saturating_add)"
    r"\s*\([^;]{0,360}"
    r")"
)

_CHECK_OPERATOR_RE = re.compile(
    r"(?is)(?:[<>!=]=?|checked_|saturating_|is_zero|is_empty|ok_or|return\s+Err)"
)

_EXTERNAL_COMPONENT_RE = (
    r"(?:"
    r"[A-Za-z_][A-Za-z0-9_]*"
    r"(?:hook|hooks|callback|callbacks|plugin|plugins|receiver|recipient|"
    r"callee|adapter|router|route|oracle|paymaster|token_program|"
    r"external_program|user_program|cpi_program)"
    r"[A-Za-z0-9_]*|"
    r"(?:hook|hooks|callback|callbacks|plugin|plugins|receiver|recipient|"
    r"callee|adapter|router|route|oracle|paymaster|token_program|"
    r"external_program|user_program|cpi_program)"
    r")"
)

_EXTERNAL_METHOD_RE = (
    r"(?:before|after|on|callback|call|execute|validate|invoke|notify|"
    r"handle|receive|transfer|transfer_checked|transfer_from|mint|mint_to|"
    r"burn|swap|quote|settle|update|sync|refresh|rebalance|route)[A-Za-z0-9_]*"
)

_EXTERNAL_STATE_CHANGE_RE = re.compile(
    rf"(?ix)"
    rf"(?:"
    rf"\benv\s*\.\s*(?:try_)?invoke_contract(?:\s*::\s*<[^>]+>)?\s*\(|"
    rf"\b(?:try_)?invoke_contract\s*\(|"
    rf"\bcall_contract\s*\(|"
    rf"\b[A-Za-z_][A-Za-z0-9_]*Client\s*::\s*new\s*\(|"
    rf"\b::Client\s*::\s*new\s*\(|"
    rf"\binvoke_signed\s*\(|"
    rf"\bprogram::invoke_signed\s*\(|"
    rf"\binvoke\s*\(|"
    rf"\bprogram::invoke\s*\(|"
    rf"\banchor_spl::token::[A-Za-z_][A-Za-z0-9_]*\s*\(|"
    rf"\btoken::(?:transfer|transfer_checked|mint_to|burn)\s*\(|"
    rf"\bcpi::[A-Za-z_][A-Za-z0-9_]*\s*\(|"
    rf"\bCpiContext\s*::\s*new\b|"
    rf"\b(?:(?:self|ctx|accounts?)\s*\.\s*)?"
    rf"(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)*"
    rf"{_EXTERNAL_COMPONENT_RE}\s*\.\s*{_EXTERNAL_METHOD_RE}\s*\("
    rf")"
)

_VALUE_EFFECT_RE = re.compile(
    r"(?i)"
    r"(transfer|transfer_from|safe_transfer|send|mint_to|burn|credit|"
    r"debit|settle|settlement|finalize|finalise|release|withdraw|payout|"
    r"pay|refund|distribute|fill|execute|record|store|insert|set|update|"
    r"mark_|reserve|commit|unlock|claim|consume)"
)

_POST_CALL_REVALIDATION_RE = re.compile(
    r"(?i)"
    r"(reload|refresh|revalid|validate|current|latest|post_call|post_cpi|"
    r"post_external|after_call|after_cpi|after_hook|after_callback|"
    r"ensure_current|check_current|balance_after|remaining_after|"
    r"available_after|status_after)"
)


def _contains_var(text: str, var_name: str) -> bool:
    return re.search(rf"\b{re.escape(var_name)}\b", text) is not None


def _line_for_offset(base_line: int, text: str, offset: int) -> int:
    return base_line + text[:offset].count("\n")


def _first_non_ws_offset(match: re.Match[str]) -> int:
    text = match.group(0)
    return match.start() + len(text) - len(text.lstrip())


def _is_state_cache(var_name: str, rhs: str) -> bool:
    combined = f"{var_name} {rhs}"
    if not _CRITICAL_VALUE_RE.search(combined):
        return False
    return bool(_STATE_SOURCE_RE.search(rhs))


def _find_pre_call_check(body_text: str, var_name: str, start: int):
    for match in _CHECK_FORM_RE.finditer(body_text, pos=start):
        snippet = match.group(0)
        if not _contains_var(snippet, var_name):
            continue
        if not _CHECK_OPERATOR_RE.search(snippet):
            continue
        return match
    return None


def _iter_external_mutations(body_text: str, start: int):
    yield from _EXTERNAL_STATE_CHANGE_RE.finditer(body_text, pos=start)


def _iter_stale_effect_uses(body_text: str, var_name: str, start: int):
    stmt_re = re.compile(
        rf"(?is)(?P<stmt>[^\{{\}};]*\b{re.escape(var_name)}\b[^;]*;)"
    )
    for match in stmt_re.finditer(body_text, pos=start):
        stmt = match.group("stmt")
        if not _VALUE_EFFECT_RE.search(stmt):
            continue
        yield match


def _has_post_call_revalidation(region: str, var_name: str) -> bool:
    escaped = re.escape(var_name)

    same_var_reload = re.search(rf"(?is)\b{escaped}\s*=", region)
    if same_var_reload and _STATE_SOURCE_RE.search(region):
        return True

    if _POST_CALL_REVALIDATION_RE.search(region):
        return True

    if _STATE_SOURCE_RE.search(region):
        for check in _CHECK_FORM_RE.finditer(region):
            check_text = check.group(0)
            if _CHECK_OPERATOR_RE.search(check_text):
                return True

    return False


def _add_optional_function_fields(row: dict, fn, source: bytes, fp: pathlib.Path) -> None:
    try:
        crate = crate_name_from_path(fp)
        if crate and crate != "unknown":
            row["crate_name"] = crate
    except Exception:
        pass
    try:
        module_path = fn_module_path(fn, source, fp)
        if module_path:
            row["module_path"] = module_path
    except Exception:
        pass
    try:
        signature = fn_signature_normalized(fn, source)
        if signature:
            row["fn_signature"] = signature
    except Exception:
        pass


def run(tree, source: bytes, filepath: str):
    hits = []
    fp = pathlib.Path(filepath)

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if not is_pub(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        raw_body = body_text_nocomment(body, source)
        name = fn_name(fn, source)
        body_line, _ = line_col(body)
        emitted_for_fn = False

        for assign in _CACHE_ASSIGN_RE.finditer(raw_body):
            var_name = assign.group("var")
            rhs = assign.group("rhs")
            if not _is_state_cache(var_name, rhs):
                continue

            check = _find_pre_call_check(raw_body, var_name, assign.end())
            if check is None:
                continue

            for external in _iter_external_mutations(raw_body, check.end()):
                post_use = next(
                    _iter_stale_effect_uses(raw_body, var_name, external.end()),
                    None,
                )
                if post_use is None:
                    continue

                post_region = raw_body[external.end():post_use.start()]
                if _has_post_call_revalidation(post_region, var_name):
                    continue

                check_line = _line_for_offset(body_line, raw_body, check.start())
                external_line = _line_for_offset(body_line, raw_body, external.start())
                use_line = _line_for_offset(
                    body_line,
                    raw_body,
                    _first_non_ws_offset(post_use),
                )
                row: dict = {
                    "detector_id": DETECTOR_ID,
                    "severity": "high",
                    "line": external_line,
                    "col": 0,
                    "snippet": snippet_of(body, source)[:220],
                    "message": (
                        f"fn `{name}` checks cached state value `{var_name}` "
                        f"at line {check_line}, crosses an external mutable "
                        f"state boundary at line {external_line}, then uses "
                        f"`{var_name}` in value movement or state finalization "
                        f"at line {use_line} without a post-call reload or "
                        f"revalidation."
                    ),
                }
                _add_optional_function_fields(row, fn, source, fp)
                hits.append(row)
                emitted_for_fn = True
                break
            if emitted_for_fn:
                break

    return hits
