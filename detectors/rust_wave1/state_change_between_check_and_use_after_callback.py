"""
state_change_between_check_and_use_after_callback.py

Flags Rust functions that cache a state value, check it, call an external
hook/callback/CPI/user-controlled target, and then reuse the same cached value
for settlement or value movement without a post-call reload or revalidation.

This is narrower than generic callback presence:
  1. A critical state value is assigned to a local variable.
  2. That local variable is used in a guard before the external call.
  3. An external callback, hook, CPI, or user-controlled call occurs.
  4. The same cached local is used after the call in transfer, credit,
     settlement, payout, or storage-finalization logic.
  5. No live state reload or revalidation appears between the call and use.
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


DETECTOR_ID = "rust_wave1.state_change_between_check_and_use_after_callback"

_CACHE_ASSIGN_RE = re.compile(
    r"(?is)\blet\s+(?:mut\s+)?(?P<var>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?:\:[^=;]+)?=\s*(?P<rhs>[^;]{1,700});"
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
    r"\bposition[s]?\s*\.|"
    r"\border[s]?\s*\.|"
    r"\bbalance[s]?\s*\.|"
    r"\ballowance[s]?\s*\.|"
    r"\breserve[s]?\s*\.|"
    r"\bstorage\s*\(\s*\)|"
    r"\.get\s*\(|"
    r"\.load\s*\(|"
    r"\.borrow\s*\(|"
    r"\.try_borrow\s*\(|"
    r"\.balance_of\s*\(|"
    r"\.amount\s*\b|"
    r"\.available\s*\b|"
    r"\.remaining\s*\b"
    r")"
)

_CRITICAL_VALUE_RE = re.compile(
    r"(?i)"
    r"(balance|available|remaining|reserve|allowance|quota|limit|cap|"
    r"credit|debit|debt|collateral|share|shares|asset|assets|amount|"
    r"supply|liquidity|position|order|escrow|settle|settlement|"
    r"reward|payout|refund|nonce|status|used|processed)"
)

_CHECK_FORM_RE = re.compile(
    r"(?is)"
    r"(?:"
    r"\bif\s+[^\{;]{0,420}\{|"
    r"\b(?:ensure|require|assert)!\s*\([^;]{0,520}\)|"
    r"\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*"
    r"(?:checked_sub|checked_add|saturating_sub|saturating_add)\s*\([^;]{0,260}"
    r")"
)

_CHECK_OPERATOR_RE = re.compile(
    r"(?is)(?:[<>!=]=?|checked_|saturating_|is_zero|is_empty|ok_or|return\s+Err)"
)

_EXTERNAL_CALL_RE = re.compile(
    r"(?ix)"
    r"(?:"
    r"\benv\s*\.\s*(?:try_)?invoke_contract(?:\s*::\s*<[^>]+>)?\s*\(|"
    r"\b(?:try_)?invoke_contract\s*\(|"
    r"\bcall_contract\s*\(|"
    r"\b[A-Za-z_][A-Za-z0-9_]*Client\s*::\s*new\s*\(|"
    r"\b::Client\s*::\s*new\s*\(|"
    r"\binvoke_signed\s*\(|"
    r"\bprogram::invoke_signed\s*\(|"
    r"\binvoke\s*\(|"
    r"\bprogram::invoke\s*\(|"
    r"\banchor_spl::token::[A-Za-z_][A-Za-z0-9_]*\s*\(|"
    r"\btoken::(?:transfer|transfer_checked|mint_to|burn)\s*\(|"
    r"\bcpi::[A-Za-z_][A-Za-z0-9_]*\s*\(|"
    r"\bCpiContext\s*::\s*new\b|"
    r"\b(?:hook|hooks|callback|callbacks|plugin|plugins|receiver|recipient|"
    r"callee|adapter|paymaster|user_program|external_program)\s*\.\s*"
    r"(?:before|after|on|callback|call|execute|validate|invoke|notify|"
    r"handle|receive)[A-Za-z0-9_]*\s*\(|"
    r"\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*"
    r"(?:before_[A-Za-z0-9_]+|after_[A-Za-z0-9_]+|on_[A-Za-z0-9_]+|"
    r"callback|call_contract|invoke|notify|receive_approval|validate_user_op)"
    r"\s*\("
    r")"
)

_VALUE_EFFECT_RE = re.compile(
    r"(?i)"
    r"(transfer|transfer_from|safe_transfer|send|mint_to|burn|credit|"
    r"debit|settle|settlement|finalize|finalise|release|withdraw|payout|"
    r"pay|refund|distribute|fill|execute|record|store|insert|set|update)"
)

_POST_CALLBACK_REVALIDATION_RE = re.compile(
    r"(?i)"
    r"(reload|refresh|revalid|validate|current|latest|post_callback|"
    r"post_call|after_callback|after_hook|after_cpi|ensure_current|"
    r"check_current|balance_after|remaining_after|available_after)"
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


def _find_check_after(body_text: str, var_name: str, start: int):
    for match in _CHECK_FORM_RE.finditer(body_text, pos=start):
        snippet = match.group(0)
        if not _contains_var(snippet, var_name):
            continue
        if not _CHECK_OPERATOR_RE.search(snippet):
            continue
        return match
    return None


def _iter_external_calls(body_text: str, start: int):
    for match in _EXTERNAL_CALL_RE.finditer(body_text, pos=start):
        text = match.group(0).strip()
        if text.startswith("self."):
            continue
        yield match


def _iter_cached_value_uses(body_text: str, var_name: str, start: int):
    stmt_re = re.compile(
        rf"(?is)(?P<stmt>[^\{{\}};]*\b{re.escape(var_name)}\b[^;]*;)"
    )
    for match in stmt_re.finditer(body_text, pos=start):
        stmt = match.group("stmt")
        if not _VALUE_EFFECT_RE.search(stmt):
            continue
        yield match


def _has_reload_or_revalidation(region: str, var_name: str) -> bool:
    escaped = re.escape(var_name)
    same_var_reload = re.search(rf"(?is)\b{escaped}\s*=", region)
    if same_var_reload and _STATE_SOURCE_RE.search(region):
        return True

    if _POST_CALLBACK_REVALIDATION_RE.search(region):
        return True

    if _STATE_SOURCE_RE.search(region):
        for check in _CHECK_FORM_RE.finditer(region):
            check_text = check.group(0)
            if _CHECK_OPERATOR_RE.search(check_text):
                return True

    return False


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

            check = _find_check_after(raw_body, var_name, assign.end())
            if check is None:
                continue

            for external in _iter_external_calls(raw_body, check.end()):
                post_use = next(
                    _iter_cached_value_uses(raw_body, var_name, external.end()),
                    None,
                )
                if post_use is None:
                    continue

                post_region = raw_body[external.end():post_use.start()]
                if _has_reload_or_revalidation(post_region, var_name):
                    continue

                call_line = _line_for_offset(body_line, raw_body, external.start())
                check_line = _line_for_offset(body_line, raw_body, check.start())
                use_line = _line_for_offset(
                    body_line,
                    raw_body,
                    _first_non_ws_offset(post_use),
                )
                row: dict = {
                    "detector_id": DETECTOR_ID,
                    "severity": "high",
                    "line": call_line,
                    "col": 0,
                    "snippet": snippet_of(body, source)[:220],
                    "message": (
                        f"fn `{name}` checks cached state value `{var_name}` "
                        f"at line {check_line}, makes an external callback/CPI "
                        f"at line {call_line}, then reuses `{var_name}` for "
                        f"value movement or settlement at line {use_line} "
                        f"without a post-call reload or revalidation."
                    ),
                }
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
                hits.append(row)
                emitted_for_fn = True
                break
            if emitted_for_fn:
                break

    return hits
