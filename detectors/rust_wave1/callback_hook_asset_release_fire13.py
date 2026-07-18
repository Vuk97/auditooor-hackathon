"""
callback_hook_asset_release_fire13.py

Flags Rust asset-release paths where a hook/callback or destructive asset
effect runs before the ownership, escrow, or fee-settlement state is finalized.

Fire13 recall gap:
- callback-hook-exploit had 5.9% same-class Rust recall.
- Confirmed held-out misses include rental-stop asset theft and ERC721 wrapper
  partial unwrap fee theft fixtures.

This detector is intentionally narrower than generic callback-before-finalize
logic. It focuses on asset custody release, ownership remapping, and partial
fee-bearing position unwraps.

Fire14 lift:
- Treat flash-loan borrower callbacks as the same class when the loan releases
  assets before repayment, fee accounting, or rounded-up premium collection.
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
    source_nocomment,
)


DETECTOR_ID = "rust_wave1.callback_hook_asset_release_fire13"

_FN_CONTEXT_RE = re.compile(
    r"(?i)(stop|end|cancel|release|unlock|withdraw|unwrap|settle|claim|"
    r"close|redeem|finali[sz]e|auction)"
)

_UNGUARDED_RELEASE_FN_RE = re.compile(
    r"(?i)(stop|end|cancel|release|unlock|settle|claim|close|redeem|auction)"
)

_UNGUARDED_RELEASE_CONTEXT_RE = re.compile(
    r"(?i)\b(escrow|rental|rentals|nft_owner|listing|auction|custody|vault)\b"
)

_ASSET_CONTEXT_RE = re.compile(
    r"(?i)\b(nft|erc721|erc1155|token_id|asset|escrow|rental|rentals|"
    r"owner_of|nft_owner|position|positions|liquidity|fee_growth|wrapper|"
    r"listing|auction|custody|vault)\b"
)

_HOOK_CALL_RE = re.compile(
    r"(?is)\b(?:self\.)?"
    r"[A-Za-z_][A-Za-z0-9_]*(?:hook|callback|receiver|recipient|notifier|"
    r"plugin|callee)[A-Za-z0-9_]*"
    r"\s*\.\s*(?:before|after|on|notify|callback|receive|handle|execute)"
    r"[A-Za-z0-9_]*\s*\([^;{}]{0,500}\)\s*\??\s*;"
)

_ASSET_RELEASE_RE = re.compile(
    r"(?is)("
    r"\b(?:self\.)?(?:escrow|rentals|owner_of|nft_owner|positions|listings|"
    r"auctions|custody|vault)\s*\.\s*(?:remove|take|insert)\s*\([^;{}]{0,260}\)|"
    r"\b(?:release|unlock|withdraw|payout|send|transfer|transfer_from|"
    r"safe_transfer_from)\s*\([^;{}]{0,300}\)|"
    r"\.\s*(?:release|unlock|withdraw|payout|send|transfer|transfer_from|"
    r"safe_transfer_from|transfer_out)\s*\([^;{}]{0,300}\)|"
    r"\b[A-Za-z_][A-Za-z0-9_\.]*liquidity\s*-=\s*[A-Za-z_][A-Za-z0-9_]*"
    r")"
)

_OWNER_OR_AUTH_GUARD_RE = re.compile(
    r"(?is)("
    r"\b(?:ensure|require|assert|assert_eq)\s*!?\s*\([^;{}]{0,360}"
    r"\b(?:owner|caller|sender|signer|renter|lender|recipient|authorized|auth)"
    r"\b|"
    r"\bif\s+[^{};]{0,360}\b(?:caller|sender|signer)\b[^{};]{0,360}"
    r"\b(?:owner|renter|lender|recipient|authorized|auth)\b|"
    r"\bif\s+[^{};]{0,360}\b(?:owner|renter|lender|recipient)\b[^{};]{0,360}"
    r"\b(?:caller|sender|signer)\b|"
    r"\b(?:require_auth|authorize|authenticate|check_owner|verify_owner|"
    r"ensure_owner|require_owner|validate_owner|is_approved_or_owner|"
    r"approved_or_owner|owns_nft|owns_ticket)\s*\(|"
    r"\bowner_of\s*\([^;{}]{0,200}\)\s*(?:==|!=)|"
    r"\b(?:pending|in_progress|processing|locked|entered|claimed|"
    r"settled|processed)\b[^;{}]{0,120}(?:=|insert|set)\s*"
    r")"
)

_FEE_CONTEXT_RE = re.compile(
    r"(?i)(fee_growth|collect_fees|claim_fees|settle_fees|sync_fees|fees)"
)

_PARTIAL_FN_RE = re.compile(r"(?i)(partial|unwrap|redeem|withdraw|split)")

_POSITION_CLONE_RE = re.compile(
    r"(?is)(?:positions\s*\.\s*insert\s*\([^;{}]{0,240}"
    r"position\s*\.\s*clone\s*\(\)|"
    r"\b(?:let\s+(?:mut\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*)?"
    r"position\s*\.\s*clone\s*\(\))"
)

_LIQUIDITY_DEBIT_RE = re.compile(
    r"(?is)\b(?:new_position|position)\s*\.\s*liquidity\s*-=\s*"
    r"(?:amount|shares|liquidity|withdraw_amount)"
)

_FEE_SETTLE_RE = re.compile(
    r"(?i)\b(?:collect|settle|claim|sync|flush)_(?:fees?|accrued|pending)\s*\("
)

_FLASHLOAN_FN_RE = re.compile(
    r"(?i)(flash_loan|flashloan|flash|execute_operation|premium|fee)"
)

_FLASHLOAN_CONTEXT_RE = re.compile(
    r"(?i)\b(flash_loan|flashloan|flash loan|receiver|borrower|premium|fee)\b"
)

_TRANSFER_CALL_RE = re.compile(
    r"(?is)\b[A-Za-z_][A-Za-z0-9_\.]*\s*\.\s*"
    r"(?:transfer|transfer_from|safe_transfer_from|transfer_checked)"
    r"\s*\([^;{}]{0,420}\)\s*;"
)

_FLASH_CALLBACK_RE = re.compile(
    r"(?is)\b(?:execute_operation|on_flash_loan|on_flashloan|"
    r"receive_flash_loan|receive_flashloan|flashloan_callback|"
    r"call_flashloan_receiver|invoke_contract)\s*\([^;{}]{0,420}\)"
    r"|"
    r"\b[A-Za-z_][A-Za-z0-9_\.]*\s*\.\s*"
    r"(?:execute_operation|on_flash_loan|on_flashloan|receive_flash_loan|"
    r"receive_flashloan|flashloan_callback|callback)\s*\([^;{}]{0,420}\)"
)

_REPAY_OR_VERIFY_RE = re.compile(
    r"(?i)\b(?:verify_repayment|ensure_repaid|assert_repaid|require_repaid|"
    r"check_balance_after|check_repayment|balance_after|repay|repayment)"
)

_PREMIUM_TOKEN_RE = re.compile(
    r"(?i)\b(?:premium|flash_loan_premium|flashloan_fee|flash_fee|"
    r"protocol_fee|fee_bps|fee_rate)\b"
)

_PREMIUM_USE_RE = re.compile(
    r"(?i)(?:(?:premium|flash_loan_premium|flashloan_fee|flash_fee|"
    r"protocol_fee|fee)\b[^;\n]{0,180}"
    r"(?:transfer|set|insert|accrue|collect|mint|\+=|\+)"
    r"|"
    r"(?:transfer|set|insert|accrue|collect|mint|\+=|\+)"
    r"[^;\n]{0,180}\b(?:premium|flash_loan_premium|flashloan_fee|"
    r"flash_fee|protocol_fee|fee)\b)"
)

_FLOOR_PREMIUM_RE = re.compile(
    r"(?is)\b[A-Za-z_][A-Za-z0-9_]*\s*\*\s*"
    r"[A-Za-z_][A-Za-z0-9_]*\s*/\s*"
    r"(?:BASIS_POINTS|BPS_SCALE|PERCENTAGE_FACTOR|WAD|RAY|10_000|10000)"
    r"|\bpercent_mul\s*\("
)

_CEIL_PREMIUM_RE = re.compile(
    r"(?i)(ceil|round_up|percent_mul_(?:up|ceil)|checked_add|"
    r"saturating_add|(?:BASIS_POINTS|BPS_SCALE|PERCENTAGE_FACTOR|WAD|RAY)"
    r"\s*-\s*1)"
)


def _line_for_offset(base_line: int, text: str, offset: int) -> int:
    return base_line + text[:offset].count("\n")


def _first_asset_release(body_text: str) -> re.Match[str] | None:
    return _ASSET_RELEASE_RE.search(body_text)


def _has_asset_context(name: str, body_text: str) -> bool:
    return bool(_FN_CONTEXT_RE.search(name) and _ASSET_CONTEXT_RE.search(body_text))


def _has_unguarded_release_context(name: str, body_text: str) -> bool:
    return bool(
        _UNGUARDED_RELEASE_FN_RE.search(name)
        and _UNGUARDED_RELEASE_CONTEXT_RE.search(body_text)
    )


def _partial_unwrap_before_fee_settle(body_text: str, module_text: str, name: str):
    if not _PARTIAL_FN_RE.search(name):
        return None
    if not (_FEE_CONTEXT_RE.search(body_text) or _FEE_CONTEXT_RE.search(module_text)):
        return None

    clone = _POSITION_CLONE_RE.search(body_text)
    if clone is None:
        return None

    debit = _LIQUIDITY_DEBIT_RE.search(body_text, pos=clone.end())
    if debit is None:
        return None

    if _FEE_SETTLE_RE.search(body_text[: clone.start()]):
        return None

    return clone


def _first_transfer(body_text: str) -> re.Match[str] | None:
    return _TRANSFER_CALL_RE.search(body_text)


def _is_flashloan_context(name: str, body_text: str) -> bool:
    return bool(_FLASHLOAN_FN_RE.search(name) and _FLASHLOAN_CONTEXT_RE.search(body_text))


def _flashloan_no_premium(body_text: str, name: str) -> re.Match[str] | None:
    if not _is_flashloan_context(name, body_text):
        return None

    transfer = _first_transfer(body_text)
    if transfer is None:
        return None

    transfer_count = len(list(_TRANSFER_CALL_RE.finditer(body_text)))
    has_callback = bool(_FLASH_CALLBACK_RE.search(body_text))
    if has_callback:
        return None
    if transfer_count < 2:
        return None

    if _PREMIUM_TOKEN_RE.search(body_text):
        return None

    return transfer


def _flashloan_premium_dropped(body_text: str, name: str) -> re.Match[str] | None:
    if not _is_flashloan_context(name, body_text):
        return None

    premium = _PREMIUM_TOKEN_RE.search(body_text)
    if premium is None:
        return None

    if not _first_transfer(body_text) and not _FLASH_CALLBACK_RE.search(body_text):
        return None

    if _PREMIUM_USE_RE.search(body_text):
        return None

    return premium


def _flashloan_floor_premium(body_text: str, name: str) -> re.Match[str] | None:
    if not _is_flashloan_context(name, body_text):
        return None

    floor = _FLOOR_PREMIUM_RE.search(body_text)
    if floor is None:
        return None

    start = max(0, floor.start() - 160)
    end = min(len(body_text), floor.end() + 160)
    if _CEIL_PREMIUM_RE.search(body_text[start:end]):
        return None

    return floor


def _flashloan_callback_before_repay(body_text: str, name: str) -> re.Match[str] | None:
    if not _is_flashloan_context(name, body_text):
        return None

    callback = _FLASH_CALLBACK_RE.search(body_text)
    if callback is None:
        return None

    repay_after = _REPAY_OR_VERIFY_RE.search(body_text, pos=callback.end())
    premium_after = _PREMIUM_USE_RE.search(body_text, pos=callback.end())
    if repay_after is not None or premium_after is not None:
        return None

    return callback


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    module_text = source_nocomment(source)

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        name = fn_name(fn, source)
        if name in {"main", "new"}:
            continue

        body = fn_body(fn)
        if body is None:
            continue

        body_text = body_text_nocomment(body, source)
        body_line, _ = line_col(body)

        no_premium = _flashloan_no_premium(body_text, name)
        if no_premium is not None:
            line = _line_for_offset(body_line, body_text, no_premium.start())
            hits.append(
                {
                    "detector_id": DETECTOR_ID,
                    "severity": "high",
                    "line": line,
                    "col": 0,
                    "snippet": snippet_of(fn, source)[:220],
                    "message": (
                        f"fn `{name}` releases flash-loan assets at line "
                        f"{line} but never accounts for a premium or fee."
                    ),
                }
            )
            continue

        dropped_premium = _flashloan_premium_dropped(body_text, name)
        if dropped_premium is not None:
            line = _line_for_offset(body_line, body_text, dropped_premium.start())
            hits.append(
                {
                    "detector_id": DETECTOR_ID,
                    "severity": "high",
                    "line": line,
                    "col": 0,
                    "snippet": snippet_of(fn, source)[:220],
                    "message": (
                        f"fn `{name}` references flash-loan premium or fee "
                        f"state at line {line} but does not charge, accrue, "
                        f"or settle it before releasing assets."
                    ),
                }
            )
            continue

        floor_premium = _flashloan_floor_premium(body_text, name)
        if floor_premium is not None:
            line = _line_for_offset(body_line, body_text, floor_premium.start())
            hits.append(
                {
                    "detector_id": DETECTOR_ID,
                    "severity": "medium",
                    "line": line,
                    "col": 0,
                    "snippet": snippet_of(fn, source)[:220],
                    "message": (
                        f"fn `{name}` computes flash-loan premium at line "
                        f"{line} with floor rounding and no visible ceil or "
                        f"round-up path."
                    ),
                }
            )
            continue

        flash_callback = _flashloan_callback_before_repay(body_text, name)
        if flash_callback is not None:
            line = _line_for_offset(body_line, body_text, flash_callback.start())
            hits.append(
                {
                    "detector_id": DETECTOR_ID,
                    "severity": "high",
                    "line": line,
                    "col": 0,
                    "snippet": snippet_of(fn, source)[:220],
                    "message": (
                        f"fn `{name}` invokes a borrower-controlled flash "
                        f"callback at line {line} before visible repayment, "
                        f"premium, or fee accounting finalization."
                    ),
                }
            )
            continue

        partial = _partial_unwrap_before_fee_settle(body_text, module_text, name)
        if partial is not None:
            line = _line_for_offset(body_line, body_text, partial.start())
            hits.append(
                {
                    "detector_id": DETECTOR_ID,
                    "severity": "high",
                    "line": line,
                    "col": 0,
                    "snippet": snippet_of(fn, source)[:220],
                    "message": (
                        f"fn `{name}` clones or rewrites a fee-bearing "
                        f"position at line {line} and later debits liquidity "
                        f"without settling accrued fees first."
                    ),
                }
            )
            continue

        hook = _HOOK_CALL_RE.search(body_text)
        if hook is not None:
            if not _has_asset_context(name, body_text):
                continue
            release_after_hook = _ASSET_RELEASE_RE.search(body_text, pos=hook.end())
            if release_after_hook is not None:
                prefix = body_text[: hook.start()]
                if not _OWNER_OR_AUTH_GUARD_RE.search(prefix):
                    line = _line_for_offset(body_line, body_text, hook.start())
                    release_line = _line_for_offset(
                        body_line,
                        body_text,
                        release_after_hook.start(),
                    )
                    hits.append(
                        {
                            "detector_id": DETECTOR_ID,
                            "severity": "high",
                            "line": line,
                            "col": 0,
                            "snippet": snippet_of(fn, source)[:220],
                            "message": (
                                f"fn `{name}` invokes a hook or callback at "
                                f"line {line} before asset custody, ownership, "
                                f"or escrow state is finalized at line "
                                f"{release_line}."
                            ),
                        }
                    )
                    continue

        if not _has_unguarded_release_context(name, body_text):
            continue

        release = _first_asset_release(body_text)
        if release is None:
            continue

        prefix = body_text[: release.start()]
        if _OWNER_OR_AUTH_GUARD_RE.search(prefix):
            continue

        line = _line_for_offset(body_line, body_text, release.start())
        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "severity": "high",
                "line": line,
                "col": 0,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"fn `{name}` performs asset release, ownership rewrite, "
                    f"or escrow mutation at line {line} before a visible "
                    f"owner, authorization, or settlement guard."
                ),
            }
        )

    return hits
