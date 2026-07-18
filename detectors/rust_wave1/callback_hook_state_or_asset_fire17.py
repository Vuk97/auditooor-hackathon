"""
callback_hook_state_or_asset_fire17.py

Rust same-class lift for callback-hook-exploit.

Flags asset or ownership flows where a callback, hook, receiver, or handler
surface can release custody or mutate ownership before the relevant owner,
state, or invariant has been checked or updated.

The detector is intentionally semantic-shape based:
  - callback or hook before asset release with no pre-hook owner/state guard
  - ERC721 safe mint/transfer wrappers that mutate state but never call the
    receiver callback
  - stale ownership handler pairs where transfer updates the current owner but
    does not update the secondary owner map, while burn trusts that stale map

Detector hits are candidate evidence only and require normal R40/R76/R80 proof
discipline before any filing work.
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


DETECTOR_ID = "rust_wave1.callback_hook_state_or_asset_fire17"

_CALLBACK_SURFACE_RE = re.compile(
    r"(?is)("
    r"\b(?:call_on_erc721_received|on_erc721_received)\s*\(|"
    r"\b(?:try_)?invoke_contract\s*\(|"
    r"\binvoke_signed\s*\(|"
    r"\binvoke\s*\(|"
    r"\bCpiContext\s*::\s*new\b|"
    r"\b(?:self\.)?[A-Za-z_][A-Za-z0-9_]*"
    r"(?:hook|callback|receiver|recipient|handler|notifier|plugin|callee)"
    r"[A-Za-z0-9_]*\s*\.\s*"
    r"(?:before|after|on|notify|callback|receive|handle|execute|validate|invoke)"
    r"[A-Za-z0-9_]*\s*\([^;{}]{0,560}\)\s*\??\s*;"
    r")"
)

_ASSET_OR_OWNER_MUTATION_RE = re.compile(
    r"(?is)("
    r"\b(?:self\.)?(?:escrow|custody|vault|positions|position|listings|"
    r"rentals|owner_of|owners|nft_owner|owner_to_record|records|balances|"
    r"pending_release|pending|claimed|processed|settled)\s*\.\s*"
    r"(?:remove|take|insert|set|push|save|update)\s*\([^;{}]{0,420}\)|"
    r"\b(?:release|unlock|withdraw|payout|send|transfer|transfer_from|"
    r"safe_transfer_from|mint|burn)\s*\([^;{}]{0,420}\)|"
    r"\.\s*(?:release|unlock|withdraw|payout|send|transfer|transfer_from|"
    r"safe_transfer_from|mint_to|burn)\s*\([^;{}]{0,420}\)|"
    r"\b[A-Za-z_][A-Za-z0-9_\.]*(?:owner|status|balance|supply|liquidity)"
    r"\s*(?:=|\+=|-=)"
    r")"
)

_OWNER_OR_STATE_GUARD_RE = re.compile(
    r"(?is)("
    r"\b(?:ensure|require|assert|assert_eq|ensure_eq)\s*!?\s*\([^;{}]{0,480}"
    r"(?:owner|caller|sender|signer|authority|receiver|recipient|state|"
    r"status|pending|locked|in_progress|processed|settled|current)"
    r"|"
    r"\bif\s+[^{};]{0,420}"
    r"(?:caller|sender|signer|authority|receiver|recipient)"
    r"[^{};]{0,420}(?:owner|authorized|current|status)[^{};]*\{"
    r"[^{}]{0,220}(?:return\s+Err|Err\s*\(|bail!\s*\()"
    r"|"
    r"\b(?:require_auth|authorize|authenticate|check_owner|verify_owner|"
    r"ensure_owner|require_owner|validate_owner|is_approved_or_owner|"
    r"approved_or_owner|owns_nft|owns_record|validate_state|ensure_state)"
    r"\s*\(|"
    r"\b(?:pending|in_progress|processing|locked|entered|claimed|processed|"
    r"settled|finalized|finalised)\b[^;{}]{0,160}(?:=|insert|set)\s*"
    r")"
)

_SAFE_WRAPPER_NAME_RE = re.compile(r"(?i)^safe_(?:mint|transfer_from|transfer)$")
_INTERNAL_ERC721_MUTATION_RE = re.compile(
    r"(?is)\b(?:self\.)?(?:mint|transfer_from|transfer)\s*\([^;{}]{0,360}\)"
)
_RECEIVER_CALLBACK_RE = re.compile(
    r"(?is)\b(?:call_on_erc721_received|on_erc721_received)\s*\("
)
_RECEIVER_TARGET_RE = re.compile(r"(?i)\b(to|receiver|recipient)\b")

_STALE_TRANSFER_FN_RE = re.compile(r"(?i)(transfer|move|assign|change_owner)")
_OWNER_FIELD_SET_RE = re.compile(
    r"(?is)\b[A-Za-z_][A-Za-z0-9_\.]*(?:owner|owner_id)\s*=\s*"
    r"(?:new_owner|to|receiver|recipient)"
)
_SECONDARY_OWNER_MAP_RE = re.compile(r"(?i)\bowner_to_record\b")
_SECONDARY_OWNER_UPDATE_RE = re.compile(
    r"(?is)\bowner_to_record\s*\.\s*(?:remove|insert|set|update)\s*\("
)
_BURN_FN_RE = re.compile(r"(?i)(burn|destroy|delete|remove)")
_STALE_OWNER_AUTH_RE = re.compile(
    r"(?is)\bowner_to_record\s*\.\s*get\s*\([^;{}]{0,220}"
    r"(?:caller|sender|owner)"
)
_ASSET_REMOVE_RE = re.compile(
    r"(?is)\b(?:records|tokens|owners|owner_of|nft_owner|escrow)\s*\.\s*"
    r"(?:remove|take)\s*\("
)
_CURRENT_OWNER_CHECK_RE = re.compile(
    r"(?is)("
    r"\brecords\s*\.\s*get[^\n;]{0,260}\.owner[^\n;]{0,260}"
    r"(?:==|!=)[^\n;]{0,160}(?:caller|sender)|"
    r"\b(?:current_owner|live_owner|record_owner)\b[^;{}]{0,220}"
    r"(?:==|!=)[^;{}]{0,160}(?:caller|sender)|"
    r"\bowner_of\s*\([^;{}]{0,220}\)\s*(?:==|!=)[^;{}]{0,160}"
    r"(?:caller|sender)|"
    r"\b(?:ensure|require|assert|assert_eq|ensure_eq)\s*!?\s*\([^;{}]{0,420}"
    r"(?:current_owner|live_owner|record_owner|owner_of|\.owner)"
    r"[^;{}]{0,420}(?:caller|sender)"
    r")"
)


def _line_for_offset(base_line: int, text: str, offset: int) -> int:
    return base_line + text[:offset].count("\n")


def _first_asset_mutation_after(body_text: str, start: int) -> re.Match[str] | None:
    return _ASSET_OR_OWNER_MUTATION_RE.search(body_text, pos=start)


def _has_pre_callback_guard(region: str) -> bool:
    return bool(_OWNER_OR_STATE_GUARD_RE.search(region))


def _safe_wrapper_missing_receiver_callback(name: str, body_text: str, fn_text: str) -> bool:
    if not _SAFE_WRAPPER_NAME_RE.match(name):
        return False
    if not _RECEIVER_TARGET_RE.search(fn_text):
        return False
    if not _INTERNAL_ERC721_MUTATION_RE.search(body_text):
        return False
    return not _RECEIVER_CALLBACK_RE.search(body_text)


def _module_has_stale_transfer_owner_map(source_text: str) -> bool:
    if not _SECONDARY_OWNER_MAP_RE.search(source_text):
        return False
    for fn_match in re.finditer(
        r"(?is)\bfn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)"
        r"\s*(?:->[^\{]+)?\{",
        source_text,
    ):
        name = fn_match.group("name")
        if not _STALE_TRANSFER_FN_RE.search(name):
            continue
        body = _extract_body_from_open_brace(source_text, fn_match.end() - 1)
        if not body:
            continue
        if not _OWNER_FIELD_SET_RE.search(body):
            continue
        if _SECONDARY_OWNER_UPDATE_RE.search(body):
            continue
        return True
    return False


def _extract_body_from_open_brace(text: str, open_idx: int) -> str:
    depth = 0
    start = None
    for idx in range(open_idx, len(text)):
        ch = text[idx]
        if ch == "{":
            depth += 1
            if depth == 1:
                start = idx + 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                return text[start:idx]
    return ""


def _stale_owner_burn_handler(name: str, body_text: str, module_has_stale_transfer: bool) -> bool:
    if not module_has_stale_transfer:
        return False
    if not _BURN_FN_RE.search(name):
        return False
    if not _STALE_OWNER_AUTH_RE.search(body_text):
        return False
    remove = _ASSET_REMOVE_RE.search(body_text)
    if remove is None:
        return False
    before_remove = body_text[: remove.start()]
    return not _CURRENT_OWNER_CHECK_RE.search(before_remove)


def _hit(
    *,
    filepath: str,
    line: int,
    col: int,
    name: str,
    reason: str,
    snippet: str,
) -> dict:
    return {
        "detector_id": DETECTOR_ID,
        "severity": "high",
        "file": filepath,
        "line": line,
        "col": col,
        "fn_name": name,
        "snippet": snippet,
        "message": (
            f"fn `{name}` exposes a callback, receiver, or handler path that "
            f"can release assets or mutate ownership before the relevant "
            f"owner/state invariant is checked or updated: {reason}. "
            f"This is a callback-hook-exploit candidate."
        ),
    }


def run(tree, source: bytes, filepath: str, *, engine=None):  # noqa: ARG001
    hits = []
    module_text = source_nocomment(source)
    module_has_stale_transfer = _module_has_stale_transfer_owner_map(module_text)

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        name = fn_name(fn, source)
        body_text = body_text_nocomment(body, source)
        fn_text = source[fn.start_byte:fn.end_byte].decode("utf-8", errors="replace")
        line, col = line_col(fn)

        if _safe_wrapper_missing_receiver_callback(name, body_text, fn_text):
            hits.append(
                _hit(
                    filepath=filepath,
                    line=line,
                    col=col,
                    name=name,
                    reason="safe ERC721 wrapper mutates token ownership without invoking the receiver callback",
                    snippet=snippet_of(fn, source, 220),
                )
            )
            continue

        if _stale_owner_burn_handler(name, body_text, module_has_stale_transfer):
            hits.append(
                _hit(
                    filepath=filepath,
                    line=line,
                    col=col,
                    name=name,
                    reason="burn handler trusts a secondary owner map after transfer can leave that map stale",
                    snippet=snippet_of(fn, source, 220),
                )
            )
            continue

        body_line, _ = line_col(body)
        for callback in _CALLBACK_SURFACE_RE.finditer(body_text):
            mutation = _first_asset_mutation_after(body_text, callback.end())
            if mutation is None:
                continue
            if _has_pre_callback_guard(body_text[: callback.start()]):
                continue
            callback_line = _line_for_offset(body_line, body_text, callback.start())
            mutation_line = _line_for_offset(body_line, body_text, mutation.start())
            hits.append(
                _hit(
                    filepath=filepath,
                    line=callback_line,
                    col=0,
                    name=name,
                    reason=(
                        f"callback/hook runs at line {callback_line} before asset "
                        f"or ownership state is finalized at line {mutation_line}"
                    ),
                    snippet=snippet_of(fn, source, 220),
                )
            )
            break

    return hits
