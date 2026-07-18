"""
reentrancy_royalty_receiver_callback_fire39.py

Rust detector for royalty receiver and NFT receiver callback reentrancy.

Flags public Rust entrypoints that derive royalty, collateral, share, or
configuration state, transfer control to a royalty receiver or NFT receiver
callback, then settle pool, seller, royalty, collateral, or share accounting
from the cached pre-callback state. The detector is scoped away from the
Fire38 packet-open midstate shape by requiring royalty or collateral/share
receiver semantics.

Source refs:
- reports/detector_lift_fire38_20260605/post_priorities_rust.md
- detectors/rust_wave1/reentrancy_packet_open_midstate_fire38.py
- detectors/rust_wave1/royalty_receiver_drains_private_pool_via_malicious_royalty_callback.py
- detectors/rust_wave1/r94_loop_nft_royalty_receiver_external_call_reentrancy.py
- detectors/rust_wave1/r94_loop_onerc721received_reentrancy_collateral_shares_manipulation.py
- reference/patterns.dsl.r94_solodit_nft/royalty-receiver-drains-private-pool-via-malicious-royalty-callback.yaml
- reference/patterns.dsl.r94_solodit_nft/onerc721received-reentrancy-manipulates-collateral-shares.yaml

verification_tier: tier-3-synthetic-taxonomy-anchored
attack_class: reentrancy-cross-contract
context_pack_id: auditooor.vault_context_pack.v1:resume:cbdd9eeb5255863c
context_pack_hash: cbdd9eeb5255863c4870d83e88642e9c4a3eef8e7cdfb8b5fb9a8ee7ac5a25d8
MCP receipt: .auditooor/memory_context_receipt.json
NOT_SUBMIT_READY
R40/R76/R80 caveat: detector hits are source-review candidates only, not proof.
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


DETECTOR_ID = "rust_wave1.reentrancy_royalty_receiver_callback_fire39"

_ROYALTY_CONTEXT_RE = re.compile(
    r"(?i)"
    r"(royalty_info|royaltyInfo|get_royalty_info|royalty_of|erc2981|"
    r"royalty_receiver|royaltyReceiver|receive_royalty|royalty_amount|"
    r"royalty_bps|royalty_fee)"
)

_RECEIVER_CONTEXT_RE = re.compile(
    r"(?i)"
    r"(on_erc721_received|onERC721Received|on_erc1155_received|"
    r"onERC1155Received|collateral_config|collateralConfig|"
    r"collateral_shares|collateralShares|token_config|tokenConfig|"
    r"share_config|shares|collateral|loan_config|position_config)"
)

_PACKET_ONLY_CONTEXT_RE = re.compile(
    r"(?i)"
    r"(open_packet|packet_open|packet_id|packet_state|booster_pack|"
    r"card_snapshot|mark_packet_opened|commit_packet_open)"
)

_EXTERNAL_BOUNDARY_RE = re.compile(
    r"(?ix)"
    r"(?:"
    r"\b(?:safe_transfer_from|safeTransferFrom|transfer_from|transferFrom)\s*\(|"
    r"\b(?:invoke_contract|try_invoke_contract|call_contract|invoke_signed|"
    r"program::invoke|program::invoke_signed|invoke)\s*\(|"
    r"\b(?:token::|anchor_spl::token::)[A-Za-z_][A-Za-z0-9_]*\s*\(|"
    r"\b(?=[A-Za-z_][A-Za-z0-9_\.]*"
    r"(?:royalty|receiver|callback|hook|recipient|erc721|erc1155|nft|token))"
    r"[A-Za-z_][A-Za-z0-9_\.]*\s*\.\s*"
    r"(?:call|send|transfer|transfer_from|safe_transfer_from|receive_royalty|"
    r"on_royalty_received|on_erc721_received|on_erc1155_received|"
    r"onERC721Received|onERC1155Received|callback|hook|execute|invoke|"
    r"notify|receive_[A-Za-z0-9_]*)\s*\("
    r")"
)

_GUARD_OR_BIND_RE = re.compile(
    r"(?is)"
    r"(?:"
    r"#\[\s*non_reentrant\s*\]|non_reentrant|nonReentrant|ReentrancyGuard|"
    r"reentrancy_guard|reentrancy_lock|callback_guard|callback_lock|"
    r"royalty_lock|collateral_lock|share_lock|cpi_guard|guard\.enter|"
    r"enter_guard|enter_reentrancy|lock_reentrancy|acquire_reentrancy|"
    r"locked\s*=\s*true|entered\s*=\s*true|in_reentrancy\s*=\s*true|"
    r"assert_royalty_receiver_bound|verify_royalty_receiver|"
    r"verify_royalty_domain|require_known_royalty_receiver|"
    r"require_trusted_royalty_receiver|royalty_domain_bound|"
    r"trusted_royalty_receiver"
    r")"
)

_PRECOMMIT_RE = re.compile(
    r"(?is)"
    r"(?:"
    r"(?:sale|listing|royalty|callback|collateral|share|nft|token|loan|"
    r"position|settlement)_[A-Za-z0-9_]*(?:state|status|phase|lock)"
    r"[\s\S]{0,120}(?:Settling|Processing|Locked|Consumed|Claimed|"
    r"Processed|Finalized|Finalised|Complete)|"
    r"\b(?:mark|set|commit|checkpoint|consume|reserve|finali[sz]e)_"
    r"(?:sale|listing|royalty|collateral|share|nft|token|loan|position)"
    r"\s*\(|"
    r"\b(?:consume_listing|remove_listing|checkpoint_sale|checkpoint_nft|"
    r"consume_once|mark_processed|mark_settling)\s*\(|"
    r"\b(?:listings|pending|pending_sales|pending_nfts|unclaimed|claims)"
    r"\s*\.\s*remove\s*\("
    r")"
)

_POST_RELOAD_RE = re.compile(
    r"(?is)"
    r"(?:"
    r"\b(?:reload|refresh|revalidate|validate_after|post_callback_check|"
    r"after_callback_check|ensure_current|check_current|verify_current)"
    r"\s*\(|"
    r"\blet\s+(?:mut\s+)?(?:fresh|latest|current|updated|"
    r"[A-Za-z_][A-Za-z0-9_]*_after)"
    r"[A-Za-z0-9_]*\s*(?::[^=;]+)?=\s*[^;]{0,220}"
    r"(?:\.get\s*\(|\.load\s*\(|\.borrow\s*\(|load_[A-Za-z0-9_]*\s*\(|"
    r"storage\s*\(\s*\))"
    r")"
)

_ROYALTY_PRE_RE = re.compile(
    r"(?is)"
    r"(?:"
    r"\b(?:let\s+(?:mut\s+)?)?\(?\s*[A-Za-z_][A-Za-z0-9_]*"
    r"(?:royalty|receiver)[A-Za-z0-9_]*[\s,\)]*"
    r"(?:\:[^=;]+)?=\s*[^;]{0,260}"
    r"(?:royalty_info|royaltyInfo|get_royalty_info|royalty_of|erc2981)|"
    r"(?:royalty_info|royaltyInfo|get_royalty_info|royalty_of|erc2981)"
    r"\s*\("
    r")"
)

_COLLATERAL_PRE_RE = re.compile(
    r"(?is)"
    r"(?:"
    r"\b(?:let\s+(?:mut\s+)?)?[A-Za-z_][A-Za-z0-9_]*"
    r"(?:collateral|share|shares|config|position|loan)[A-Za-z0-9_]*"
    r"\s*(?::[^=;]+)?=\s*[^;]{0,260}"
    r"(?:\.get\s*\(|\.load\s*\(|load_[A-Za-z0-9_]*\s*\(|"
    r"storage\s*\(\s*\))|"
    r"\b[A-Za-z_][A-Za-z0-9_\.]*"
    r"(?:collateral|share|shares|config|position|loan)[A-Za-z0-9_\.]*"
    r"\s*(?:=|\+=|-=)|"
    r"\b[A-Za-z_][A-Za-z0-9_\.]*"
    r"(?:collateral|share|shares|config|position|loan)[A-Za-z0-9_\.]*"
    r"\s*\.\s*(?:insert|set|update|save|replace|push)\s*\("
    r")"
)

_POST_ACCOUNTING_RE = re.compile(
    r"(?is)"
    r"(?:"
    r"\b(?:self|state|pool|vault|ledger|market|sale|listing|collateral|"
    r"config|position|loan)[A-Za-z0-9_\.\[\]]*"
    r"(?:royalty|seller|balance|balances|pool|reserve|sale|listing|"
    r"collateral|share|shares|config|position|loan|accounting|status)"
    r"[A-Za-z0-9_\.\[\]]*[\s\S]{0,160}(?:\+=|-=|=)|"
    r"\b(?:self|state|pool|vault|ledger|market)\s*\.\s*"
    r"(?:balances|royalties|royalty_balances|seller_balances|reserves|"
    r"sales|listings|collateral|collateral_configs|collateral_shares|"
    r"token_configs|positions|loans|shares)[\s\S]{0,180}"
    r"(?:\+=|-=|=|\.insert\s*\(|\.set\s*\(|\.update\s*\(|\.save\s*\(|"
    r"\.replace\s*\()|"
    r"\b(?:save_collateral|save_collateral_config|save_position|"
    r"save_loan|settle_sale|complete_sale|finali[sz]e_sale|"
    r"credit_royalty|credit_seller|record_royalty|record_collateral|"
    r"update_collateral_shares|update_shares|commit_collateral|"
    r"commit_royalty|commit_sale)\s*\("
    r")"
)

_ACCOUNTING_FAMILY_RE = re.compile(
    r"(?i)"
    r"(royalty|seller|balance|balances|pool|reserve|sale|listing|"
    r"collateral|share|shares|config|position|loan|accounting|status)"
)


def _line_for_offset(base_line: int, text: str, offset: int) -> int:
    return base_line + text[:offset].count("\n")


def _has_safe_marker_before(header_prefix: str, body_text: str, offset: int) -> bool:
    prefix = header_prefix + "\n" + body_text[:offset]
    return bool(_GUARD_OR_BIND_RE.search(prefix) or _PRECOMMIT_RE.search(prefix))


def _first_post_accounting(region: str):
    for match in _POST_ACCOUNTING_RE.finditer(region):
        context = region[max(0, match.start() - 180):match.end() + 180]
        if not _ACCOUNTING_FAMILY_RE.search(context):
            continue
        if _POST_RELOAD_RE.search(region[:match.start()]):
            return None
        return match
    return None


def _is_packet_only(body_text: str) -> bool:
    if not _PACKET_ONLY_CONTEXT_RE.search(body_text):
        return False
    return not (_ROYALTY_CONTEXT_RE.search(body_text) or _RECEIVER_CONTEXT_RE.search(body_text))


def _kind_for_body(name: str, body_text: str) -> str | None:
    if _ROYALTY_CONTEXT_RE.search(body_text):
        return "royalty receiver"
    if _RECEIVER_CONTEXT_RE.search(name) or _RECEIVER_CONTEXT_RE.search(body_text):
        return "NFT receiver collateral/share"
    return None


def _has_precallback_state(kind: str, prefix: str) -> bool:
    if kind == "royalty receiver":
        return bool(_ROYALTY_PRE_RE.search(prefix))
    return bool(_COLLATERAL_PRE_RE.search(prefix))


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    source_text = source.decode("utf-8", errors="replace")

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if not is_pub(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        body_text = body_text_nocomment(body, source)
        if _is_packet_only(body_text):
            continue

        name = fn_name(fn, source)
        kind = _kind_for_body(name, body_text)
        if kind is None:
            continue

        header_prefix = source_text[max(0, fn.start_byte - 320):fn.start_byte]
        body_line, _ = line_col(body)

        for boundary in _EXTERNAL_BOUNDARY_RE.finditer(body_text):
            prefix = body_text[:boundary.start()]
            if not _has_precallback_state(kind, prefix):
                continue
            if _has_safe_marker_before(header_prefix, body_text, boundary.start()):
                continue

            post_accounting = _first_post_accounting(body_text[boundary.end():])
            if post_accounting is None:
                continue

            call_line = _line_for_offset(body_line, body_text, boundary.start())
            accounting_line = _line_for_offset(
                body_line,
                body_text,
                boundary.end() + post_accounting.start(),
            )

            hits.append(
                {
                    "detector_id": DETECTOR_ID,
                    "severity": "high",
                    "line": call_line,
                    "col": 0,
                    "snippet": snippet_of(fn, source)[:220],
                    "message": (
                        f"fn `{name}` derives {kind} state, transfers control "
                        f"through a receiver callback at line {call_line}, and "
                        f"settles related accounting only at line "
                        f"{accounting_line} without a visible guard, domain "
                        "binding, pre-callback checkpoint, consume-once marker, "
                        "or post-callback reload. NOT_SUBMIT_READY: detector "
                        "hit is a source-review candidate only."
                    ),
                }
            )
            break

    return hits
