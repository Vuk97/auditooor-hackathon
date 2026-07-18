"""
bridge_manager_burn_without_owner_check_fire10.py

Flags Rust bridge or withdrawal manager functions that destructively burn,
remove, consume, unlock, or release an NFT or bridge asset before checking
owner authority or bridge custody context.

Confirmed corpus anchor:
- Solodit #64140 / Code4rena Megapot JackpotBridgeManager
- reference/patterns.dsl.r94_solodit_nft/bridge-manager-burns-nft-without-checking-owner.yaml

This fire10 lift is intentionally narrower than generic bridge proof-domain
detectors. It requires a bridge/withdrawal asset context plus a destructive
asset effect, then verifies that an ownership or custody guard appears before
the first destructive effect in the same public Rust function.
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


_FN_NAME_RE = re.compile(
    r"(?i)("
    r"bridge(_?out|_?burn|_?withdraw|_?release|_?redeem|_?settle)?|"
    r"withdraw(_?bridge|_?nft|_?asset)?|"
    r"release(_?bridge|_?nft|_?asset|_?ticket)?|"
    r"redeem(_?bridge|_?nft|_?asset|_?ticket)?|"
    r"claim(_?bridge|_?nft|_?asset|_?ticket)?|"
    r"finalize(_?withdraw|_?bridge|_?release)?|"
    r"consume(_?bridge|_?nft|_?asset|_?ticket)?|"
    r"unlock(_?bridge|_?nft|_?asset|_?ticket)?"
    r")"
)

_BRIDGE_ASSET_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"bridge|withdraw|withdrawal|cross_chain|crosschain|gateway|portal|"
    r"escrow|custody|vault|ticket|nft|token_id|ticket_id|nft_id|asset_id"
    r")\b"
)

_DESTRUCTIVE_EFFECT_RE = re.compile(
    r"(?is)("
    r"\b(?:burn_nft|burn_ticket|burn_bridge_asset|consume_bridge_asset|"
    r"consume_ticket|remove_bridge_asset|release_bridge_asset|"
    r"unlock_bridge_asset|pay_bridge)\s*\([^;{}]{0,220}\)|"
    r"\b(?:_burn|burn|burn_nft|burn_ticket)\s*\([^;{}]{0,220}"
    r"\b(?:token_id|ticket_id|nft_id|asset_id)\b[^;{}]{0,220}\)|"
    r"\.(?:burn|remove|take|consume)\s*\(\s*&?\s*"
    r"(?:token_id|ticket_id|nft_id|asset_id)\b[^;{}]{0,180}\)|"
    r"\b(?:transfer_from|safe_transfer_from)\s*\([^;{}]{0,320}"
    r"\b(?:bridge|custody|escrow|vault)\b[^;{}]{0,320}\)|"
    r"\b(?:release|unlock|withdraw|payout)\s*\([^;{}]{0,220}"
    r"\b(?:token_id|ticket_id|nft_id|asset_id|amount)\b[^;{}]{0,220}\)|"
    r"\.(?:release|unlock|withdraw|payout|transfer_out)\s*\([^;{}]{0,220}"
    r"\b(?:token_id|ticket_id|nft_id|asset_id|amount)\b[^;{}]{0,220}\)"
    r")"
)

_OWNER_OR_CUSTODY_GUARD_RE = re.compile(
    r"(?is)("
    r"owner_of\s*\([^;{}]{0,140}\b(?:token_id|ticket_id|nft_id|asset_id)\b"
    r"[^;{}]{0,140}\)\s*(?:==|!=)\s*[^;{}]{0,80}"
    r"\b(?:caller|sender|signer|invoker|owner|from|msg_sender)\b|"
    r"\b(?:caller|sender|signer|invoker|owner|from|msg_sender)\b"
    r"[^;{}]{0,80}\s*(?:==|!=)\s*owner_of\s*\(|"
    r"\b(?:assert|assert_eq|ensure|require|require_eq)\s*!?\s*\([^;{}]{0,260}"
    r"\b(?:owner_of|owner|is_owner|approved_or_owner|is_approved_or_owner|"
    r"owns_ticket|owns_nft|require_owner|check_owner|verify_owner)\b|"
    r"\b(?:require_auth|authorize|authenticate)\s*\([^;{}]{0,180}"
    r"\b(?:owner|caller|sender|signer|invoker)\b|"
    r"\b(?:check_owner|verify_owner|ensure_owner|require_owner|"
    r"is_approved_or_owner|approved_or_owner|owns_ticket|owns_nft)\s*\(|"
    r"\b(?:bridge_custody|custody|escrow|vault|locked_assets|locked_nfts|"
    r"bridge_account)\b[^;{}]{0,220}"
    r"(?:contains_key|contains|owner_of|is_custody|is_locked|has|verify|ensure|check)|"
    r"\b(?:ensure_custody|verify_custody|check_custody|require_custody|"
    r"ensure_bridge_custody|verify_bridge_custody|check_bridge_custody)\s*\(|"
    r"\b(?:source_chain|origin_chain|bridge_id|lane_id|route_id|channel_id)"
    r"[^;{}]{0,180}(?:==|!=|ensure|require|assert)"
    r")"
)


def _signature_text(fn, body, source: bytes) -> str:
    return source[fn.start_byte:body.start_byte].decode("utf-8", errors="replace")


def _first_destructive_effect(body_text: str) -> re.Match[str] | None:
    return _DESTRUCTIVE_EFFECT_RE.search(body_text)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if not is_pub(fn, source):
            continue

        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        signature = _signature_text(fn, body, source)
        body_nc = body_text_nocomment(body, source)
        fn_text = f"{signature}\n{body_nc}"
        if not _BRIDGE_ASSET_CONTEXT_RE.search(fn_text):
            continue

        destructive = _first_destructive_effect(body_nc)
        if destructive is None:
            continue

        prefix = body_nc[: destructive.start()]
        if _OWNER_OR_CUSTODY_GUARD_RE.search(prefix):
            continue

        line, col = line_col(fn)
        hits.append(
            {
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"pub fn `{name}` performs a destructive bridge asset "
                    f"effect before any owner or bridge-custody guard. "
                    f"An attacker-controlled token, ticket, NFT, or asset id "
                    f"can be burned, removed, consumed, or released without "
                    f"proving owner authority or bridge custody context "
                    f"(bridge-manager-burn-without-owner-check-fire10; "
                    f"Solodit #64140)."
                ),
            }
        )

    return hits
