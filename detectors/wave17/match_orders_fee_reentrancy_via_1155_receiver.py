"""
match-orders-fee-reentrancy-via-1155-receiver

Fixture-smoke/source-shape detector for the Polymarket-style fee accounting
shape: a match/fill routine reads this contract's ERC-1155 balance, transfers
ERC-1155 fees to a receiver that can run onERC1155Received, and then updates
fee/order accounting without a reentrancy guard.

Submission posture: NOT_SUBMIT_READY. This is intentionally narrow and backed
only by the checked-in fixture pair.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


_FUNCTION_NAME_RE = re.compile(
    r"(?i)^(?:_?match(?:Orders|BuyOrders|SellOrders)|_?fillMaker|_?settleMaker)$"
)
_MATCH_CONTEXT_RE = re.compile(
    r"(?i)\b(?:matchOrders|matchBuyOrders|matchSellOrders|conditionalTokens|CTF|IERC1155|ERC1155)\b"
)
_SELF_BALANCE_RE = re.compile(
    r"(?is)(?:"
    r"\bbalanceOf\s*\(\s*address\s*\(\s*this\s*\)"
    r"|"
    r"\bbalanceOf\s*\([^;,\)]*,\s*[^;\)]*address\s*\(\s*this\s*\)"
    r"|"
    r"\b_getBalance\s*\("
    r")"
)
_ERC1155_RECEIVER_TRANSFER_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:safeTransferFrom|safeBatchTransferFrom)\s*\(\s*address\s*\(\s*this\s*\)"
    r"|"
    r"\b_transfer\s*\(\s*address\s*\(\s*this\s*\)\s*,\s*(?:getFeeReceiver\s*\(|feeReceiver\b)"
    r")"
)
_POST_TRANSFER_MUTATION_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:batchedExchangeFees|exchangeFees|feeBalance|lastFeeBalance)\s*(?:=|\+=|-=)"
    r"|"
    r"\b(?:orderStatus|filled|fills|positions|fees)\s*\[[^\]]+\]\s*(?:=|\+=|-=)"
    r"|"
    r"\b(?:_setOrderStatus|_recordFill|_updateFee|_settleFee)\s*\("
    r")"
)
_REENTRANCY_GUARD_RE = re.compile(
    r"(?i)\b(?:nonReentrant|ReentrancyGuard|noReentrant|noReentry|_lockReentrancy)\b"
    r"|\b_status\s*=\s*\d"
    r"|\b_locked\s*=\s*true"
)


def _source(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


def _has_guard(function) -> bool:
    for modifier in getattr(function, "modifiers", []) or []:
        if _REENTRANCY_GUARD_RE.search(getattr(modifier, "name", "") or ""):
            return True
    return bool(_REENTRANCY_GUARD_RE.search(_source(function)))


def _has_ordered_fee_reentrancy_shape(src: str) -> bool:
    balance_match = _SELF_BALANCE_RE.search(src)
    if not balance_match:
        return False

    transfer_match = _ERC1155_RECEIVER_TRANSFER_RE.search(src, balance_match.end())
    if not transfer_match:
        return False

    return bool(_POST_TRANSFER_MUTATION_RE.search(src, transfer_match.end()))


class MatchOrdersFeeReentrancyVia1155Receiver(AbstractDetector):
    ARGUMENT = "match-orders-fee-reentrancy-via-1155-receiver"
    HELP = (
        "Match/fill routine reads this contract's ERC-1155 balance before an "
        "ERC-1155 receiver-callback transfer, then mutates fee/order accounting "
        "after the transfer without a reentrancy guard."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "match-orders-fee-reentrancy-via-1155-receiver.yaml"
    )
    WIKI_TITLE = (
        "matchOrders fee accounting remains mutable after ERC-1155 receiver callback"
    )
    WIKI_DESCRIPTION = (
        "A match/fill routine reads balanceOf(address(this)) or an equivalent "
        "self-balance helper, sends ERC-1155 fees from the exchange to a receiver "
        "that can execute onERC1155Received, and then updates fee/order state. "
        "Without a reentrancy guard, receiver-controlled code can observe or "
        "perturb mid-settlement accounting."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A maker-controlled fee receiver re-enters during safeTransferFrom and "
        "changes order state before the outer matchOrders call records the next "
        "fee/order mutation."
    )
    WIKI_RECOMMENDATION = (
        "Guard match/fill entry points with nonReentrant and complete fee/order "
        "accounting before ERC-1155 receiver-callback transfers."
    )

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            contract_src = _source(contract)
            if not _MATCH_CONTEXT_RE.search(contract_src):
                continue

            for function in contract.functions_and_modifiers_declared:
                if getattr(function, "visibility", "") not in {"external", "public", "internal"}:
                    continue
                if is_leaf_helper(function):
                    continue
                if not _FUNCTION_NAME_RE.search(function.name or ""):
                    continue
                if _has_guard(function):
                    continue

                function_src = _source(function)
                if not _MATCH_CONTEXT_RE.search(function_src):
                    continue
                if not _has_ordered_fee_reentrancy_shape(function_src):
                    continue

                info = [
                    function,
                    (
                        " — match-orders-fee-reentrancy-via-1155-receiver: "
                        "self ERC-1155 balance read precedes receiver-callback "
                        "transfer and post-transfer fee/order mutation without "
                        "a reentrancy guard."
                    ),
                ]
                results.append(self.generate_result(info))
        return results
