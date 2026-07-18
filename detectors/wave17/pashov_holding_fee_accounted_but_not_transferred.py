"""
pashov-holding-fee-accounted-but-not-transferred

Row-local fixture-smoke/source-shape detector for a narrow fee-accounting
discrepancy: code caps the vault transfer to available collateral but still
increments realized fee accounting by the uncapped holding-fee amount.

Submission posture: NOT_SUBMIT_READY. This detector is intentionally scoped to
the owned fixture pair and should not be treated as corpus-backed exploit proof.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


_FUNCTION_NAME_RE = re.compile(
    r"(?i)^(?:realizeHoldingFeesOnOpenTrade|realizeHoldingFee|accrueBorrowingFee|"
    r"chargeHoldingFee|applyFundingFee)$"
)
_CONTEXT_RE = re.compile(
    r"(?is)\b(?:holdingFeesCollateral|holdingFee|borrowingFee|fundingFee|"
    r"availableCollateralInDiamond|availableCollateral|realizedTradingFeesCollateral|"
    r"realizedFees)\b"
)
_CAPPED_BRANCH_RE = re.compile(
    r"(?is)\b(?:holdingFeesCollateral|holdingFee|borrowingFee|fundingFee|fees)\b"
    r"\s*>\s*\b(?:availableCollateralInDiamond|availableCollateral)\b"
)
_CAPPED_ASSIGN_RE = re.compile(
    r"(?is)\b(?:amountSentToVault|actualTransferred|sentToVault)\b\s*=\s*"
    r"\b(?:availableCollateralInDiamond|availableCollateral)\b"
)
_TRANSFER_RE = re.compile(
    r"(?is)\b(?:sendToVault|transferToVault|_sendToVault|depositFeeToVault)\s*"
    r"\(\s*(?:amountSentToVault|actualTransferred|sentToVault)\b"
)
_UNCAPPED_ACCUM_RE = re.compile(
    r"(?is)\b(?:realizedTradingFeesCollateral|realizedFees|realizedBorrowingFees"
    r"Collateral|realizedFundingFeesCollateral)\b\s*\+=\s*"
    r"\b(?:holdingFeesCollateral|holdingFee|borrowingFee|fundingFee|fees)\b"
)
_CAPPED_ACCUM_RE = re.compile(
    r"(?is)\b(?:realizedTradingFeesCollateral|realizedFees|realizedBorrowingFees"
    r"Collateral|realizedFundingFeesCollateral)\b\s*\+=\s*"
    r"\b(?:amountSentToVault|actualTransferred|sentToVault)\b"
)


def _source(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


def _has_capped_transfer_but_uncapped_accounting(src: str) -> bool:
    branch_match = _CAPPED_BRANCH_RE.search(src)
    if not branch_match:
        return False

    capped_assign = _CAPPED_ASSIGN_RE.search(src, branch_match.end())
    if not capped_assign:
        return False

    transfer_match = _TRANSFER_RE.search(src, capped_assign.end())
    if not transfer_match:
        return False

    uncapped_accum = _UNCAPPED_ACCUM_RE.search(src, transfer_match.end())
    if not uncapped_accum:
        return False

    return not _CAPPED_ACCUM_RE.search(src)


class PashovHoldingFeeAccountedButNotTransferred(AbstractDetector):
    ARGUMENT = "pashov-holding-fee-accounted-but-not-transferred"
    HELP = (
        "NOT_SUBMIT_READY fixture-smoke/source-shape proof only: flags a narrow "
        "fee path where the vault transfer is capped to available collateral but "
        "realized fee accounting is still incremented by the uncapped fee amount."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "pashov-holding-fee-accounted-but-not-transferred.yaml"
    )
    WIKI_TITLE = (
        "Holding-fee transfer is capped to available collateral but realized fees "
        "still add the uncapped amount"
    )
    WIKI_DESCRIPTION = (
        "Fixture-smoke/source-shape proof only: this detector looks for the direct "
        "Solidity shape where a fee routine caps `amountSentToVault` to "
        "`availableCollateral(InDiamond)`, transfers that capped amount, and then "
        "increments realized fee accounting with the uncapped holding/borrowing/"
        "funding fee variable. NOT_SUBMIT_READY."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A trade accrues 1,200 USDC of holding fees while only 300 USDC of "
        "available collateral remains. The fee path sets `amountSentToVault = "
        "availableCollateralInDiamond`, transfers 300 to the vault, and then "
        "executes `realizedTradingFeesCollateral += holdingFeesCollateral`. The "
        "protocol books 1,200 of realized revenue while only 300 moved."
    )
    WIKI_RECOMMENDATION = (
        "Use the same capped variable for both transfer and realized-fee "
        "accounting, and track any shortfall separately if needed. Keep this row "
        "NOT_SUBMIT_READY until evidence expands beyond the owned fixture pair."
    )

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            contract_src = _source(contract)
            if not _CONTEXT_RE.search(contract_src):
                continue

            for function in contract.functions_and_modifiers_declared:
                if getattr(function, "visibility", "") not in {"external", "public", "internal"}:
                    continue
                if is_leaf_helper(function):
                    continue
                if not _FUNCTION_NAME_RE.search(function.name or ""):
                    continue

                function_src = _source(function)
                if not _CONTEXT_RE.search(function_src):
                    continue
                if not _has_capped_transfer_but_uncapped_accounting(function_src):
                    continue

                info = [
                    function,
                    (
                        " — pashov-holding-fee-accounted-but-not-transferred: "
                        "capped vault transfer is followed by uncapped realized "
                        "fee accounting."
                    ),
                ]
                results.append(self.generate_result(info))
        return results
