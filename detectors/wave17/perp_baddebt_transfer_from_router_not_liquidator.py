"""
Fixture-smoke detector for perp-baddebt-transfer-from-router-not-liquidator.

This row remains NOT_SUBMIT_READY. It proves only the owned liquidation shape
where a router/core perp liquidation path pulls bad-debt repayment from
`msg.sender` even though the architecture names imply `msg.sender` is a market
or router contract rather than the real liquidator.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract  # noqa: E402

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


def _source_of(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


class PerpBaddebtTransferFromRouterNotLiquidator(AbstractDetector):
    ARGUMENT = "perp-baddebt-transfer-from-router-not-liquidator"
    HELP = (
        "Perp liquidation shortfall is pulled with "
        "`safeTransferFrom(msg.sender, ...)` in a router/core architecture, so "
        "bad-debt liquidations can revert against the router instead of the "
        "real liquidator."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "perp-baddebt-transfer-from-router-not-liquidator.yaml"
    )
    WIKI_TITLE = "Liquidation shortfall pulled from msg.sender (router) instead of the liquidator"
    WIKI_DESCRIPTION = (
        "Fixture-smoke/source-shape proof only. The detector flags only the "
        "owned liquidation shape where a perp pool/core path handles negative "
        "remaining margin or shortfall accounting and then executes "
        "`safeTransferFrom(msg.sender, address(this), ...)` without using a "
        "forwarded liquidator address. NOT_SUBMIT_READY."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A liquidator calls a market/router contract, which forwards into a "
        "pool liquidation path. The pool closes the vault, computes negative "
        "remaining margin, and tries to collect bad debt via "
        "`safeTransferFrom(msg.sender, address(this), shortfall)`. Because "
        "`msg.sender` is the router contract, the transfer reverts and the "
        "under-water vault cannot be liquidated."
    )
    WIKI_RECOMMENDATION = (
        "Pass the real liquidator through the router/core boundary and pull "
        "shortfall from that address, or pre-pull the shortfall in the router "
        "before calling the core. Do not promote this row from fixture smoke "
        "alone."
    )

    SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
    COVERAGE_CLAIM = "detector_fixture_smoke_only"
    PROMOTION_ALLOWED = False

    _CONTRACT_GATE_RE = re.compile(
        r"(?:PerpMarket|PredyPool|Clearing|Router|Market|Pool)",
        re.IGNORECASE,
    )
    _ENTRY_NAME_RE = re.compile(
        r"(?:liquidate|_liquidate|executeLiquidation|settleBadDebt|payShortfall)",
        re.IGNORECASE,
    )
    _NEGATIVE_MARGIN_RE = re.compile(
        r"\b(?:remainingMargin|negativeMargin|shortfall|badDebt|insolvency)\b",
        re.IGNORECASE,
    )
    _SHORTFALL_BRANCH_RE = re.compile(
        r"(?:remainingMargin|negativeMargin)\s*<\s*0|"
        r"shortfall\s*>\s*0|badDebt\s*>\s*0",
        re.IGNORECASE,
    )
    _TRANSFER_FROM_MSG_SENDER_RE = re.compile(
        r"(?:safeTransferFrom|transferFrom)\s*\(\s*msg\s*\.\s*sender\s*,\s*"
        r"address\s*\(\s*this\s*\)\s*,",
        re.IGNORECASE | re.DOTALL,
    )
    _LIQUIDATOR_GUARD_RE = re.compile(
        r"(?:safeTransferFrom|transferFrom)\s*\(\s*"
        r"(?:liquidator|keeper|caller|originalSender|actualLiquidator)\s*,",
        re.IGNORECASE | re.DOTALL,
    )

    @classmethod
    def _has_router_baddebt_transfer_shape(cls, function) -> bool:
        if getattr(function, "visibility", "") not in {"external", "public", "internal"}:
            return False
        if is_leaf_helper(function):
            return False

        name = getattr(function, "name", "") or ""
        if not cls._ENTRY_NAME_RE.search(name):
            return False

        source = _source_of(function)
        if not source:
            return False
        if not cls._NEGATIVE_MARGIN_RE.search(source):
            return False
        if not cls._SHORTFALL_BRANCH_RE.search(source):
            return False
        if not cls._TRANSFER_FROM_MSG_SENDER_RE.search(source):
            return False
        if cls._LIQUIDATOR_GUARD_RE.search(source):
            return False
        return True

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue

            contract_source = _source_of(contract)
            if not contract_source:
                continue
            if not self._CONTRACT_GATE_RE.search(contract_source):
                continue

            for function in contract.functions_and_modifiers_declared:
                if not self._has_router_baddebt_transfer_shape(function):
                    continue
                info = [
                    function,
                    " -- perp-baddebt-transfer-from-router-not-liquidator: "
                    "liquidation shortfall is pulled from `msg.sender` across "
                    "a router/core shape. NOT_SUBMIT_READY: fixture-smoke/"
                    "source-shape proof only.",
                ]
                results.append(self.generate_result(info))
        return results
