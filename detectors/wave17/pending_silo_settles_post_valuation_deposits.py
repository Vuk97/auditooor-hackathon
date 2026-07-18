"""
pending-silo-settles-post-valuation-deposits

Fixture-smoke/source-shape detector for the owned async-vault row where a
settlement entrypoint drains the full pending silo balance after valuation
without a visible valuation-timestamp or request-epoch cutoff.

Submission posture: NOT_SUBMIT_READY. This detector is intentionally narrow and
backed only by the checked-in fixture pair.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


_CONTEXT_RE = re.compile(
    r"(?is)\b(?:pendingSilo|valuationTimestamp|lastValuationTime|"
    r"requestDeposit|settleDeposit|currentEpoch)\b"
)
_FUNCTION_NAME_RE = re.compile(
    r"(?i)^(?:settleDeposit|settleDeposits|finalizeEpoch|_settleDeposit|_settle)$"
)
_VALUATION_CONTEXT_RE = re.compile(
    r"(?is)\b(?:sharePrice|pricePerShare|valuationTimestamp|lastValuationTime|currentEpoch)\b"
)
_FULL_BALANCE_READ_RE = re.compile(
    r"(?is)\b(?:uint256\s+\w+\s*=\s*)?"
    r"(?:\w+\s*\.\s*)?balanceOf\s*\(\s*(?:address\s*\(\s*)?pendingSilo\s*\)?\s*\)"
)
_DRAIN_CALL_RE = re.compile(
    r"(?is)\b(?:transferFrom|safeTransferFrom|releaseToVault|release|drainToVault)\s*\("
)
_VALUATION_FILTER_RE = re.compile(
    r"(?is)\b(?:valuationTimestamp|lastValuationTime|requestTime|requestTimestamp|"
    r"requestEpoch|requestId|assetsAtValuation|pendingAtValuation|"
    r"pendingAssetsAtValuation|settleableAssets)\b[^;{}]{0,120}"
    r"(?:<=|<|==|!=|>=|>|at valuation|atValuation)"
)
_VALUATION_FILTER_CALL_RE = re.compile(
    r"(?is)\b(?:_filterPostValuationDeposits|_settleOnlyValuedDeposits|"
    r"_assetsAtValuation|_pendingAtValuation|_requestQuotedBeforeValuation)\s*\("
)


def _source(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


class PendingSiloSettlesPostValuationDeposits(AbstractDetector):
    ARGUMENT = "pending-silo-settles-post-valuation-deposits"
    HELP = (
        "Settlement drains the full pending silo balance after valuation "
        "without a visible valuation-timestamp or request-epoch cutoff."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "pending-silo-settles-post-valuation-deposits.yaml"
    )
    WIKI_TITLE = (
        "Async vault settlement drains post-valuation deposits at the stale epoch price"
    )
    WIKI_DESCRIPTION = (
        "Fixture-smoke/source-shape proof only: this row flags the owned async "
        "settlement shape where `settleDeposit`-style code reads the full "
        "pending silo balance and drains it after a valuation exists, but the "
        "settlement body does not visibly restrict assets to deposits quoted at "
        "or before that valuation. NOT_SUBMIT_READY."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "An async vault records a valuation for epoch N, then later executes "
        "`settleDeposit()`. The function reads `asset.balanceOf(pendingSilo)` "
        "and drains that entire balance into the vault. Deposits that arrived "
        "after the valuation are now absorbed at epoch N's price even though "
        "they should wait for epoch N+1."
    )
    WIKI_RECOMMENDATION = (
        "Track the amount or request set that was eligible at valuation time "
        "and settle only that subset. Re-queue post-valuation deposits into the "
        "next epoch. Do not promote this row from fixture smoke alone."
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
                if getattr(function, "visibility", "") not in {"external", "public"}:
                    continue
                if is_leaf_helper(function):
                    continue
                if not _FUNCTION_NAME_RE.search(function.name or ""):
                    continue

                function_src = _source(function)
                if not function_src:
                    continue
                if not _VALUATION_CONTEXT_RE.search(function_src):
                    continue
                if not _FULL_BALANCE_READ_RE.search(function_src):
                    continue
                if not _DRAIN_CALL_RE.search(function_src):
                    continue
                if _VALUATION_FILTER_RE.search(function_src):
                    continue
                if _VALUATION_FILTER_CALL_RE.search(function_src):
                    continue

                info = [
                    function,
                    (
                        " — pending-silo-settles-post-valuation-deposits: "
                        "settlement drains the full pending silo balance after "
                        "valuation without a visible valuation cutoff. "
                        "NOT_SUBMIT_READY: fixture-smoke/source-shape proof "
                        "only."
                    ),
                ]
                results.append(self.generate_result(info))
        return results
