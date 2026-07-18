"""
fund-loss-value-math-state-scale-mismatch - custom detector.

Source rows inspected:
- ec-borrow-supply-rate-snapshot-mismatch
- fee-redirect-user-controlled-sink
- fund-loss-via-arithmetic-value-math
"""

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract  # noqa: E402

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


_ENTRY_NAME_RE = re.compile(
    r"(deposit|mint|withdraw|redeem|claim|settle|payout|liquidat|borrow|repay|request|"
    r"queue|process|finalize|convert|preview|price|quote|rate|spread|collect|fee)",
    re.IGNORECASE,
)
_ECON_CONTRACT_RE = re.compile(
    r"(asset|share|vault|rate|borrow|supply|collateral|debt|fee|withdraw|redeem|claim|"
    r"payout|price|scale|precision|exchangeRate|treasury|feeRecipient|feeCollector)",
    re.IGNORECASE,
)
_ACCRUAL_RE = re.compile(r"\b_?accrue(?:Interest)?\s*\(", re.IGNORECASE)
_FULL_PRECISION_OR_POSITIVE_RE = re.compile(
    r"(mulDiv|FullMath|FixedPointMathLib|ceilDiv|Rounding\.(?:Up|Ceil)|"
    r"require\s*\([^;]*(?:assets|shares|amount|amountOut|payout|feeAmount|tokensOut|value)"
    r"\s*(?:>|>=|!=)\s*0|ZeroAssets|ZeroShares|ZeroAmount|ZeroPayout|ZeroFee)",
    re.IGNORECASE | re.DOTALL,
)
_AUTH_OR_CONFIGURED_SINK_RE = re.compile(
    r"(onlyOwner|onlyRole|onlyAdmin|requiresAuth|auth|AccessControl|"
    r"require\s*\([^;]*(?:msg\.sender|_msgSender\s*\(\s*\))\s*==\s*"
    r"(?:owner|admin|keeper|treasury|feeCollector|feeRecipient)|"
    r"(?:safeTransfer|transfer|sendValue)\s*\(\s*"
    r"(?:treasury|feeCollector|protocolTreasury|feeSink|configuredFeeRecipient)\s*,)",
    re.IGNORECASE | re.DOTALL,
)
_RATE_SNAPSHOT_RE = re.compile(
    r"(?:borrowRate|getBorrowRate)[\s\S]{0,320}(?:supplyRate|getSupplyRate|exchangeRate)|"
    r"(?:supplyRate|getSupplyRate|exchangeRate)[\s\S]{0,320}(?:borrowRate|getBorrowRate)",
    re.IGNORECASE,
)
_DIRECT_RATE_HELPER_RE = re.compile(r"^_?get(?:Borrow|Supply)Rate$", re.IGNORECASE)
_STATE_SCALE_ASSIGN_RE = re.compile(
    r"\b(?:assets|shares|amountOut|amount|payout|proceeds|collateral|repay|debt|value|"
    r"credit|fee|tokensOut|credited|queuedAssets)\s*=\s*[^;]{0,220}"
    r"(?:/\s*(?:totalAssets\s*\(\s*\)|totalSupply\s*\(\s*\)|"
    r"[A-Za-z_][A-Za-z0-9_]*(?:Supply|Assets|Shares|Balance|Debt|Collateral|Rate|Price|"
    r"Scale|SCALE|Precision|PRECISION|Factor|FACTOR|Denominator|DENOMINATOR)|"
    r"1e\d{1,2}|10\s*\*\*\s*\d{1,2})|"
    r"\*\s*[^;]{0,100}/\s*(?:1e\d{1,2}|10\s*\*\*\s*\d{1,2}|"
    r"[A-Za-z_][A-Za-z0-9_]*(?:Scale|SCALE|Precision|PRECISION|Denominator|DENOMINATOR)))",
    re.IGNORECASE | re.DOTALL,
)
_VALUE_MOVE_RE = re.compile(
    r"(?:safeTransfer|transfer|sendValue|send|mint|burn|unreserve|reserve|pay)\w*"
    r"\s*\([^;]*(?:assets|shares|amountOut|amount|payout|proceeds|collateral|repay|debt|"
    r"value|credit|fee|tokensOut|credited|queuedAssets)\b",
    re.IGNORECASE | re.DOTALL,
)
_FEE_STATE_RE = re.compile(
    r"\b(?:feeAmount|protocolFee|platformFee|serviceFee|treasuryFee|royaltyFee|keeperFee|fee)"
    r"\s*=\s*(?:accruedFee|pendingFee|protocolFees|platformFees|royaltyFees|keeperFees)"
    r"(?:\s*\[[^\]]+\])?",
    re.IGNORECASE | re.DOTALL,
)
_CALLER_FEE_TRANSFER_RE = re.compile(
    r"(?:safeTransfer|transfer|sendValue)\s*\(\s*"
    r"(?:msg\.sender|_msgSender\s*\(\s*\)|caller|recipient|receiver|to|beneficiary|"
    r"feeRecipient|feeReceiver)\s*,\s*"
    r"(?:feeAmount|protocolFee|platformFee|serviceFee|treasuryFee|royaltyFee|keeperFee|fee)"
    r"\b",
    re.IGNORECASE | re.DOTALL,
)


def _source(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


def _contract_source(contract) -> str:
    parts = [_source(contract), getattr(contract, "name", "") or ""]
    for function in getattr(contract, "functions_and_modifiers_declared", []) or []:
        parts.append(getattr(function, "name", "") or "")
        parts.append(_source(function))
    return "\n".join(part for part in parts if part)


def _matches_stale_rate_snapshot(source: str) -> bool:
    if _ACCRUAL_RE.search(source):
        return False
    return bool(_RATE_SNAPSHOT_RE.search(source))


def _matches_state_scaled_value_move(source: str) -> bool:
    if _FULL_PRECISION_OR_POSITIVE_RE.search(source):
        return False
    return bool(_STATE_SCALE_ASSIGN_RE.search(source) and _VALUE_MOVE_RE.search(source))


def _matches_fee_state_to_user_sink(source: str) -> bool:
    if _AUTH_OR_CONFIGURED_SINK_RE.search(source):
        return False
    return bool(_FEE_STATE_RE.search(source) and _CALLER_FEE_TRANSFER_RE.search(source))


class FundLossValueMathStateScaleMismatch(AbstractDetector):
    ARGUMENT = "fund-loss-value-math-state-scale-mismatch"
    HELP = (
        "Flags public economic paths that consume stale rate snapshots, lossy state-scaled "
        "value math, or protocol fee state into a caller-controlled sink without the matching "
        "accrual, full-precision, positive-result, or configured-sink guard."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fund-loss-via-arithmetic-value-math.yaml"
    WIKI_TITLE = "State value math consumed with mismatched scale or sink"
    WIKI_DESCRIPTION = (
        "A public value-moving or value-pricing path reads protocol state such as rates, "
        "shares, totals, fees, or exchange rates and consumes it under a different unit or "
        "recipient assumption than the state was recorded under."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A vault or lending path reads stale borrow and supply rates, converts shares with "
        "division before a transfer, or transfers protocol fee state to a caller-supplied "
        "recipient. The caller receives or redirects value that should have been priced or "
        "routed under protocol state."
    )
    WIKI_RECOMMENDATION = (
        "Refresh rates before pricing, use full-precision value conversion with positive "
        "result checks, and route protocol fee state only to configured sinks or authorized "
        "operators."
    )

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if not _ECON_CONTRACT_RE.search(_contract_source(contract)):
                continue

            for function in getattr(contract, "functions_and_modifiers_declared", []) or []:
                visibility = getattr(function, "visibility", "") or ""
                if visibility not in ("external", "public"):
                    continue
                if not _ENTRY_NAME_RE.search(function.name or ""):
                    continue

                source = _source(function)
                branch = ""
                if _matches_stale_rate_snapshot(source) and not _DIRECT_RATE_HELPER_RE.match(function.name or ""):
                    branch = "stale rate snapshot"
                elif _matches_state_scaled_value_move(source):
                    branch = "state scaled value move"
                elif _matches_fee_state_to_user_sink(source):
                    branch = "fee state to user sink"

                if not branch:
                    continue

                info = [
                    function,
                    f" - fund-loss-value-math-state-scale-mismatch: {branch}.",
                ]
                results.append(self.generate_result(info))

        return results
