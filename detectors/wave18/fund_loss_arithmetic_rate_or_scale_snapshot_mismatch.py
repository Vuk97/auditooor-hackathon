"""
fund-loss-arithmetic-rate-or-scale-snapshot-mismatch - generated from reference/patterns.dsl/fund-loss-arithmetic-rate-or-scale-snapshot-mismatch.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fund-loss-arithmetic-rate-or-scale-snapshot-mismatch.yaml
Source: detector-lift-fire5-rwrq-fund-loss-via-arithmetic-9e69bdc71f4e
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FundLossArithmeticRateOrScaleSnapshotMismatch(AbstractDetector):
    ARGUMENT = "fund-loss-arithmetic-rate-or-scale-snapshot-mismatch"
    HELP = "Public economic path reads linked rates without accrual, moves value from lossy state-scale math, or routes protocol fee state to a caller-controlled sink without the corresponding accrual, full-precision, positive-result, or configured-sink guard."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fund-loss-arithmetic-rate-or-scale-snapshot-mismatch.yaml"
    WIKI_TITLE = "Arithmetic rate or scale snapshot mismatch moves funds under stale or wrong state"
    WIKI_DESCRIPTION = "Fund-moving and fund-pricing paths often convert between shares, assets, debt, collateral, rates, fees, and protocol accounting state. If the path reads linked rates before accrual, consumes division-based state-scale math in a value move, or sends protocol fee state to a caller-selected sink, users or the protocol can lose funds through stale pricing or wrong recipient accounting."
    WIKI_EXPLOIT_SCENARIO = "A vault claims queued shares using `assets = shares / exchangeRate * 1e18` and transfers `assets` to the caller. Small claims round to zero or stale exchange-rate units. In a sibling fee path, `feeAmount = accruedFee` is sent to a caller supplied recipient, letting any caller redirect protocol fees."
    WIKI_RECOMMENDATION = "Refresh rates before pricing, use full-precision multiplication before division, reject zero or lossy converted amounts before value movement, and route protocol fee state only to configured sinks or authorized operators."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?is)(asset|share|vault|rate|borrow|supply|collateral|debt|fee|withdraw|redeem|claim|payout|price|scale|precision|exchangeRate|treasury|feeRecipient|feeCollector|accruedFee|pendingFee)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(deposit|mint|withdraw|redeem|claim|settle|payout|liquidat|borrow|repay|request|queue|process|finalize|convert|preview|price|quote|rate|getSpread|collect|fee)'}, {'function.body_contains_regex': '(?is)(?:borrowRate|getBorrowRate)[\\s\\S]{0,320}(?:supplyRate|getSupplyRate|exchangeRate)|(?:supplyRate|getSupplyRate|exchangeRate)[\\s\\S]{0,320}(?:borrowRate|getBorrowRate)|\\b(?:assets|shares|amountOut|amount|payout|proceeds|collateral|repay|debt|value|credit|tokensOut|credited|queuedAssets)\\s*=\\s*[^;]{0,220}(?:/\\s*(?:totalAssets\\s*\\(\\s*\\)|totalSupply\\s*\\(\\s*\\)|[A-Za-z_][A-Za-z0-9_]*(?:Supply|Assets|Shares|Balance|Debt|Collateral|Rate|Price|Scale|SCALE|Precision|PRECISION|Factor|FACTOR|Denominator|DENOMINATOR)|1e\\d{1,2}|10\\s*\\*\\*\\s*\\d{1,2})|\\*\\s*[^;]{0,100}/\\s*(?:1e\\d{1,2}|10\\s*\\*\\*\\s*\\d{1,2}|[A-Za-z_][A-Za-z0-9_]*(?:Scale|SCALE|Precision|PRECISION|Denominator|DENOMINATOR)))[\\s\\S]{0,260}(?:safeTransfer|transfer|sendValue|send|mint|burn|unreserve|reserve|pay)\\w*\\s*\\([^;]*(?:assets|shares|amountOut|amount|payout|proceeds|collateral|repay|debt|value|credit|tokensOut|credited|queuedAssets)\\b|\\b(?:feeAmount|protocolFee|platformFee|serviceFee|treasuryFee|royaltyFee|keeperFee|fee)\\s*=\\s*(?:accruedFee|pendingFee|protocolFees|platformFees|royaltyFees|keeperFees)(?:\\s*\\[[^\\]]+\\])?[\\s\\S]{0,220}(?:safeTransfer|transfer|sendValue)\\s*\\(\\s*(?:msg\\.sender|_msgSender\\s*\\(\\s*\\)|caller|recipient|receiver|to|beneficiary|feeRecipient|feeReceiver)\\s*,\\s*(?:feeAmount|protocolFee|platformFee|serviceFee|treasuryFee|royaltyFee|keeperFee|fee)\\b'}, {'function.body_not_contains_regex': '(?is)(mulDiv|FullMath|FixedPointMathLib|ceilDiv|Rounding\\.(?:Up|Ceil)|\\.decimals\\s*\\(|IERC20Metadata|tokenDecimals|assetDecimals|normalizeDecimals|scaleBy|accrueInterest\\s*\\(|_accrueInterest\\s*\\(|require\\s*\\([^;]*\\b(?:assets|shares|amountOut|amount|payout|proceeds|collateral|repay|debt|value|credit|tokensOut|credited|queuedAssets)\\b\\s*(?:>|>=|!=)\\s*0|ZeroAssets|ZeroShares|ZeroAmount|ZeroPayout|onlyOwner|onlyRole|onlyAdmin|requiresAuth|auth|AccessControl|require\\s*\\([^;]*(?:msg\\.sender|_msgSender\\s*\\(\\s*\\))\\s*==\\s*(?:owner|admin|keeper|treasury|feeCollector|feeRecipient)|(?:safeTransfer|transfer|sendValue)\\s*\\(\\s*(?:treasury|feeCollector|protocolTreasury|feeSink|configuredFeeRecipient)\\s*,)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture|harness)\\b'}]

    _INCLUDE_LEAF_HELPERS = False
    _INVERSE_CEI = False

    def _detect(self):
        results = []
        for c in self.contracts:
            if is_vendored_or_test_contract(c):
                continue
            if not eval_preconditions(c, self._PRECONDITIONS):
                continue
            for f in c.functions_and_modifiers_declared:
                if not self._INCLUDE_LEAF_HELPERS and is_leaf_helper(f):
                    continue
                if not eval_function_match(f, self._MATCH):
                    continue
                info = [f, f" - fund-loss-arithmetic-rate-or-scale-snapshot-mismatch: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
