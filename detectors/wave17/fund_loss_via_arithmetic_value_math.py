"""
fund-loss-via-arithmetic-value-math - generated from reference/patterns.dsl/fund-loss-via-arithmetic-value-math.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fund-loss-via-arithmetic-value-math.yaml
Source: capability-lift-p1-02-fund-loss-via-arithmetic
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FundLossViaArithmeticValueMath(AbstractDetector):
    ARGUMENT = "fund-loss-via-arithmetic-value-math"
    HELP = "Value conversion, share/asset exchange, debt/collateral math, decimal scaling, stale rate snapshots, fee math, liquidation math, or withdrawal queue accounting can round, truncate, clamp, or scale a returned or transferred value incorrectly, producing non-self fund loss."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fund-loss-via-arithmetic-value-math.yaml"
    WIKI_TITLE = "Arithmetic value math can misprice fund movement"
    WIKI_DESCRIPTION = "Deposit, redeem, liquidation, claim, payout, and withdrawal queue paths convert between assets, shares, debt, collateral, fees, and rates. If the conversion divides before multiplying, hardcodes decimal scale, reads linked rates from stale snapshots, or consumes a clamped value without validating units, the returned, transferred, minted, burned, or accounted amount can be zero, too low, too high, "
    WIKI_EXPLOIT_SCENARIO = "A vault records `queuedAssets = shares / totalSupply() * totalAssets()` when a withdrawal is requested, then burns shares and later settles the queued value. Dust shares can queue zero assets, while stale rate or decimal-scale variants can underpay or overpay the user or protocol. Similar arithmetic appears in liquidation reward and collateral-seizure paths."
    WIKI_RECOMMENDATION = "Use full-precision multiplication before division, typed fixed-point helpers, dynamic token decimals, explicit rate accrual before pricing, and positive-result or bounded-delta guards before any transfer, mint, burn, queue, or accounting consumption."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(asset|share|vault|decimal|rate|borrow|supply|collateral|debt|liquidat|fee|withdraw|redeem|claim|queue|payout|totalAssets|totalSupply|price|scale|precision|exchangeRate)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(deposit|mint|withdraw|redeem|claim|settle|payout|liquidat|borrow|repay|request|queue|process|finalize|convert|preview|price|quote|rate|getSpread|cashout|allocate)'}, {'function.body_contains_regex': '(?is)(assets|shares|amount|amountOut|payout|proceeds|collateral|repay|debt|value|credit|fee|rate|price|exchangeRate|borrowRate|supplyRate|queued|claimable|withdrawal)'}, {'function.body_contains_regex': '(?is)(\\b(?:assets|shares|amountOut|amount|payout|proceeds|collateral|repay|debt|value|credit|fee|cashoutShares|tokensOut|credited|queuedAssets|borrow|supply|spread)\\s*=\\s*[^;]{0,180}/\\s*(?:totalAssets\\s*\\(\\s*\\)|totalSupply\\s*\\(\\s*\\)|[A-Za-z_][A-Za-z0-9_]*(?:Supply|Assets|Shares|Balance|Debt|Collateral|Rate|Price|Scale|SCALE|Precision|PRECISION|Factor|FACTOR|Denominator|DENOMINATOR)|1e\\d{1,2}|10\\s*\\*\\*\\s*\\d{1,2})(?:\\s*(?:\\*|\\+|-)|\\s*;)|\\b(?:assets|shares|amountOut|amount|payout|proceeds|collateral|repay|debt|value|credit|fee|cashoutShares|tokensOut|credited|queuedAssets)\\s*=\\s*[^;]{0,180}\\*\\s*[^;]{0,80}/\\s*(?:1e\\d{1,2}|10\\s*\\*\\*\\s*\\d{1,2}|[A-Za-z_][A-Za-z0-9_]*(?:Scale|SCALE|Precision|PRECISION|Denominator|DENOMINATOR))|(?:borrowRate|getBorrowRate)[\\s\\S]{0,240}(?:supplyRate|getSupplyRate|exchangeRate)|(?:supplyRate|getSupplyRate|exchangeRate)[\\s\\S]{0,240}(?:borrowRate|getBorrowRate)|(?:queued|claimable|withdrawal)[\\s\\S]{0,200}(?:rate|price|share|asset)|(?:min|max|clamp)[\\s\\S]{0,160}(?:fee|amount|assets|shares))'}, {'function.body_not_contains_regex': '(?is)(mulDiv|FullMath|FixedPointMathLib|Rounding\\.(?:Up|Ceil)|ceilDiv|\\.decimals\\s*\\(|IERC20Metadata|tokenDecimals|assetDecimals|normalizeDecimals|scaleBy|accrueInterest\\s*\\(|_accrueInterest\\s*\\(|require\\s*\\([^;]*(?:assets|shares|amountOut|amount|payout|proceeds|collateral|repay|debt|value|credit|fee|cashoutShares|tokensOut|credited|queuedAssets)\\s*(?:>|>=|!=)\\s*0|ZeroAssets|ZeroShares|ZeroAmount|underlyingHeld\\s*>=|idleBalance\\s*>=)'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture|harness)\\b'}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" - fund-loss-via-arithmetic-value-math: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
