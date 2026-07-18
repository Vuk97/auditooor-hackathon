"""
fund-loss-via-arithmetic-conversion-output-zero - generated from reference/patterns.dsl/fund-loss-via-arithmetic-conversion-output-zero.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fund-loss-via-arithmetic-conversion-output-zero.yaml
Source: capability-lift-pillar1-fund-loss-via-arithmetic
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FundLossViaArithmeticConversionOutputZero(AbstractDetector):
    ARGUMENT = "fund-loss-via-arithmetic-conversion-output-zero"
    HELP = "A fund-moving conversion output is computed with lossy division or hardcoded fixed-point scaling, then used in a transfer, mint, burn, or accounting debit without proving the result is positive. Dust inputs or decimal mismatches can transfer funds while minting or paying zero value."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fund-loss-via-arithmetic-conversion-output-zero.yaml"
    WIKI_TITLE = "Fund-loss arithmetic conversion output can round to zero"
    WIKI_DESCRIPTION = "Deposit, redeem, claim, payout, and liquidation paths often convert between assets, shares, debt, and collateral. If the code divides before multiplying, or downscales through a hardcoded fixed-point denominator without reading token decimals, the converted output can truncate to zero. When that zero output is then consumed by a transfer, mint, burn, or accounting debit without a positive-result guard, users can lose funds or protocol accounting can silently misvalue collateral."
    WIKI_EXPLOIT_SCENARIO = "A vault computes `shares = assets / totalAssets() * totalSupply()` and then transfers the user's assets before minting shares. For any dust deposit where `assets < totalAssets()`, `shares` is zero, so the user transfers assets and receives no shares. The same shape appears on redeem paths that burn shares for zero assets, payout paths that downscale non-18-decimal amounts through `/ 1e18`, and claim paths that divide an entitlement before multiplying by a rate."
    WIKI_RECOMMENDATION = "Compute conversions with full precision multiplication before division, preferably via `mulDiv`, use token-specific decimals for scaling, and reject zero-result value movements with `require(output > 0)` or a typed zero-output error."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(vault|share|asset|deposit|withdraw|redeem|claim|payout|collateral|liquidat|rate|price|precision|decimal|totalSupply|totalAssets)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(deposit|mint|withdraw|redeem|claim\\w*|settle\\w*|payout\\w*|liquidate\\w*)$'}, {'function.body_contains_regex': '(?is)\\b(?:assets|shares|amountOut|amount|payout|proceeds|collateral|repay|debt|value|credit)\\s*=\\s*[^;]*(?:/\\s*(?:totalAssets\\s*\\(\\s*\\)|totalSupply\\s*\\(\\s*\\)|[A-Za-z_][A-Za-z0-9_]*(?:Supply|Assets|Shares|Balance|Denominator|DENOMINATOR|Scale|SCALE|Precision|PRECISION|Wad|WAD|Ray|RAY)|1e\\d{1,2}|10\\s*\\*\\*\\s*\\d{1,2})\\s*\\*\\s*[A-Za-z_][A-Za-z0-9_]*(?:Supply|Assets|Shares|Balance|Rate|Price|Factor|FACTOR|Scale|SCALE)?|\\*\\s*[A-Za-z_][A-Za-z0-9_]*\\s*/\\s*(?:1e\\d{1,2}|10\\s*\\*\\*\\s*\\d{1,2}))'}, {'function.body_contains_regex': '(?is)(safeTransferFrom|safeTransfer|transferFrom|transfer\\s*\\(|_mint\\s*\\(|_burn\\s*\\(|claimable[^\\n;]*-=|pending[^\\n;]*-=|maxWithdraw[^\\n;]*-=|total[A-Za-z0-9_]*\\s*(?:\\+=|-=))'}, {'function.body_not_contains_regex': '(?is)(require\\s*\\(\\s*(?:assets|shares|amountOut|amount|payout|proceeds|collateral|repay|debt|value|credit)\\s*(?:>|>=|!=)\\s*0|if\\s*\\(\\s*(?:assets|shares|amountOut|amount|payout|proceeds|collateral|repay|debt|value|credit)\\s*==\\s*0\\s*\\)\\s*(?:revert|return)|ZeroShares|ZeroAssets|ZeroAmount|Rounding\\.(?:Up|Ceil)|mulDiv|FullMath|FixedPointMathLib|\\.decimals\\s*\\(|IERC20Metadata|tokenDecimals|assetDecimals|normalizeDecimals)'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture|harness)\\b'}]

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
                info = [f, f" - fund-loss-via-arithmetic-conversion-output-zero: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
