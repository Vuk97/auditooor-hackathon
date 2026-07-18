"""
certora-aave-totalsupply-gte-availableliquidity — generated from reference/patterns.dsl/certora-aave-totalsupply-gte-availableliquidity.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py certora-aave-totalsupply-gte-availableliquidity.yaml
Source: certora-aave-v3-core/Reserve/expectedLiquidityGeAvailable
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CertoraAaveTotalsupplyGteAvailableliquidity(AbstractDetector):
    ARGUMENT = "certora-aave-totalsupply-gte-availableliquidity"
    HELP = "Cash-side transfer-out path does not burn matching aToken supply — Aave Certora `expectedLiquidityGeAvailable` invariant violated."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/certora-aave-totalsupply-gte-availableliquidity.yaml"
    WIKI_TITLE = "Transfer-out of reserve underlying without burning aToken (solvency drift)"
    WIKI_DESCRIPTION = "Aave's Certora specs maintain `aTokenTotalSupply(asset) * liquidityIndex >= availableLiquidity(asset) + totalDebt(asset)` — the aToken is always at least as well backed as the reserve claim on it. A path that transfers underlying out of the aToken contract (rescue, emergency sweep, unchecked adapter pull) without burning the corresponding aToken supply leaves more aToken claims outstanding than li"
    WIKI_EXPLOIT_SCENARIO = "An admin `rescueTokens(reserveUnderlying, to, amount)` is added and gated by onlyPoolAdmin. It calls `IERC20(underlying).safeTransfer(to, amount)` without burning aToken supply or debiting reserve accounting. 10% of a reserve's USDC is swept. Next 10% of withdrawers revert. The remaining 90% rush to withdraw, causing a run. Protocol books 10% bad debt."
    WIKI_RECOMMENDATION = "Any path that moves underlying out of the aToken must also call `_burn(msg.sender / treasury, amount)` (or the equivalent scaled-burn), decrementing totalSupply by an amount consistent with the underlying removed. Prove `expectedLiquidityGeAvailable` in Certora on every path touching cash."

    _PRECONDITIONS = [{'contract.has_state_var_matching': '(?i)(availableLiquidity|totalDebt|_cash|underlyingBalance|totalSupply)'}, {'contract.source_matches_regex': '(?i)(aToken|reserve|pool|lending)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': '(?i)^(withdraw|withdrawETH|withdrawTo|flashLoan|flashLoanSimple|transferUnderlyingTo|_transferUnderlying|rescue|rescueTokens|sweep|sweepTokens|adminWithdraw|skim|skimTo)$'}, {'function.body_contains_regex': '(?i)(transfer|safeTransfer)\\s*\\(.*\\)\\s*;'}, {'function.body_not_contains_regex': '(?i)(totalSupply|burn|_burn|scaledBalance|scaledBurn|reduceSupply)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — certora-aave-totalsupply-gte-availableliquidity: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
