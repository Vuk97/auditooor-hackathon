"""
lp-asymmetric-liquidity-extract — generated from reference/patterns.dsl/lp-asymmetric-liquidity-extract.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py lp-asymmetric-liquidity-extract.yaml
Source: solodit-cluster-C0176
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LpAsymmetricLiquidityExtract(AbstractDetector):
    ARGUMENT = "lp-asymmetric-liquidity-extract"
    HELP = "External/public liquidity entrypoint (addLiquidity/swap/deposit/zap/provideSingleSided) accepts a single-sided deposit without any price-imbalance or oracle check — attacker tilts reserves and extracts value via IL."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/lp-asymmetric-liquidity-extract.yaml"
    WIKI_TITLE = "Asymmetric single-sided liquidity extract (IL-profit attack)"
    WIKI_DESCRIPTION = "A contract holds an AMM-style reserve (state var named reserve/pool/liquidity/totalReserves/poolBalance) and exposes a user-callable deposit path whose body contains a single-sided-LP idiom (addLiquidity.*single, singleSided, oneSided, zap, zapIn) but contains none of the canonical price-imbalance defenses (sqrtPriceX96, TWAP, oracle.getPrice, imbalance, priceDeviation). Because adding liquidity o"
    WIKI_EXPLOIT_SCENARIO = "A vault exposes `provideSingleSided(uint256 amountA)` that mints LP against the reserve's ratio at call time, with no pre- or post- oracle check. The attacker swaps tokenA into tokenB on the same pool, tilting the ratio to undervalue tokenA. Inside the same tx they call `provideSingleSided` with a large tokenA amount: because the pool is now tilted, the vault mints them LP worth more tokenB-equiva"
    WIKI_RECOMMENDATION = "Require a freshness-checked oracle read (`sqrtPriceX96`, Chainlink `oracle.getPrice`, or a multi-block TWAP) on every single-sided-deposit and bound the allowed deviation between the pool's instantaneous ratio and the oracle quote. Reject the deposit when the deviation exceeds a configured threshold"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'reserve|pool|liquidity|totalReserves|poolBalance'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'addLiquidity|swap|deposit|_swap|_addLiquidity|provideSingleSided'}, {'function.body_contains_regex': 'addLiquidity.*single|singleSided|oneSided|zap|zapIn'}, {'function.body_not_contains_regex': 'sqrtPriceX96|TWAP|oracle\\.getPrice|imbalance|priceDeviation'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — lp-asymmetric-liquidity-extract: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
