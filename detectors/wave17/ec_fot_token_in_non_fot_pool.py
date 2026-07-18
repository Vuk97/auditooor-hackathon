"""
ec-fot-token-in-non-fot-pool — generated from reference/patterns.dsl/ec-fot-token-in-non-fot-pool.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py ec-fot-token-in-non-fot-pool.yaml
Source: economic-mining-R61
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EcFotTokenInNonFotPool(AbstractDetector):
    ARGUMENT = "ec-fot-token-in-non-fot-pool"
    HELP = "AMM swap computes output from amountIn parameter while k-check uses actual post-transfer balance; FoT tokens cause delta mismatch allowing k-check bypass."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/ec-fot-token-in-non-fot-pool.yaml"
    WIKI_TITLE = "Fee-on-transfer token in non-FoT-aware AMM — amountIn vs reserve delta mismatch"
    WIKI_DESCRIPTION = "The AMM swap function computes amountOut from the nominal amountIn parameter but enforces the k-invariant using the actual post-transfer balances. For FoT tokens, actual received balance < amountIn. The k-check passes because it sees the smaller real delta, but amountOut was computed against the larger parameter, enabling over-extraction of the paired token."
    WIKI_EXPLOIT_SCENARIO = "Pool: reserve0=1000 FoT, reserve1=1000 USDC. FoT token has 10% fee. User swaps 100 FoT → USDC. Contract computes amountOut = 100*1000/1100 = 90.9 USDC using parameter. Only 90 FoT actually received (10 fee taken). k-check: 1090 * 909 vs 1000 * 1000. 1090*909 = 990,810 < 1,000,000, check fails — but in reverse k direction this enables extraction in other designs."
    WIKI_RECOMMENDATION = "Compute amountIn as the balance delta: `uint256 amountIn0 = balance0 - reserve0` and use this in output calculations. This is the Uniswap V2 standard approach; deviation from it for parameterized inputs creates the vulnerability. Alternatively, whitelist or blacklist FoT tokens explicitly."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'swap|mint|burn|reserve0|reserve1|getReserves'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(swap|mint|_mint|addLiquidity)'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': 'balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*\\)|IERC20.*balanceOf'}, {'function.body_contains_regex': 'amountIn|amount0In|amount1In'}, {'function.body_contains_regex': 'balance0Adjusted|balance1Adjusted|amount[01]In\\s*\\*\\s*9[79]'}, {'function.body_not_contains_regex': 'feeOnTransfer|isFoT|hasFee|deflation|isTaxed'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — ec-fot-token-in-non-fot-pool: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
