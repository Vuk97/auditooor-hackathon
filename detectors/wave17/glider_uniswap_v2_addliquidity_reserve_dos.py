"""
glider-uniswap-v2-addliquidity-reserve-dos — generated from reference/patterns.dsl/glider-uniswap-v2-addliquidity-reserve-dos.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-uniswap-v2-addliquidity-reserve-dos.yaml
Source: hexens-glider/denial-of-service-attack-on-uniswap-v2-pools-via-o
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderUniswapV2AddliquidityReserveDos(AbstractDetector):
    ARGUMENT = "glider-uniswap-v2-addliquidity-reserve-dos"
    HELP = "Launcher calls `router.addLiquidity()` for initial liquidity without validating both reserves are zero / pair is fresh. Attacker pre-creates the pair, donates a single asset, calls `sync()` — `UniswapV2Library.quote()` then reverts with INSUFFICIENT_LIQUIDITY permanently DoSing the launch."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-uniswap-v2-addliquidity-reserve-dos.yaml"
    WIKI_TITLE = "UniswapV2 addLiquidity initial-liquidity DoS via one-sided reserve"
    WIKI_DESCRIPTION = "UniswapV2Library.quote() requires reserveA > 0 && reserveB > 0. If both are 0, the router handles bootstrap. If only one is > 0 (attacker transferred tokenA and called sync), quote reverts. Launchpads that route all initial liquidity through addLiquidity without an escape hatch are permanently bricked once this sync is done."
    WIKI_EXPLOIT_SCENARIO = "Token launch contract expects to seed liquidity via `router.addLiquidityETH{value: x}(token, amtToken, ...)`. Attacker pre-creates pair, transfers 1 wei of `token` to it, calls `pair.sync()`. Now reserveToken>0 and reserveETH=0. Victim's addLiquidityETH call reverts inside `quote`. No recovery path exists."
    WIKI_RECOMMENDATION = "Do initial liquidity via direct `pair.mint(to)` after transferring both assets, OR validate `getReserves()` first and fall back to the mint path if one side is non-zero."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'addLiquidity|IUniswapV2Router'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '\\.addLiquidity(ETH)?\\s*\\('}, {'function.body_not_contains_regex': 'pair\\.mint\\s*\\(|IUniswapV2Pair\\s*\\(|getReserves\\s*\\(|reserveA\\s*>\\s*0|reserveB\\s*>\\s*0|reserve0\\s*>\\s*0|reserve1\\s*>\\s*0'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-uniswap-v2-addliquidity-reserve-dos: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
