"""
swap-allows-tokenin-equals-tokenout-overwrites-price — generated from reference/patterns.dsl/swap-allows-tokenin-equals-tokenout-overwrites-price.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py swap-allows-tokenin-equals-tokenout-overwrites-price.yaml
Source: auditooor-R76-rekt-monox-2021
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SwapAllowsTokeninEqualsTokenoutOverwritesPrice(AbstractDetector):
    ARGUMENT = "swap-allows-tokenin-equals-tokenout-overwrites-price"
    HELP = "AMM swap lets tokenIn == tokenOut. Both legs write to the same per-token price storage slot, so the swap's OUT-leg price update uses the inflated IN-leg price, pumping the asset's recorded price with each self-swap."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/swap-allows-tokenin-equals-tokenout-overwrites-price.yaml"
    WIKI_TITLE = "AMM swap does not reject tokenIn == tokenOut, enabling self-swap price inflation"
    WIKI_DESCRIPTION = "In single-sided AMMs (MonoX, some PMM designs), each token carries its own stored `price[token]` that is updated via the swap's inputs and outputs. If the swap code does not reject `tokenIn == tokenOut`, the attacker swaps the asset against itself — the IN leg first adjusts `price[MONO]` upward (as if MONO were being bought), then the OUT leg re-reads that inflated price as the starting point for "
    WIKI_EXPLOIT_SCENARIO = "Attacker calls `swapTokenForExactToken(MONO, MONO, 1e18, 1e18, attacker, deadline)`. `_updateTokenInfo` first updates `price[MONO] = price[MONO] * (reserveIn + amountIn) / reserveIn` — inflating. Then the out-leg runs and uses the inflated price to compute the output's new price: `price[MONO] = price[MONO] * reserveOut / (reserveOut - amountOut)` — inflating again. Net: one swap doubled the price."
    WIKI_RECOMMENDATION = "Add `require(tokenIn != tokenOut, 'identical tokens');` at the top of every swap entrypoint, including batched / multi-hop paths. For multi-hop, validate `path[i] != path[i+1]` and ideally that the full path does not contain a repeat beyond a whitelisted wrap cycle (e.g. WETH → stETH → wstETH → WETH"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, 'AMM swap function does not require `tokenIn != tokenOut` and writes a per-token price into storage that is read during price updates.']
    _MATCH = [{'function.kind': 'external'}, {'function.name_matches': '(?i)^swap\\w*|swapTokenFor|swapExact|swapForExact'}, {'function.body_contains_regex': '(?i)_updateTokenInfo|tokenStatus\\s*\\[|priceOf\\s*\\[|_token\\w*\\.price|tokenPrice\\s*\\['}, {'function.body_not_contains_regex': '(?i)require\\s*\\(\\s*tokenIn\\s*!=\\s*tokenOut|require\\s*\\(\\s*_in\\s*!=\\s*_out|require\\s*\\(\\s*path\\[0\\]\\s*!=\\s*path\\[path\\.length'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — swap-allows-tokenin-equals-tokenout-overwrites-price: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
