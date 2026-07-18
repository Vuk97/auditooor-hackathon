"""
curve-getdy-as-slippage-reference-circular-protection — generated from reference/patterns.dsl/curve-getdy-as-slippage-reference-circular-protection.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py curve-getdy-as-slippage-reference-circular-protection.yaml
Source: auditooor-R76-cyfrin-sablier-bob-escrow-H1
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CurveGetdyAsSlippageReferenceCircularProtection(AbstractDetector):
    ARGUMENT = "curve-getdy-as-slippage-reference-circular-protection"
    HELP = "Slippage threshold computed by calling pool's own get_dy then subtracting slippageTolerance. Both quote and exchange read the same (manipulable) reserves — slippage check is always tautologically satisfied."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/curve-getdy-as-slippage-reference-circular-protection.yaml"
    WIKI_TITLE = "Circular slippage: minOut derived from Curve get_dy() on same pool → 0% effective protection"
    WIKI_DESCRIPTION = "`_wstETHToWeth` derives minOut as `get_dy(1, 0, stEthAmount) * (1 - slippageTolerance)` and then immediately calls `exchange(1, 0, stEthAmount, minOut)`. Curve's `get_dy` reads `self._balances()` to compute its quote; `exchange` reads the same balances to compute the actual output. Both operations happen within the same attacker-controlled transaction, so both sides of the slippage inequality refl"
    WIKI_EXPLOIT_SCENARIO = "Vault expires; `unstakeTokensViaAdapter(vid)` is permissionless. Attacker flashloans 10k stETH and dumps into the stETH/ETH Curve pool, depressing stETH/ETH by 4%. Attacker calls unstakeTokensViaAdapter: get_dy returns 4% depressed quote, minOut = depressed * 0.95. exchange runs at the depressed rate, user receives ~4% less WETH. Attacker back-runs to restore pool and profits. `_wethReceivedAfterU"
    WIKI_RECOMMENDATION = "Replace the circular spot-price reference with an EXTERNAL oracle feed. Options: (1) Use a Chainlink stETH/ETH price feed (or derive from stETH/USD and ETH/USD): `fairEthOut = stEthAmount * oracleRate / 1e18; minEthOut = fairEthOut * (1 - slippageTolerance)`. (2) Let the caller pass `minEthOut` comp"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)Adapter|Swap|Curve|Pool|Router|Wrapper'}, {'contract.has_function_matching': '(?i)_swap|_stETHToWeth|_wstETHToWeth|curveSwap|exchange'}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.name_matches': '(?i)_wstETHToWeth|_stETHToWeth|_swap|_curveSwap|_exchange|_unstakeAdapter'}, {'function.body_contains_regex': '(?i)get_dy\\s*\\(|getAmountsOut|quote\\s*\\(|previewSwap'}, {'function.body_contains_regex': '(?i)slippageTolerance|SLIPPAGE|MAX_SLIPPAGE|unitSub\\s*\\(\\s*slippage|\\.mul\\(UNIT\\.sub\\(slippage'}, {'function.body_contains_regex': '(?i)exchange\\s*\\(|swap\\s*\\('}, {'function.body_not_contains_regex': '(?i)getOracle|oracle.*Price|STETH_ORACLE|chainlinkPrice|external.*price|stEthPerToken\\s*\\(\\s*\\)|getPooledEthByShares'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — curve-getdy-as-slippage-reference-circular-protection: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
