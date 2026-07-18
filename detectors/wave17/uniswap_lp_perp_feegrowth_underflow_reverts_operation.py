"""
uniswap-lp-perp-feegrowth-underflow-reverts-operation — generated from reference/patterns.dsl/uniswap-lp-perp-feegrowth-underflow-reverts-operation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py uniswap-lp-perp-feegrowth-underflow-reverts-operation.yaml
Source: auditooor-R75-c4-2023-12-particle-H10
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class UniswapLpPerpFeegrowthUnderflowRevertsOperation(AbstractDetector):
    ARGUMENT = "uniswap-lp-perp-feegrowth-underflow-reverts-operation"
    HELP = "`getFeeGrowthInside` ports the Uniswap v3 formula but omits the `unchecked {}` block. Solidity 0.8+ panics on the expected modular subtraction — every position-fee computation reverts, DoSing open/close/liquidate paths."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/uniswap-lp-perp-feegrowth-underflow-reverts-operation.yaml"
    WIKI_TITLE = "getFeeGrowthInside port missing unchecked block — 0.8+ panics on expected modular subtraction"
    WIKI_DESCRIPTION = "Uniswap v3 tracks fee growth as cumulative uint256 values that are designed to wrap. The per-range formula is `feeGrowthInside = feeGrowthGlobal - feeGrowthOutsideLower - feeGrowthOutsideUpper`. Under Solidity 0.7.x (which Uniswap v3 core uses) the subtraction naturally wraps. Downstream protocols on Solidity 0.8+ ( Particle, Panoptic, Bracket, Gammaswap) that re-implement the calculation inline w"
    WIKI_EXPLOIT_SCENARIO = "(1) Protocol uses Solidity 0.8.23, copies Uniswap `PositionValue.getFeeGrowthInside` as-is. (2) Pool has tick-crossings over time such that `feeGrowthOutsideLower + feeGrowthOutsideUpper` > `feeGrowthGlobal` in uint256 terms (normal; the 'negative' value represents a modular displacement). (3) User tries to close a Particle loan with a position spanning the problematic range. `getFeeGrowthInside` "
    WIKI_RECOMMENDATION = "Wrap the modular-subtraction arithmetic in `unchecked { ... }` exactly matching Uniswap v3 core semantics: ```unchecked { feeGrowthInside0X128 = feeGrowthGlobal0X128 - below0 - above0; feeGrowthInside1X128 = feeGrowthGlobal1X128 - below1 - above1; }```. Add a unit test with a crafted tick state wher"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(getFeeGrowthInside|feeGrowthInside0X128|feeGrowthInside1X128|getPositionValue)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.state_mutability': 'view'}, {'function.name_matches': '(getFeeGrowthInside|_getFeeGrowthInside|computeFeeGrowth|positionFees)'}, {'function.body_contains_regex': 'feeGrowthGlobal0X128|lowerFeeGrowthOutside0X128|upperFeeGrowthOutside0X128'}, {'function.body_contains_regex': '(feeGrowthInside0X128|feeGrowthInside1X128)\\s*=\\s*.*-.*-'}, {'function.body_not_contains_regex': 'unchecked\\s*\\{'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — uniswap-lp-perp-feegrowth-underflow-reverts-operation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
