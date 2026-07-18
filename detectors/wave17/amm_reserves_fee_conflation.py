"""
amm-reserves-fee-conflation — generated from reference/patterns.dsl/amm-reserves-fee-conflation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py amm-reserves-fee-conflation.yaml
Source: code4arena/slice_ac-GTE-Launchpad-H03H04H05
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AmmReservesFeeConflation(AbstractDetector):
    ARGUMENT = "amm-reserves-fee-conflation"
    HELP = "AMM pair's mint/burn/swap reads reserve0/reserve1 or balanceOf(this) without subtracting the protocol/launchpad fee accumulator. LPs, burners, or swappers capture the fee reserve; k-invariant uses a larger-than-true reserve."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/amm-reserves-fee-conflation.yaml"
    WIKI_TITLE = "AMM reserves vs accrued-fee conflation in mint/burn/swap"
    WIKI_DESCRIPTION = "A custom AMM pair tracks a protocol or launchpad fee via an in-contract accumulator (`accruedFees`, `launchpadFee`). The balance held by the pair therefore equals `trueReserve + accruedFee`. When `mint`/`burn`/`swap` reads `reserve0/reserve1` or `balanceOf(address(this))` and uses the raw value in its proportion math or k-check, the accumulated fee is treated as LP-owned reserve: mints issue too m"
    WIKI_EXPLOIT_SCENARIO = "Launchpad pair accrues 10k quote as `launchpadFee` between skims. Attacker burns their 1% LP share; `burn()` distributes `(1% * balanceOf(this))` including the 10k fee — attacker pockets 100 from what should have been protocol revenue. Same bug lets swap compute `k = r0 * r1` including the fee float, enabling free-mint / drain combinations against the three sibling functions."
    WIKI_RECOMMENDATION = "Subtract the fee accumulator before any reserve-based arithmetic: `uint256 realReserve0 = reserve0 - accruedFee0`. Skim fees to treasury before mint/burn, or snapshot fees inside the function and subtract from the observed balance. Run k-invariant on the fee-adjusted reserves only."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'reserve0|reserve1|getReserves|accruedFee|accumulatedFee|launchpadFee'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(mint|burn|swap|_mint|_burn)'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': 'reserve0|reserve1|_reserve0|_reserve1|balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)'}, {'contract.has_state_var_matching': '(accruedFee|accumulatedFee|launchpadFee|protocolFee|treasuryFee)'}, {'function.body_not_contains_regex': '(reserve0|reserve1|_reserve0|_reserve1|balance\\w*)\\s*-\\s*(accruedFee|accumulatedFee|launchpadFee|protocolFee|treasuryFee)|subFees|_subtractFee'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — amm-reserves-fee-conflation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
