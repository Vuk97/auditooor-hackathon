"""
balancer-linear-pool-wei-exchange-1-to-1-rate-drift — generated from reference/patterns.dsl/balancer-linear-pool-wei-exchange-1-to-1-rate-drift.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py balancer-linear-pool-wei-exchange-1-to-1-rate-drift.yaml
Source: auditooor-R76-immunefi-balancer-$100k
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BalancerLinearPoolWeiExchange1To1RateDrift(AbstractDetector):
    ARGUMENT = "balancer-linear-pool-wei-exchange-1-to-1-rate-drift"
    HELP = "Rate calculation `balance/supply` uses div-DOWN. Repeated 1-wei swaps decrement balance without supply changes, drifting rate below 1:1. With flash-loanable BPT and zero-fee band, attacker drains."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/balancer-linear-pool-wei-exchange-1-to-1-rate-drift.yaml"
    WIKI_TITLE = "Linear pool rate computed with divDown drifts below parity under wei-level swaps"
    WIKI_DESCRIPTION = "ERC4626LinearPools (and any 1:1 wrap/underlying AMM) derive their internal exchange rate from `mainBalance / wrappedSupply`. When the rounding mode is `divDown`, every 1-wei `GivenOut` swap burns 1 wei from mainBalance but only 1 wei from wrappedSupply — and over many iterations the rate drops below 1.0. Because target-balance-window swaps are fee-free and BPT is flashloanable, the attacker: flash"
    WIKI_EXPLOIT_SCENARIO = "Balancer ERC4626LinearPool rate = balance/supply (divDown). Attacker flashloaned BPT, executed GivenOut swaps of 1 wei repeatedly. Each shaved the rate minutely without updating supply proportionally. Cumulative drift drained underlying. $100k bounty; fix: divUp for user-favor calculations, divDown when it hurts them."
    WIKI_RECOMMENDATION = "When computing exchange rates that gate *user withdrawals*, always round against the user (divUp). Use OZ/Balancer FixedPoint.divUp consistently. Add fuzz test: `forall seq of wei-level swaps, final_rate >= initial_rate` (for non-yielding pools)."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.is_balancer_linear_pool': True}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)onSwap|_swap|swapGivenOut|_calcInGivenOut|_getRate'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.body_contains_regex': '(?i)rate\\s*=\\s*balance\\s*/\\s*supply|_mainBalance\\s*/\\s*_wrappedSupply|/\\s*totalSupply|divDown'}, {'function.body_not_contains_regex': '(?i)divUp|FixedPoint\\.divUp|round.*up|\\+\\s*1(?![0-9])|Math\\.ceil'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — balancer-linear-pool-wei-exchange-1-to-1-rate-drift: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
