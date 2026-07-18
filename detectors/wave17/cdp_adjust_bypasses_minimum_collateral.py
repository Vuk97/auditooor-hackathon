"""
cdp-adjust-bypasses-minimum-collateral — generated from reference/patterns.dsl/cdp-adjust-bypasses-minimum-collateral.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py cdp-adjust-bypasses-minimum-collateral.yaml
Source: auditooor-R75-code4rena-2024-06-badger-17
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CdpAdjustBypassesMinimumCollateral(AbstractDetector):
    ARGUMENT = "cdp-adjust-bypasses-minimum-collateral"
    HELP = "adjustCdp reduces collateral without re-asserting the minimum net collateral + liquidator stipend invariant that openCdp enforces."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/cdp-adjust-bypasses-minimum-collateral.yaml"
    WIKI_TITLE = "adjustCdp collateral-reduction path skips min-collateral check enforced at open"
    WIKI_DESCRIPTION = "`openCdp` requires `stEthDeposit - LIQUIDATOR_REWARD >= MIN_NET_STETH_BALANCE`. `adjustCdp` accepts negative collateral deltas and reduces collateral without re-checking the invariant. Users can open at exactly the minimum and adjust their collateral down to near-zero, evading the liquidator gas stipend design. Liquidators won't bother liquidating low-collateral positions (no reward), leaving bad "
    WIKI_EXPLOIT_SCENARIO = "User opens at 2.2 stETH (2 net + 0.2 stipend). Immediately calls adjustCdp with collDelta = -1.5 stETH. CDP now has 0.7 stETH. No liquidator has incentive to close it. Price drops — CDP is insolvent, no one liquidates, protocol eats bad debt."
    WIKI_RECOMMENDATION = "In adjustCdp, after applying collDelta, call `_requireAtLeastMinNetStEthBalance(newColl - LIQUIDATOR_REWARD)`. Invariant test: after every state-changing call (open, adjust, close), CDP either has 0 collateral (closed) or ≥ MIN_NET + LIQUIDATOR_REWARD."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external'}, {'function.name_matches': '(?i)adjustCdp|adjustPosition|modifyCdp|updatePosition'}, {'function.body_contains_regex': '(?i)collateral\\s*-=|_decreaseColl|_withdrawColl|_reduceColl'}, {'function.body_not_contains_regex': '(?i)_requireAtLeastMinNetStEthBalance|_requireMinColl|_checkMinCollateral|MIN_NET_COLL'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — cdp-adjust-bypasses-minimum-collateral: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
