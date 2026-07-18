"""
ec-lp-total-supply-read-before-burn — generated from reference/patterns.dsl/ec-lp-total-supply-read-before-burn.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py ec-lp-total-supply-read-before-burn.yaml
Source: economic-mining-R61
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EcLpTotalSupplyReadBeforeBurn(AbstractDetector):
    ARGUMENT = "ec-lp-total-supply-read-before-burn"
    HELP = "Share price computed using totalSupply before the corresponding burn call; pre-burn supply inflates the output assets received."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/ec-lp-total-supply-read-before-burn.yaml"
    WIKI_TITLE = "LP share price uses pre-burn totalSupply — inflated asset output"
    WIKI_DESCRIPTION = "The withdraw/redeem function computes assets-to-send as `shares * totalAssets / totalSupply` but reads totalSupply before calling _burn(). This means the divisor is the pre-burn (larger) supply, making each share appear worth fewer assets — or in the inverse flow, mints too many shares against the same deposit. Combined with a flash-minted supply change, the delta is exploitable."
    WIKI_EXPLOIT_SCENARIO = "totalSupply = 100e18, totalAssets = 100e18. User holds 10e18 shares. Calls withdraw(). Code: assets = shares * totalAssets / totalSupply = 10e18 (correct). But attacker front-runs with a tiny deposit that changes totalSupply to 100.0001e18 without proportionally adding assets. Now assets = 10e18 * 100e18 / 100.0001e18 = slightly less — user is short-changed. Reverse: deposit before withdraw inflat"
    WIKI_RECOMMENDATION = "Perform all burns/mints before computing the output amount, or use a snapshot of totalSupply taken after the burn. In ERC-4626 vaults follow the spec's ordering: burn shares first, then compute and transfer assets."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'totalSupply|_totalSupply|burn|_burn|withdraw|redeem'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(withdraw|redeem|exit|burn|removeLiquidity)'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.body_contains_regex': 'totalSupply\\(\\)|_totalSupply\\b'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.body_contains_regex': 'assets\\s*=.*totalSupply|amount\\s*=.*totalSupply|shares.*\\*.*totalAssets.*totalSupply'}, {'function.body_contains_regex': '_burn\\s*\\(|burn\\s*\\('}, {'function.body_not_contains_regex': '_burn.*;\\s*\\w+\\s*=.*totalSupply|after.*burn.*price|postBurn'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — ec-lp-total-supply-read-before-burn: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
