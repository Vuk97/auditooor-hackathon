"""
ec-rounding-withdraw-favors-user — generated from reference/patterns.dsl/ec-rounding-withdraw-favors-user.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py ec-rounding-withdraw-favors-user.yaml
Source: economic-mining-R61
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EcRoundingWithdrawFavorsUser(AbstractDetector):
    ARGUMENT = "ec-rounding-withdraw-favors-user"
    HELP = "withdraw/redeem computes shares-to-burn using floor division instead of ceiling division, slowly leaking vault value to users in violation of ERC-4626 spec."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/ec-rounding-withdraw-favors-user.yaml"
    WIKI_TITLE = "ERC-4626 withdraw rounds down shares-to-burn (should round up)"
    WIKI_DESCRIPTION = "The withdraw/redeem function computes the number of shares to burn using plain integer division (floor/round-down). ERC-4626 mandates that convertToShares used in a withdrawal rounds UP to protect the vault from value leakage. With round-down, a user can withdraw slightly more assets per share than fair, and in loops of many small withdrawals this extracts material value."
    WIKI_EXPLOIT_SCENARIO = "Attacker finds vault with totalAssets=1000001 and totalSupply=1000000. Calls withdraw(1) in a loop 100,000 times. Each call burns 0 shares (1 * 1000000 / 1000001 rounds down to 0) but transfers 1 wei of asset. Net: 100,000 wei extracted with 0 shares burned."
    WIKI_RECOMMENDATION = "Use mulDivUp (or OpenZeppelin Math.mulDiv with Rounding.Ceil) for shares-to-burn in withdraw/redeem: `shares = assets.mulDivUp(totalSupply, totalAssets)`. Conversely, shares-to-mint in deposit must round DOWN. This is mandated by ERC-4626 section 4."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'totalAssets|totalSupply|convertToShares|previewWithdraw'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(withdraw|redeem|_withdraw|_redeem)'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.body_contains_regex': 'shares\\s*=.*assets.*totalSupply|shares\\s*=.*\\*.*totalSupply.*totalAssets|convertToShares\\s*\\('}, {'function.body_not_contains_regex': 'mulDivUp|ceilDiv|roundUp|RoundingUp|ROUND_UP|\\.ceil\\b|_divCeil|divUp'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — ec-rounding-withdraw-favors-user: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
