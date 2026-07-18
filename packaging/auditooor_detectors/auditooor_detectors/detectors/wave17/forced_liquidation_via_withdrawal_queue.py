"""
forced-liquidation-via-withdrawal-queue — generated from reference/patterns.dsl/forced-liquidation-via-withdrawal-queue.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py forced-liquidation-via-withdrawal-queue.yaml
Source: SKILL_ISSUE
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ForcedLiquidationViaWithdrawalQueue(AbstractDetector):
    ARGUMENT = "forced-liquidation-via-withdrawal-queue"
    HELP = "A vault/tranche with a withdrawal queue allows a attacker to request withdrawals exceeding their actual balance or the vault's liquid reserves, forcing liquidation of ALL positions to satisfy the request."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/forced-liquidation-via-withdrawal-queue.yaml"
    WIKI_TITLE = "Forced liquidation via withdrawal queue TVL exhaustion"
    WIKI_DESCRIPTION = "The withdrawal queue or claimable-balance mechanism allows a user to request withdrawals without properly validating that the requested amount does not exceed the user's actual balance or the vault's available liquid reserves. An attacker deposits a small amount, then requests a withdrawal equal to the entire vault TVL. Because the queue processes requests in FIFO order, the vault must liquidate a"
    WIKI_EXPLOIT_SCENARIO = "Attacker deposits 1 wei of capital into a vault with 10M TVL. Attacker calls requestWithdraw(10M). The vault's withdrawal queue processes this request in FIFO order. To fulfill the 10M withdrawal, the vault liquidates all remaining positions (9.999999M from other users). The attacker receives 10M, draining the vault and leaving other users with nothing. Pear Protocol lost $56M this way."
    WIKI_RECOMMENDATION = "Add a require statement checking that the withdrawal amount does not exceed the user's balance or the vault's available liquid reserves before adding to the queue. Alternatively, implement a per-user withdrawal limit based on their share of total deposits."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(withdrawalQueue|claimableBalance|tranche|vault)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(requestWithdraw|addToWithdrawalQueue|withdraw|claim|redeem)$'}, {'function.not_body_contains_regex': 'require\\s*\\(\\s*balance'}, {'function.not_body_contains_regex': 'require\\s*\\(\\s*shares'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — forced-liquidation-via-withdrawal-queue: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
