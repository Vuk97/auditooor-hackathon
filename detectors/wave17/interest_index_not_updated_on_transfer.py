"""
interest-index-not-updated-on-transfer — generated from reference/patterns.dsl/interest-index-not-updated-on-transfer.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py interest-index-not-updated-on-transfer.yaml
Source: solodit-novel/slice_aa-interest-index
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class InterestIndexNotUpdatedOnTransfer(AbstractDetector):
    ARGUMENT = "interest-index-not-updated-on-transfer"
    HELP = "Interest/reward-bearing token transfers balances without snapshotting per-user interest index. Receiver inherits sender's accrued interest position or skips accrual on sender."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/interest-index-not-updated-on-transfer.yaml"
    WIKI_TITLE = "ERC20 transfer does not update per-user interest/reward index"
    WIKI_DESCRIPTION = "Compound/Aave-style cTokens and reward-emitting tokens track per-user `userIndex` snapshots. The `_transfer` override must call `_updateInterestIndex(from)` and `_updateInterestIndex(to)` before moving balances. Skipping this double-counts or under-counts interest accrued to the sender."
    WIKI_EXPLOIT_SCENARIO = "User holds 100 cUSDC earning 5% APY since last update. User transfers all 100 to a new address. Without `_updateInterestIndex(from)` the accrued interest is either lost (never minted to sender) or overcounted (receiver inherits sender's snapshot index)."
    WIKI_RECOMMENDATION = "Always call `_updateInterestIndex(from); _updateInterestIndex(to);` at the top of `_transfer`."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'interestIndex|borrowIndex|supplyIndex|rewardPerTokenPaid|_userIndex'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(_transfer|_update|transfer|transferFrom)$'}, {'function.writes_storage_matching': 'balanceOf|_balances'}, {'function.body_not_contains_regex': '_updateInterestIndex|_updateIndex|_updateRewards|updateBorrowIndex|_accrueInterest|_updateUserIndex'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — interest-index-not-updated-on-transfer: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
