"""
withdraw-keys-inflate-total-assets — generated from reference/patterns.dsl/withdraw-keys-inflate-total-assets.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py withdraw-keys-inflate-total-assets.yaml
Source: solodit-novel/slice_ab-logarithm-labs
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class WithdrawKeysInflateTotalAssets(AbstractDetector):
    ARGUMENT = "withdraw-keys-inflate-total-assets"
    HELP = "`totalAssets()` sums pending-withdraw entries without subtracting them; the vault reports more assets than it actually owns after redemption completes."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/withdraw-keys-inflate-total-assets.yaml"
    WIKI_TITLE = "totalAssets() over-reports by including settled pending withdrawals"
    WIKI_DESCRIPTION = "Vault tracks pending withdrawals in a mapping/array. `totalAssets()` iterates and adds these entries to total. When a redemption settles, the asset leaves the vault but the entry stays in the pending list (soft-delete or missing cleanup), inflating totalAssets and therefore share price."
    WIKI_EXPLOIT_SCENARIO = "Alice redeems 100 USDC. Vault sends USDC to Alice. pendingWithdraw[alice] remains 100. `totalAssets()` now over-counts by 100. Next depositor's shares price off inflated totalAssets and receives fewer shares than fair."
    WIKI_RECOMMENDATION = "On settlement, delete the entry (`delete pendingWithdraw[alice]`) or subtract it in the accumulation."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'pendingWithdraw|withdrawQueue|pendingRedemption|queuedWithdraw'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^totalAssets$'}, {'function.state_mutability': 'view'}, {'function.body_contains_regex': 'pendingWithdraw|withdrawQueue|pendingRedemption|queuedWithdraw|_pending'}, {'function.body_not_contains_regex': 'subtract|_pending\\s*-\\s*|-\\s*pending|-\\s*\\w*Queue'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — withdraw-keys-inflate-total-assets: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
