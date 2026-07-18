"""
missing-before-transfer-hook-erc20-flywheel — generated from reference/patterns.dsl/missing-before-transfer-hook-erc20-flywheel.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py missing-before-transfer-hook-erc20-flywheel.yaml
Source: solodit-novel/slice_af-Maia-DAO
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MissingBeforeTransferHookErc20Flywheel(AbstractDetector):
    ARGUMENT = "missing-before-transfer-hook-erc20-flywheel"
    HELP = "ERC20 flywheel token does not call accrue(from)/accrue(to) inside its _transfer hook. Transfers desync the per-user reward-debt accounting."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/missing-before-transfer-hook-erc20-flywheel.yaml"
    WIKI_TITLE = "ERC20 flywheel transfer lacks accrue hook"
    WIKI_DESCRIPTION = "Reward flywheels depend on `accrue(user)` being invoked before any balance change so that pending rewards are snapshotted. ERC20 tokens that serve as the flywheel staking token must override `_transfer`/`_update` to call `accrue` on both sender and recipient. Without this, transferring the balance also transfers unrealized rewards to the recipient, or the sender keeps accumulating post-transfer."
    WIKI_EXPLOIT_SCENARIO = "Maia DAO variant: flywheel ERC20 does not override `_beforeTokenTransfer`. Attacker stakes, waits for rewards to accrue, transfers staked balance to a secondary wallet. Secondary wallet now inherits ALL unrealized rewards. Attacker repeats across wallets, extracting rewards as many times as the transfer cycle. First-discovery variants of the flywheel bug pattern."
    WIKI_RECOMMENDATION = "Override `_beforeTokenTransfer` (or `_update` in OZ v5) to call `flywheel.accrue(from); flywheel.accrue(to)` before performing the balance update. Unit-test: transfer-then-claim should pay sender, not recipient, for rewards earned before the transfer."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'ERC20|IERC20|flywheel|rewardDebt|rewardPerShare|accReward|accumulatedReward'}]
    _MATCH = [{'function.kind': 'internal'}, {'function.name_matches': '_transfer|_update|_beforeTokenTransfer|transfer'}, {'function.is_mutating': True}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': 'balanceOf|_balances\\s*\\['}, {'function.body_not_contains_regex': 'accrue\\s*\\(|_updateRewards\\s*\\(|rewardDebt|checkpoint\\s*\\(|flywheel\\.'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — missing-before-transfer-hook-erc20-flywheel: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
