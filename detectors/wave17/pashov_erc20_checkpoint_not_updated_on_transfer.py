"""
pashov-erc20-checkpoint-not-updated-on-transfer — generated from reference/patterns.dsl/pashov-erc20-checkpoint-not-updated-on-transfer.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py pashov-erc20-checkpoint-not-updated-on-transfer.yaml
Source: auditooor-R75-pashov-StakeDAO-StrategyWrapper-C02
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PashovErc20CheckpointNotUpdatedOnTransfer(AbstractDetector):
    ARGUMENT = "pashov-erc20-checkpoint-not-updated-on-transfer"
    HELP = "A wrapper token tracks reward checkpoints per address but inherits ERC20 without overriding `_update`/`_beforeTokenTransfer` — plain transfers move balance but not checkpoint, so rewards attach to the wrong address and liquidators revert on redeem."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/pashov-erc20-checkpoint-not-updated-on-transfer.yaml"
    WIKI_TITLE = "Reward-checkpoint wrapper token forgets to override _update (ERC20 transfers bypass checkpoint)"
    WIKI_DESCRIPTION = "Contracts that inherit OpenZeppelin `ERC20` (or `ERC20Upgradeable`) and layer per-user reward bookkeeping (`userCheckpoints[user].balance`) MUST override `_update` (OZ 5.x) or `_beforeTokenTransfer`/`_afterTokenTransfer` (OZ 4.x) so that transfers, mints and burns keep the checkpoint in sync with the ERC20 balance. When the override is missing, only the deposit/withdraw paths update the checkpoint"
    WIKI_EXPLOIT_SCENARIO = "StakeDAO StrategyWrapper is used as collateral in Morpho Blue. Bob borrows against the wrapper and gets liquidated. The liquidator now owns the wrapper tokens via a standard ERC20 transfer inside Morpho's liquidation settlement. When the liquidator calls `withdraw` or `redeemLP`, the code executes `UserCheckpoint storage checkpoint = userCheckpoints[msg.sender]; checkpoint.balance -= amount;` — bu"
    WIKI_RECOMMENDATION = "Override `_update(from, to, value)` (OZ 5.x) in the wrapper and, inside it, call the reward-state updater for both `from` and `to` (unless zero-address), then adjust checkpoint balances to match the new ERC20 balances. Re-audit every sibling wrapper (StakedToken, veToken, share-manager) for the same"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'ERC20|ERC20Upgradeable|userCheckpoints|checkpoint\\.balance'}]
    _MATCH = [{'contract.inherits_regex': 'ERC20|ERC20Upgradeable|ERC20VotesUpgradeable'}, {'contract.has_function_matching': 'deposit|withdraw|claim'}, {'contract.body_contains_regex': 'userCheckpoints\\s*\\[|checkpoint\\.balance|UserCheckpoint\\s+storage'}, {'contract.body_not_contains_regex': 'function\\s+_update\\s*\\(|function\\s+_beforeTokenTransfer\\s*\\(|function\\s+_afterTokenTransfer\\s*\\('}, {'contract.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — pashov-erc20-checkpoint-not-updated-on-transfer: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
