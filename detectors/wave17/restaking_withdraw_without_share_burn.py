"""
restaking-withdraw-without-share-burn — generated from reference/patterns.dsl/restaking-withdraw-without-share-burn.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py restaking-withdraw-without-share-burn.yaml
Source: solodit-cluster/C0129
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RestakingWithdrawWithoutShareBurn(AbstractDetector):
    ARGUMENT = "restaking-withdraw-without-share-burn"
    HELP = "Restaking withdraw path removes underlying (transfer / pod.withdraw / validatorBalance -= ...) but does not burn the withdrawer's shares — next accrual mis-distributes, and a slashing event turns the accounting drift into direct principal loss for the remaining share holders."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/restaking-withdraw-without-share-burn.yaml"
    WIKI_TITLE = "Restaking withdraw without corresponding share burn (EigenLayer / Puffer-style accounting break)"
    WIKI_DESCRIPTION = "A restaking vault or EigenPod-style delegator exposes a withdraw / completeWithdrawal path that (a) moves underlying out of the protocol — via a direct token transfer, pod.withdraw, a decrement of validatorBalance / restakedBalance, or a generic _removeAsset helper — but (b) fails to burn the withdrawer's corresponding share tokens. The invariant totalAssets == sum(shares * price) breaks immediate"
    WIKI_EXPLOIT_SCENARIO = "PufferVault holds 100 ETH of validator balance backing 100 shares. Alice holds 20 shares. Alice calls completeWithdrawal(); the function transfers 20 ETH to Alice and decrements validatorBalance by 20 ETH, but forgets to burn Alice's 20 shares. Vault now backs 80 ETH with 100 shares (price 0.8). A slashing event then accrues 10 ETH of loss. Loss is spread pro-rata across 100 shares (0.1 ETH per sh"
    WIKI_RECOMMENDATION = "Every withdraw / completeWithdrawal / queueWithdraw path must burn shares atomically with the underlying asset movement. Use a CEI-ordered sequence: (1) compute shares to burn, (2) `_burn(msg.sender, sharesOut)` or equivalent protocol-specific `decreaseDelegatedShares` / `burnPodShares`, (3) transfe"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'delegatedShares|restakedShares|operatorShares|podOwnerShares|pod|validatorBalance|restakedBalance|beaconChainETHStrategy'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.not_slither_synthetic': True}, {'function.is_mutating': True}, {'function.name_matches': 'withdraw|completeWithdrawal|processWithdraw|_completeWithdrawal|finalizeWithdraw|queueWithdraw'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.body_contains_regex': '_removeAsset|\\.transfer\\s*\\(|safeTransfer\\s*\\(|pod\\.withdraw|validatorBalance\\s*-=|restakedBalance\\s*-=|withdrawBeaconChainETH'}, {'function.body_not_contains_regex': '_burn\\s*\\(|burnShares\\s*\\(|decreaseShares\\s*\\(|_decreaseDelegatedShares\\s*\\(|burnPodShares\\s*\\(|_decreasePodShares\\s*\\(|removeShares\\s*\\('}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — restaking-withdraw-without-share-burn: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
