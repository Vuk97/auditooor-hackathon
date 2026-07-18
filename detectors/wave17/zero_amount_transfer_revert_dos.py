"""
zero-amount-transfer-revert-dos — generated from reference/patterns.dsl/zero-amount-transfer-revert-dos.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py zero-amount-transfer-revert-dos.yaml
Source: auditooor-cross-cluster
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ZeroAmountTransferRevertDos(AbstractDetector):
    ARGUMENT = "zero-amount-transfer-revert-dos"
    HELP = "Function calls `token.transfer(to, amount)` without first checking `amount > 0`. Some ERC20s (LEND and various custom tokens) revert on zero-value transfers, so any caller that may pass 0 (dust refund, zero-balance harvest) DOSes itself."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/zero-amount-transfer-revert-dos.yaml"
    WIKI_TITLE = "Direct ERC20 transfer without zero-amount skip — reverts on LEND-style tokens"
    WIKI_DESCRIPTION = "The function performs `IERC20(token).transfer(to, amount)` or a safeTransfer variant without guarding against `amount == 0`. EIP-20 does not forbid zero-value transfers from reverting, and a long tail of tokens (LEND, certain fee-on-transfer tokens, custom reward tokens) DO revert when amount is zero. Callers that can plausibly invoke the function with a zero amount — reward harvest with nothing a"
    WIKI_EXPLOIT_SCENARIO = "A staking contract calls `rewardToken.transfer(user, pendingReward)` inside `claim()`. If a user calls claim() twice in the same block, the second call transfers 0. If rewardToken is one of the zero-revert tokens, the entire claim() reverts and any state changes (e.g., timestamp update) are rolled back. A griefer can additionally enter with a dust stake that accrues to zero reward per second, maki"
    WIKI_RECOMMENDATION = "Wrap every transfer with a zero-amount skip: `if (amount == 0) return;` before the transfer, or `if (amount > 0) token.transfer(to, amount);`. For loop-based distributors use `continue`. This is a one-line fix that removes an entire category of token-compatibility bugs."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.body_contains_regex': '\\.transfer\\s*\\(|safeTransfer\\s*\\(|\\.transferFrom\\s*\\(|safeTransferFrom\\s*\\('}, {'function.body_not_contains_regex': 'if\\s*\\(\\s*\\w*amount\\s*(==|!=)\\s*0|if\\s*\\(\\s*\\w*amount\\s*>\\s*0|return\\s*;|continue\\s*;|require\\s*\\(\\s*amount\\s*>\\s*0'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — zero-amount-transfer-revert-dos: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
