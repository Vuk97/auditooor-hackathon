"""
duplicate-input-token-loop-multi-transfer-steal — generated from reference/patterns.dsl/duplicate-input-token-loop-multi-transfer-steal.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py duplicate-input-token-loop-multi-transfer-steal.yaml
Source: auditooor-R75-nethermind-ccdm-CRITICAL
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DuplicateInputTokenLoopMultiTransferSteal(AbstractDetector):
    ARGUMENT = "duplicate-input-token-loop-multi-transfer-steal"
    HELP = "An array of tokens (e.g. campaign inputTokens, reward tokens) is iterated and for each one the contract transfers an amount looked up by token-address. If the array can contain duplicates and the per-token amount is not decremented after transfer, each duplicate issues another full transfer — enabli"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/duplicate-input-token-loop-multi-transfer-steal.yaml"
    WIKI_TITLE = "Token-array loop with duplicates: per-index transfer multiplies payout"
    WIKI_DESCRIPTION = "When a campaign/market owner can set or influence the input/reward token list, and the transfer loop reads a cached per-token amount (deposited, earned, owed) without decrementing storage or deduplicating the array, repeating a token address inflates the total transferred. Because contracts often hold pooled balances for many markets/campaigns, the extra transfers come from balances owed to other "
    WIKI_EXPLOIT_SCENARIO = "CCDM's DepositExecutor iterates _inputTokens and transfers tokenToTotalAmountDeposited[token] to the weiroll wallet per iteration. Campaign owner Alice sets her inputTokens array to [USDC, USDC, USDC, USDC]. On executeDepositRecipes, 4 × USDC_deposited is sent to her wallet. The contract's USDC balance drops by 3× the over-transfer, coming from other campaigns' USDC. Alice drains her recipe's outp"
    WIKI_RECOMMENDATION = "Use OpenZeppelin EnumerableSet to store tokens (prevents duplicates), or de-duplicate the array before transferring, or decrement the per-token accounting on each transfer. Additionally, do not let the campaign owner mutate inputTokens after initial setup — pin the list to the cross-chain-confirmed "

    _PRECONDITIONS = [{'contract.source_matches_regex': 'inputTokens|campaignTokens|rewardTokens|assets.*\\[\\]'}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.name_matches': '^(_transfer|_transferTokens|transferInputTokens|transferCampaignTokens|_payoutRewards|_distributeRewards|_distribute|_executeTransfers|executeDepositRecipes|_executeDeposit)$'}, {'function.body_contains_regex': 'for\\s*\\(\\s*uint256\\s+i\\s*=\\s*0\\s*;\\s*i\\s*<\\s*[a-zA-Z_0-9.]+(inputTokens|tokens|rewards|assets)\\.length'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.body_contains_regex': '(safeTransfer|safeTransferFrom|transfer)\\s*\\(\\s*[a-zA-Z_]+[a-zA-Z_0-9]*\\s*,\\s*(wallet|recipient|to)\\s*,\\s*[a-zA-Z_0-9.]+\\[[a-zA-Z_]+\\]'}, {'function.body_not_contains_regex': '(EnumerableSet|_containsDuplicates|require.*unique|seenTokens)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — duplicate-input-token-loop-multi-transfer-steal: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
