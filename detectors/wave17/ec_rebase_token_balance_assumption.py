"""
ec-rebase-token-balance-assumption — generated from reference/patterns.dsl/ec-rebase-token-balance-assumption.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py ec-rebase-token-balance-assumption.yaml
Source: auditooor-R71-ec-patterns-batch
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EcRebaseTokenBalanceAssumption(AbstractDetector):
    ARGUMENT = "ec-rebase-token-balance-assumption"
    HELP = "Function snapshots balanceOf + later reads balanceOf as deltas without accounting for rebase drift. If the underlying token is stETH / aToken / sDAI-v1 / rebase-family, the pre/post balance diff doesn't equal actual transfers, leading to reward misattribution or drain."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/ec-rebase-token-balance-assumption.yaml"
    WIKI_TITLE = "Rebase-token balance-delta assumption (stETH, aToken, sDAI, cToken)"
    WIKI_DESCRIPTION = "Function uses `IERC20(token).balanceOf(address(this))` as a SNAPSHOT-DIFF baseline for computing deposits / withdrawals / rewards. For non-rebasing ERC-20s this is correct. For rebase-family tokens (Lido's stETH, Aave aTokens, pre-ERC4626 sDAI, Compound cTokens, some wrapped-LSTs), the balance grows/shrinks over time without any transfer, and the `balanceAfter - balanceBefore` delta silently captu"
    WIKI_EXPLOIT_SCENARIO = "A yield compounder holds stETH. `harvestRewards()` snapshots `balanceBefore = stETH.balanceOf(this)`, calls `stETH.submit{value: msg.value}(...)` to restake ETH, then reads `balanceAfter` and computes `harvested = balanceAfter - balanceBefore - depositedValue`. Because stETH rebases upward at ~4% APR continuously, `balanceAfter - balanceBefore` ALREADY includes the passive rebase accrued since las"
    WIKI_RECOMMENDATION = "Use the token's share accounting, not its balance snapshot:\n\n```solidity\n// Lido: use sharesOf + getSharesByPooledEth\nuint256 sharesBefore = stETH.sharesOf(address(this));\n// ... perform operation ...\nuint256 sharesAfter = stETH.sharesOf(address(this));\nuint256 sharesHarvested = sharesAfter -"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': '(balanceBefore|preBalance|snapshot[Bb]alance|startingBalance|initial[Bb]alance)\\s*=\\s*IERC20\\s*\\(|balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*\\)'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': '(balanceAfter|postBalance|final[Bb]alance|newBalance)\\s*=\\s*IERC20\\s*\\(.*\\)\\.balanceOf|uint256\\s+[a-zA-Z_]*delta\\s*='}, {'function.body_not_contains_regex': '(sharesBefore|preShares|sharePrice|getPooledEthByShares|submit|convertToShares|convertToAssets|shares\\s*=\\s*[a-zA-Z_]+\\s*/)'}, {'function.body_not_contains_regex': '(REBASE_SAFE|non-rebase|not-rebasing|notRebase|!\\s*isRebase)'}, {'function.name_matches': 'harvest|pull|sweep|recoverFees|claim[A-Z]|accrueInterest|accrueFees|balanceDelta|rebalance|updateYield|updateRewards'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — ec-rebase-token-balance-assumption: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
