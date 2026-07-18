"""
lido-el-rewards-amount-unchecked — generated from reference/patterns.dsl/lido-el-rewards-amount-unchecked.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py lido-el-rewards-amount-unchecked.yaml
Source: solodit/LID-12-lido-el-rewards
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LidoElRewardsAmountUnchecked(AbstractDetector):
    ARGUMENT = "lido-el-rewards-amount-unchecked"
    HELP = "Lido-style EL rewards intake trusts the amount reported by `LidoExecutionLayerRewardsVault.withdrawRewards` without asserting it matches the actual balance delta. A bug or compromised vault can over/under-report, silently corrupting the protocol's reward accounting (Lido audit finding LID-12)."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/lido-el-rewards-amount-unchecked.yaml"
    WIKI_TITLE = "Lido EL rewards intake does not cross-check amount vs vault balance delta"
    WIKI_DESCRIPTION = "When a staking protocol withdraws execution-layer rewards from a dedicated rewards vault, the receiving function typically accepts the amount as a parameter OR reads it from the external call's return. The correct pattern measures the vault's native balance before and after the call and asserts they match. A buggy implementation trusts the reported value, so any accounting drift inside the vault ("
    WIKI_EXPLOIT_SCENARIO = "A compromised `LidoExecutionLayerRewardsVault` implementation returns `_withdrawRewards` = 10 ETH but actually transfers only 9 ETH. The staking contract's `handleELRewards(10 ether)` callback credits 10 ETH of rewards to the share price. stETH supply inflates by 1 ETH of phantom rewards. Every redemption afterward is under-collateralised. The opposite direction — report 10 ETH, send 11 ETH — leav"
    WIKI_RECOMMENDATION = "Before calling `withdrawRewards`, record `balanceBefore = address(this).balance`. After the call, assert `address(this).balance - balanceBefore == reportedAmount`. Equivalently, ignore the reported parameter and use the balance delta directly for all downstream accounting. For ERC-20 variants, do th"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'LidoExecutionLayerRewardsVault|ExecutionLayerRewardsVault|receiveELRewards|elRewards'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(receiveELRewards|handleELRewards|processELRewards|withdrawELRewards|_receiveELRewards)[A-Za-z0-9_]*'}, {'function.body_contains_regex': 'ExecutionLayer|ELVault|elRewards|RewardsVault'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*received\\s*==\\s*|require\\s*\\(\\s*balance[Bb]efore|actual\\s*==\\s*expected|balanceAfter\\s*-\\s*balanceBefore|preBalance|postBalance'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — lido-el-rewards-amount-unchecked: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
