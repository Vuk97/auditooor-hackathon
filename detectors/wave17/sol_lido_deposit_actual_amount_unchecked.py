"""
sol-lido-deposit-actual-amount-unchecked — generated from reference/patterns.dsl/sol-lido-deposit-actual-amount-unchecked.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py sol-lido-deposit-actual-amount-unchecked.yaml
Source: solodit-cluster-C0079-Lido
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SolLidoDepositActualAmountUnchecked(AbstractDetector):
    ARGUMENT = "sol-lido-deposit-actual-amount-unchecked"
    HELP = "Lido EL-rewards/deposit path trusts a cached pooledEth snapshot instead of a before/after balance diff."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/sol-lido-deposit-actual-amount-unchecked.yaml"
    WIKI_TITLE = "Lido integration trusts cached pooled-ether vs actual balance"
    WIKI_DESCRIPTION = "Lido exposes `getTotalPooledEther()` which updates on oracle report, not on raw ETH receipt. Integrations that convert shares via this snapshot miss reward ETH sitting in the EL-rewards vault that has not yet been reported, and — on the other side — can double-count if they don't compare with the actual contract balance."
    WIKI_EXPLOIT_SCENARIO = "LID-12 (Lido audit): vault receive-rewards path used cached shares × ratio; when actual vault balance deviated due to slashing between report and execution, user withdraw was under- or over-paid. Extending: puffETH 38271 couldn't redeem when lidoLockedETH drifted from actual."
    WIKI_RECOMMENDATION = "Measure `address(lidoVault).balance` before and after the transfer, use the diff as the canonical received amount. Also revalidate shares × pooledEth against raw ETH after any oracle-update block."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'Lido|stETH|ILido|LidoExecutionLayerRewardsVault|IStETH'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': 'getTotalPooledEther|getPooledEthByShares|ILidoExecutionLayerRewardsVault|receiveELRewards'}, {'function.body_not_contains_regex': 'address\\s*\\(\\s*this\\s*\\)\\.balance|_balanceBefore|actualReceived|balanceDiff'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — sol-lido-deposit-actual-amount-unchecked: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
