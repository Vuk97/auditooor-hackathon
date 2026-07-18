"""
r94-loop-rewards-update-after-external-transfer-reentrancy-steal — generated from reference/patterns.dsl/r94-loop-rewards-update-after-external-transfer-reentrancy-steal.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-rewards-update-after-external-transfer-reentrancy-steal.yaml
Source: solodit-35121-sherlock-notional-leveraged-vaults
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopRewardsUpdateAfterExternalTransferReentrancySteal(AbstractDetector):
    ARGUMENT = "r94-loop-rewards-update-after-external-transfer-reentrancy-steal"
    HELP = "r94-loop-rewards-update-after-external-transfer-reentrancy-steal"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-rewards-update-after-external-transfer-reentrancy-steal.yaml"
    WIKI_TITLE = "r94-loop-rewards-update-after-external-transfer-reentrancy-steal"
    WIKI_DESCRIPTION = "r94-loop-rewards-update-after-external-transfer-reentrancy-steal"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-rewards-update-after-external-transfer-reentrancy-steal"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(Vault|LeveragedVault|Pendle|Rewards|Notional)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(redeemShares|redeemVaultShares|withdrawVaultShares|exitVault|unwindPosition|closeLeveragedPosition|burnVaultShares)'}, {'function.source_matches_regex': '(transfer(From)?\\s*\\([\\s\\S]{0,200}?\\)\\s*;\\s*[\\s\\S]{0,200}?(updateAccountRewards|accrueRewardsFor|distributeRewardsFor|claimRewardDebtUpdate|syncRewardCheckpoint))'}, {'function.not_source_matches_regex': '(updateAccountRewards[\\s\\S]{0,300}?(transfer|_burn)\\s*\\(|nonReentrant|reentrancyGuard|_status\\s*=\\s*ENTERED)'}]

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
                info = [f, f" — r94-loop-rewards-update-after-external-transfer-reentrancy-steal: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
