"""
halborn-lrt-restake-withdrawal-queue-share-inflate — generated from reference/patterns.dsl/halborn-lrt-restake-withdrawal-queue-share-inflate.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py halborn-lrt-restake-withdrawal-queue-share-inflate.yaml
Source: auditooor-R75-halborn-Renzo-EigenLayerRestake
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class HalbornLrtRestakeWithdrawalQueueShareInflate(AbstractDetector):
    ARGUMENT = "halborn-lrt-restake-withdrawal-queue-share-inflate"
    HELP = "LRT / restaked-ETH contracts that enqueue withdrawals but leave the withdrawn value in `totalAssets()` inflate the share price for remaining depositors — new depositors are diluted, an attacker can deposit-queue-claim in a cycle capturing the dilution."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/halborn-lrt-restake-withdrawal-queue-share-inflate.yaml"
    WIKI_TITLE = "LRT total-assets not decreased when withdrawal queued — share-price inflation / donation"
    WIKI_DESCRIPTION = "Liquid restaking tokens (Renzo ezETH, EtherFi, Puffer) queue withdrawals through EigenLayer's 7-day escrow. During the queue period the underlying staked ETH is no longer available to the protocol but is still counted in `totalAssets()` / `calculateTVLs()`. Because `sharePrice = totalAssets / totalSupply`, and queued shares are burned on the ENQUEUE (decreasing supply) while assets are subtracted "
    WIKI_EXPLOIT_SCENARIO = "Renzo: vault has 10000 ETH / 10000 shares (price=1). Alice queues 1000 shares. Supply drops to 9000; totalAssets() still reads 10000 (ETH hasn't settled out of EigenLayer yet). New depositor Bob deposits 9000 ETH → receives 9000*9000/10000 = 8100 shares at the inflated price. 7 days later Alice's withdrawal completes: 1000 ETH leaves, totalAssets=18000, supply=17100 → price≈1.053. Bob's 8100 share"
    WIKI_RECOMMENDATION = "Subtract queued assets from `totalAssets()` at ENQUEUE time, not at complete: introduce `pendingWithdrawalAssets` that tracks sum of asset-equivalents scheduled to exit, and compute `sharePrice = (rawAssets - pendingWithdrawalAssets) / totalSupply`. Add pending-delta at enqueue, remove at complete. "

    _PRECONDITIONS = [{'contract.source_matches_regex': 'Restake|ezETH|ethOperator|OperatorDelegator|RestakeManager|WithdrawQueue|LRT'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'withdraw|completeWithdrawal|queueWithdrawal|claimWithdrawal|redeem'}, {'function.body_contains_regex': 'totalAssets|calculateTVLs|_getTVL|getTotalSupply|totalValueLocked|shares\\s*\\*\\s*totalAssets'}, {'function.body_contains_regex': 'queuedShares|pendingShares|withdrawalQueue|pendingWithdraw'}, {'function.body_not_contains_regex': 'totalAssets\\s*-=\\s*queuedAssets|TVL\\s*-\\s*pending|subtract.*queuedAssets|excludePending|minus\\s+queued'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — halborn-lrt-restake-withdrawal-queue-share-inflate: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
