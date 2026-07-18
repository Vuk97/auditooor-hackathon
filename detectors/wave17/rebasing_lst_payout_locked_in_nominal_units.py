"""
rebasing-lst-payout-locked-in-nominal-units — generated from reference/patterns.dsl/rebasing-lst-payout-locked-in-nominal-units.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py rebasing-lst-payout-locked-in-nominal-units.yaml
Source: auditooor-R75-c4-yield-2024-04-renzo-282

Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY.
"""

import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))

from _predicate_engine import eval_function_match, eval_preconditions
from _template_utils import is_leaf_helper, is_vendored_or_test_contract
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RebasingLstPayoutLockedInNominalUnits(AbstractDetector):
    ARGUMENT = "rebasing-lst-payout-locked-in-nominal-units"
    HELP = "Withdraw queue claim transfers a stored nominal rebasing-token payout instead of converting from shares at claim time."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/rebasing-lst-payout-locked-in-nominal-units.yaml"
    WIKI_TITLE = "Rebasing-token payout stored in nominal units is broken by negative rebase between request and claim"
    WIKI_DESCRIPTION = "Queue-based redemption vaults that accept rebasing LSTs commonly record the withdraw obligation as a nominal token amount. If the token rebases down between request creation and claim, the contract balance shrinks while the recorded payout stays fixed, so late claimers can be DoSed."
    WIKI_EXPLOIT_SCENARIO = "A withdraw queue records `amountToRedeem = 10e18` stETH for each request. After a negative rebase, the queue balance is lower but claim still transfers the stored nominal amount. Early claimers exit whole and a later claimer reverts on transfer."
    WIKI_RECOMMENDATION = "Store obligations in rebase-invariant units such as shares or wrap the rebasing asset at the boundary. Convert to nominal units only at claim time."

    _PRECONDITIONS = [
        {
            "contract.source_matches_regex": "(?i)(amountToRedeem|pendingAssets|request\\.amount|queued.*withdraw|withdraw.*request)"
        },
        {"contract.source_matches_regex": "(?i)contract\\s+\\w*(withdraw|redemption|claim)\\w*(queue)?"},
    ]
    _MATCH = [
        {"function.kind": "external_or_public"},
        {"function.name_matches": "(?i)^(claim|redeem|completeWithdraw|claimRedemption)$"},
        {"function.body_contains_regex": "(?i)(amountToRedeem|pendingAssets|request\\.amount)"},
        {"function.body_contains_regex": "(?i)(safeTransfer\\s*\\(|\\.transfer\\s*\\()"},
        {"function.has_high_level_call_named": "safeTransfer|transfer"},
        {"function.not_in_skip_list": True},
        {"function.not_leaf_helper": True},
        {
            "function.body_not_contains_regex": "(?i)(sharesOf\\s*\\(|getPooledEthByShares\\s*\\(|getSharesByPooledEth\\s*\\(|_convertToShares\\s*\\(|wstETH)"
        },
        {"function.not_source_matches_regex": "(?i)\\b(mock|test|fixture)"},
    ]

    _INCLUDE_LEAF_HELPERS = False
    _INVERSE_CEI = False

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if not eval_preconditions(contract, self._PRECONDITIONS):
                continue
            for function in contract.functions_and_modifiers_declared:
                if not self._INCLUDE_LEAF_HELPERS and is_leaf_helper(function):
                    continue
                if not eval_function_match(function, self._MATCH):
                    continue
                info = [
                    function,
                    " — rebasing-lst-payout-locked-in-nominal-units: pattern matched. See WIKI for details.",
                ]
                results.append(self.generate_result(info))
        return results
