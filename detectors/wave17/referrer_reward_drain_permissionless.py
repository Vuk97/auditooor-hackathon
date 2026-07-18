"""
referrer-reward-drain-permissionless — generated from reference/patterns.dsl/referrer-reward-drain-permissionless.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py referrer-reward-drain-permissionless.yaml
Source: solodit/C0004
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ReferrerRewardDrainPermissionless(AbstractDetector):
    ARGUMENT = "referrer-reward-drain-permissionless"
    HELP = "Referral system pays a percentage to a caller-supplied referrer address with no cap, cooldown, or stability check — attacker self-references and drains the referral fee pool via dummy activity."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/referrer-reward-drain-permissionless.yaml"
    WIKI_TITLE = "Permissionless referrer reward drain: no cap, cooldown, or pointer stability"
    WIKI_DESCRIPTION = "Referral and affiliate-reward contracts commonly let the caller pass an `address referrer` (or self-register via `setReferrer`) and credit that address a percentage of the caller's activity. When there is no cap on cumulative payouts, no cooldown on how often the referrer pointer can rotate, and no sanity check that the referrer was stable before the triggering action, an attacker can set themselv"
    WIKI_EXPLOIT_SCENARIO = "A perp protocol rebates 10% of taker fees to the position-opener's `referrer`. An attacker calls `setReferrer(attackerAddr2)` from `attackerAddr1`, opens and immediately closes a max-size position, pockets ~10% of the taker fee as 'referral rebate', and repeats. Nothing in the contract caps total referrer receipts or requires the referrer pointer to be older than the trade. The referral pool drain"
    WIKI_RECOMMENDATION = "(a) Cap total receipts per referrer with a `maxReferralPerEpoch` / `referralCap`. (b) Require the referrer pointer to be set at least N blocks / seconds before any reward-bearing action (`lastReferrerChange + cooldown < block.timestamp`). (c) Enforce `referrer != msg.sender` and `referrer != tx.orig"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(referrer|referrals|referralFee|feePool|affiliate)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(setReferrer|claimReferralFee|claim|claimReferrerRewards|withdrawReferralRewards|_payReferrer|onReferral)'}, {'function.has_param_of_type': 'address'}, {'function.body_not_contains_regex': '(require\\s*\\(.*(referralCap|maxReferral|lastClaim|lastReferrerChange|block\\.timestamp\\s*[><]))'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — referrer-reward-drain-permissionless: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
