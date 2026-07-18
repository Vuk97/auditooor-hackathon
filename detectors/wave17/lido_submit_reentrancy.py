"""
lido-submit-reentrancy — generated from reference/patterns.dsl/lido-submit-reentrancy.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py lido-submit-reentrancy.yaml
Source: solodit-cluster/cross-cluster-lido-integration
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LidoSubmitReentrancy(AbstractDetector):
    ARGUMENT = "lido-submit-reentrancy"
    HELP = "Payable function forwards ETH into Lido.submit() (or WithdrawalQueue.requestWithdrawals) while updating its own shares/accounting mapping without a nonReentrant guard, exposing cross-function reentrancy."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/lido-submit-reentrancy.yaml"
    WIKI_TITLE = "Lido submit() integration without reentrancy guard"
    WIKI_DESCRIPTION = "A payable external/public function calls into Lido's `submit()` (or the withdrawal queue) to stake ETH and then updates the contract's own share or balance bookkeeping. Because the external call crosses a trust boundary into a contract that can itself route back via receivers or proxied handlers, and because the function is missing `nonReentrant`, an attacker that can influence any of the re-entry"
    WIKI_EXPLOIT_SCENARIO = "A staking wrapper's `deposit()` is `payable`, calls `Lido.submit{value: msg.value}(referral)`, and then writes `shares[msg.sender] += computedShares`. If any hook or subsequent `transfer`/`call` on the same transaction yields control back (e.g., via a router, a Permit2-style callback, or a token-hook the contract itself exposes), the attacker re-enters `deposit()` observing the pre-update `shares["
    WIKI_RECOMMENDATION = "Add `nonReentrant` (OpenZeppelin ReentrancyGuard or an equivalent lock modifier) to every payable function that forwards value into Lido.submit or the withdrawal queue. Additionally, apply strict CEI ordering: compute the share amount, write the shares/balances mapping, and only then perform the ext"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_payable': True}, {'function.body_contains_regex': 'Lido\\.submit|lido\\.submit|ILido\\.submit|stETH\\.submit|WithdrawalQueue\\.requestWithdrawals'}, {'function.has_high_level_call_named': '(?i)^(submit|requestWithdrawals|requestWithdrawal|claimWithdrawal)$'}, {'function.has_modifier': {'includes': ['nonReentrant', 'reentrancyGuard', 'lock'], 'negate': True}}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — lido-submit-reentrancy: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
