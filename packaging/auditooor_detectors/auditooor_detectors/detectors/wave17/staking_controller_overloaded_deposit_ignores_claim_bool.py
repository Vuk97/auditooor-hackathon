"""
staking-controller-overloaded-deposit-ignores-claim-bool — generated from reference/patterns.dsl/staking-controller-overloaded-deposit-ignores-claim-bool.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py staking-controller-overloaded-deposit-ignores-claim-bool.yaml
Source: lisa-mine-r99-case-02827-sherlock-sentiment-2022-11
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class StakingControllerOverloadedDepositIgnoresClaimBool(AbstractDetector):
    ARGUMENT = "staking-controller-overloaded-deposit-ignores-claim-bool"
    HELP = "Staking controller's `canCall` dispatcher routes the `deposit(uint256,address,bool)` / `withdraw(uint256,address,bool)` selectors to the `canDepositAndClaim` / `canWithdrawAndClaim` paths without first decoding the `bool _claim_rewards` argument. Anyone calling `deposit(amt, target, false)` (full-ar"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/staking-controller-overloaded-deposit-ignores-claim-bool.yaml"
    WIKI_TITLE = "Staking controller routes claim-flagged selectors without decoding the bool"
    WIKI_DESCRIPTION = "Pattern fires on `canCall` dispatcher functions that select between `canDeposit` / `canDepositAndClaim` based ONLY on the 4-byte function selector (e.g. `0x83df6747` for `deposit(uint256,address,bool)`). The full-arity selector covers BOTH `claim=true` and `claim=false` invocations; without decoding the bool from `data[36+]`, the controller treats every full-arity call as a 'deposit and claim', in"
    WIKI_EXPLOIT_SCENARIO = "A Sentiment user calls the underlying gauge's `deposit(amt, accountAddr, false)`. Sentiment's `canCall` sees the full-arity selector, dispatches to `canDepositAndClaim`, returns a `tokensIn` array containing CRV / BAL / etc. reward tokens plus the gauge token. The risk engine credits the user's account as if those reward tokens had arrived. The user's collateralisation ratio appears better than it"
    WIKI_RECOMMENDATION = "In `canCall`, decode the bool argument when the full-arity selector hits: `(, , bool claim) = abi.decode(data[4:], (uint256, address, bool));`. Branch on `claim` to choose between `canDeposit` (just the gauge token) and `canDepositAndClaim` (gauge + rewards). Add a unit test that calls the dispatche"

    _PRECONDITIONS = [{'contract.has_state_var_matching': 'DEPOSIT|DEPOSITCLAIM|WITHDRAWCLAIM|CLAIM'}, {'contract.has_function_matching': 'canCall|canDepositAndClaim|canWithdrawAndClaim'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^canCall$'}, {'function.body_contains_regex': 'sig\\s*==\\s*DEPOSITCLAIM|sig\\s*==\\s*WITHDRAWCLAIM'}, {'function.body_not_contains_regex': 'abi\\.decode\\s*\\(\\s*data\\s*\\[\\s*4\\s*:\\s*\\][^)]*bool\\s*\\)|claimFlag\\s*=|_claim_rewards\\s*='}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" — staking-controller-overloaded-deposit-ignores-claim-bool: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
