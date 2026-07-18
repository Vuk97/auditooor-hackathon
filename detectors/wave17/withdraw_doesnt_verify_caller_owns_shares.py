"""
withdraw-doesnt-verify-caller-owns-shares — generated from reference/patterns.dsl/withdraw-doesnt-verify-caller-owns-shares.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py withdraw-doesnt-verify-caller-owns-shares.yaml
Source: solodit/access-control
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class WithdrawDoesntVerifyCallerOwnsShares(AbstractDetector):
    ARGUMENT = "withdraw-doesnt-verify-caller-owns-shares"
    HELP = "withdraw/redeem takes an owner/receiver address but never verifies msg.sender has allowance or ownership over owner's shares, allowing arbitrary accounts to drain other users."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/withdraw-doesnt-verify-caller-owns-shares.yaml"
    WIKI_TITLE = "Withdraw/redeem does not verify caller owns or is approved for owner's shares"
    WIKI_DESCRIPTION = "A withdrawal-style entry point accepts a receiver and/or owner address parameter, then burns shares from the owner and sends the underlying to the receiver, without ever checking that msg.sender is either the owner or has a nonzero allowance over owner's shares. ERC-4626 mandates the allowance check; non-4626 vaults routinely forget it."
    WIKI_EXPLOIT_SCENARIO = "Victim holds 1,000 shares of the vault. Attacker calls withdraw(1000, attacker, victim). The function burns victim's shares and transfers the underlying to attacker. All vault deposits are drainable by any EOA because the function never gated msg.sender against victim's allowance or identity."
    WIKI_RECOMMENDATION = "At the top of withdraw/redeem enforce either `require(msg.sender == owner)` or, for ERC-4626 compatibility, consume the allowance: `if (msg.sender != owner) { uint256 allowed = allowance[owner][msg.sender]; require(allowed >= shares); if (allowed != type(uint256).max) _allowances[owner][msg.sender] "

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'balances|shares|allowance|_allowances'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'withdraw|redeem|withdrawFor|redeemFor|_withdraw'}, {'function.has_param_of_type': 'address'}, {'function.body_not_contains_regex': 'msg\\.sender\\s*==\\s*(owner|account)|require\\s*\\(.*(allowance\\s*\\[|_allowances\\s*\\[|allowances\\s*\\[).*(msg\\.sender|caller)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — withdraw-doesnt-verify-caller-owns-shares: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
