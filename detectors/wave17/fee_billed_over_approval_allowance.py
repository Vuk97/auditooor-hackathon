"""
fee-billed-over-approval-allowance — generated from reference/patterns.dsl/fee-billed-over-approval-allowance.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fee-billed-over-approval-allowance.yaml
Source: code4arena/slice_ab-NextGen-M01
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FeeBilledOverApprovalAllowance(AbstractDetector):
    ARGUMENT = "fee-billed-over-approval-allowance"
    HELP = "ERC-20 transferFrom charges a fee by deducting `amount + fee` from the `from` balance but decrements `allowance` by only `amount`. An approver authorized amount X but is billed X+fee; repeated calls drain beyond the approval."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fee-billed-over-approval-allowance.yaml"
    WIKI_TITLE = "transferFrom fee path bills sender over approval amount"
    WIKI_DESCRIPTION = "When a token implements a transfer fee taken from the sender in addition to `amount`, the fee must be factored into the allowance deduction. If balance is debited by `amount + fee` but allowance is debited only by `amount`, the approver's authorization cap is effectively `amount + N*fee` for N transfers. A router or operator with a small approval can repeatedly move the victim's funds until allowa"
    WIKI_EXPLOIT_SCENARIO = "Alice approves Router for 100 TOKEN. Token charges 1% fee on transferFrom. Router calls `transferFrom(alice, bob, 100)`; Alice's balance -= 101, Alice's allowance -= 100, so allowance is now 0. Net effect: Alice was billed 101 on a 100 approval."
    WIKI_RECOMMENDATION = "When charging a fee on top of the transfer amount, deduct the full `amount + fee` from allowance, or charge the fee from the `amount` itself (recipient receives `amount - fee`). Be explicit in ERC20 docs about which party bears the fee."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(fee|Fee|surcharge|tax)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(transferFrom|_transferFrom|_transfer)$'}, {'function.body_contains_regex': 'fee|surcharge|tax'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': 'balance\\w*\\s*\\[\\s*(from|sender)\\s*\\]\\s*-=\\s*(amount\\s*\\+\\s*fee|totalAmount|total|amountWithFee)|balanceOf\\s*\\[\\s*(from|sender)\\s*\\]\\s*-=\\s*(amount\\s*\\+|\\w*fee)'}, {'function.body_contains_regex': '_approve\\s*\\(\\s*\\w+\\s*,\\s*\\w+\\s*,\\s*allowance\\s*\\(\\s*\\w+\\s*,\\s*\\w+\\s*\\)\\s*-\\s*amount\\s*\\)|allowance\\s*\\[\\s*\\w+\\s*\\]\\s*\\[\\s*\\w+\\s*\\]\\s*-=\\s*amount'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fee-billed-over-approval-allowance: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
