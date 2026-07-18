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
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fee-billed-over-approval-allowance.yaml"
    WIKI_TITLE = "transferFrom fee path bills sender over approval amount"
    WIKI_DESCRIPTION = "When a token implements a transfer fee taken from the sender in addition to `amount`, the fee must be factored into the allowance deduction. If balance is debited by `amount + fee` but allowance is debited only by `amount`, the approver's authorization cap is effectively `amount + N*fee` for N transfers. A router or operator with a small approval can repeatedly move the victim's funds until allowa"
    WIKI_EXPLOIT_SCENARIO = "Alice approves Router for 100 TOKEN. Token charges 1% fee on transferFrom. Router calls `transferFrom(alice, bob, 100)`; Alice's balance -= 101, Alice's allowance -= 100, so allowance is now 0. Net effect: Alice was billed 101 on a 100 approval."
    WIKI_RECOMMENDATION = "When charging a fee on top of the transfer amount, deduct the full `amount + fee` from allowance, or charge the fee from the `amount` itself (recipient receives `amount - fee`). Be explicit in ERC20 docs about which party bears the fee."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(allowance|_allowances|balanceOf|_balances|transferFrom)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '^(transferFrom|_transferFrom)$'}, {'function.has_param_name_matching': '(?i)^amount$'}, {'function.body_contains_regex': '(?i)\\b(?:fee|tax|surcharge)\\b'}, {'function.body_contains_regex': '(?is)\\b(?:uint\\d+\\s+)?\\w*(?:fee|tax|surcharge)\\w*\\s*=\\s*[^;]*\\bamount\\b'}, {'function.body_contains_regex': '(?is)(?:\\b(?:totalDebit|totalAmount|amountWithFee)\\b\\s*=\\s*\\bamount\\b\\s*\\+\\s*\\w*(?:fee|tax|surcharge)\\w*\\b[\\s\\S]{0,220})?(?:_?balances?|balanceOf)\\s*\\[\\s*from\\s*\\]\\s*(?:-=|=\\s*[^;]*-)\\s*(?:\\bamount\\b\\s*\\+\\s*\\w*(?:fee|tax|surcharge)\\w*\\b|\\b(?:totalDebit|totalAmount|amountWithFee)\\b)'}, {'function.body_contains_regex': '(?is)(?:_?allowances?|allowance)\\s*\\[\\s*from\\s*\\]\\s*\\[\\s*(?:msg\\.sender|_msgSender\\(\\))\\s*\\]\\s*(?:-=|=\\s*[^;]*-)\\s*\\bamount\\b|_approve\\s*\\(\\s*from\\s*,\\s*(?:msg\\.sender|_msgSender\\(\\))\\s*,\\s*allowance\\s*\\(\\s*from\\s*,\\s*(?:msg\\.sender|_msgSender\\(\\))\\s*\\)\\s*-\\s*\\bamount\\b\\s*\\)'}, {'function.body_not_contains_regex': '(?is)(?:_?allowances?|allowance)\\s*\\[\\s*from\\s*\\]\\s*\\[\\s*(?:msg\\.sender|_msgSender\\(\\))\\s*\\]\\s*(?:-=|=\\s*[^;]*-)\\s*(?:\\bamount\\b\\s*\\+\\s*\\w*(?:fee|tax|surcharge)\\w*\\b|\\b(?:totalDebit|totalAmount|amountWithFee)\\b)|_approve\\s*\\(\\s*from\\s*,\\s*(?:msg\\.sender|_msgSender\\(\\))\\s*,\\s*allowance\\s*\\(\\s*from\\s*,\\s*(?:msg\\.sender|_msgSender\\(\\))\\s*\\)\\s*-\\s*(?:\\bamount\\b\\s*\\+\\s*\\w*(?:fee|tax|surcharge)\\w*\\b|\\b(?:totalDebit|totalAmount|amountWithFee)\\b)\\s*\\)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
