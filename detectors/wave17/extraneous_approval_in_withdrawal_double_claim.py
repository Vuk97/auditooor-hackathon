"""
extraneous-approval-in-withdrawal-double-claim — generated from reference/patterns.dsl/extraneous-approval-in-withdrawal-double-claim.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py extraneous-approval-in-withdrawal-double-claim.yaml
Source: solodit-novel/slice_ag
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ExtraneousApprovalInWithdrawalDoubleClaim(AbstractDetector):
    ARGUMENT = "extraneous-approval-in-withdrawal-double-claim"
    HELP = "Withdraw path calls BOTH approve(user, amount) AND transfer(user, amount). User can transferFrom again for the same allocation, doubling their withdrawal."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/extraneous-approval-in-withdrawal-double-claim.yaml"
    WIKI_TITLE = "Withdrawal uses both approve and transfer — double-claim surface"
    WIKI_DESCRIPTION = "Pull vs push patterns are mutually exclusive. A withdrawal that both transfers tokens AND leaves an allowance for the recipient effectively allows a second pull. Attackers call `withdraw` to get funds via transfer, then call `transferFrom` with the leftover allowance to pull the same amount again."
    WIKI_EXPLOIT_SCENARIO = "Vesting claim: `claim()` transfers `amount` to user, then `token.approve(user, amount)` 'in case user prefers pull'. User receives amount from transfer + uses leftover allowance to pull amount again via `transferFrom(vault, user, amount)` — draining twice their allocation. Solera-style vesting vulnerability."
    WIKI_RECOMMENDATION = "Pick one pattern: push (`transfer`) OR pull (`approve` + user calls transferFrom). Do not emit both. If legacy support for pull is needed, track claimed amount so that `transferFrom` after `transfer` reverts."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'IERC20|SafeERC20|safeTransfer|approve|transferFrom|transfer'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': 'withdraw|claim|redeem|release|disburse|exit'}, {'function.reads_msg_sender': True}, {'function.has_high_level_call_named': '^approve$'}, {'function.has_high_level_call_named': '^(transfer|safeTransfer)$'}, {'function.body_contains_regex': '(\\.approve\\s*\\(\\s*(msg\\.sender|recipient|user|account|to)\\s*,[\\s\\S]*\\.(?:transfer|safeTransfer)\\s*\\(\\s*\\2\\s*,|\\.(?:transfer|safeTransfer)\\s*\\(\\s*(msg\\.sender|recipient|user|account|to)\\s*,[\\s\\S]*\\.approve\\s*\\(\\s*\\3\\s*,)'}, {'function.body_not_contains_regex': '\\.approve\\s*\\(\\s*(msg\\.sender|recipient|user|account|to)\\s*,\\s*0\\s*\\)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — extraneous-approval-in-withdrawal-double-claim: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
