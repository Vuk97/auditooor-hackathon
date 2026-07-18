"""
r94-reverse-withdraw-transfer-failure-swallowed — generated from reference/patterns.dsl/r94-reverse-withdraw-transfer-failure-swallowed.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-reverse-withdraw-transfer-failure-swallowed.yaml
Source: reverse-port-from-rust_wave1
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94ReverseWithdrawTransferFailureSwallowed(AbstractDetector):
    ARGUMENT = "r94-reverse-withdraw-transfer-failure-swallowed"
    HELP = "NOT_SUBMIT_READY detector-fixture-smoke-only: withdraw / redeem / liquidate swallows a low-level transfer failure (no require(success)) AND then decrements user accounting."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-reverse-withdraw-transfer-failure-swallowed.yaml"
    WIKI_TITLE = "Swallowed transfer failure while accounting is debited in withdraw path"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. A withdraw/redeem path performs a low-level transfer attempt but does not enforce success, then debits user accounting in the same function body."
    WIKI_EXPLOIT_SCENARIO = "Fixture row scenario: `(bool success,) = to.call{value: amount}(\"\");` executes, success is not required, then `balances[msg.sender] -= amount` still runs. No corpus-backed exploit claim is made in this row."
    WIKI_RECOMMENDATION = "Require low-level transfer success (`require(ok, 'transfer failed')`) before mutating user balances/collateral/shares, and keep row posture as detector-fixture-smoke-only until corpus-backed evidence is added."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(withdraw|redeem|seize|liquidate|pullFunds)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(withdraw|_withdraw|redeem|_redeem|liquidate|_liquidate|seize|pullFunds|emergencyWithdraw|claimAndWithdraw)$'}, {'function.body_contains_regex': '(\\.call\\s*\\{[^}]*\\}\\s*\\([^)]*\\)|\\(bool\\s+\\w+\\s*,\\s*\\)\\s*=|try\\s+\\w+[\\s\\S]{1,200}\\.transfer\\(|try\\s+\\w+[\\s\\S]{1,200}\\.send\\(|_safeTokenTransfer|\\.send\\(|tryTransfer)'}, {'function.body_not_contains_regex': '(require\\s*\\(\\s*\\w*success\\w*|require\\s*\\(\\s*\\w*ok\\w*|if\\s*\\(\\s*!\\s*\\w*success\\w*\\s*\\)\\s*revert|if\\s*\\(\\s*!\\s*\\w*ok\\w*\\s*\\)\\s*revert|if\\s*\\(\\s*!\\s*\\w*success\\w*\\s*\\)\\s*return|safeTransfer|SafeERC20)'}, {'function.body_contains_regex': '(balanceOf\\[[^\\]]+\\]\\s*-=|balances\\[[^\\]]+\\]\\s*-=|collateral\\[[^\\]]+\\]\\s*-=|shares\\[[^\\]]+\\]\\s*-=|principal\\[[^\\]]+\\]\\s*-=|userCollateral\\[[^\\]]+\\]\\s*=|_burn\\s*\\()'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — r94-reverse-withdraw-transfer-failure-swallowed: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
