"""
agent-underlying-balance-can-be-inflated-which-cannot-be-pro-x — generated from reference/patterns.dsl/agent-underlying-balance-can-be-inflated-which-cannot-be-pro-x.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py agent-underlying-balance-can-be-inflated-which-cannot-be-pro-x.yaml
Source: code4arena audit 2025-08-flare-fasset
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AgentUnderlyingBalanceCanBeInflatedWhichCannotBeProX(AbstractDetector):
    ARGUMENT = "agent-underlying-balance-can-be-inflated-which-cannot-be-pro-x"
    HELP = "farman1094 Finding Description This issue is agent can make the payment to one of his another address, and later use this amount to top-up himself. According to the protocol, this\n"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/agent-underlying-balance-can-be-inflated-which-cannot-be-pro-x.yaml"
    WIKI_TITLE = "Agent underlying balance can be inflated, which cannot be prove-able to challenge it as illegal."
    WIKI_DESCRIPTION = "farman1094 Finding Description This issue is agent can make the payment to one of his another address, and later use this amount to top-up himself. According to the protocol, this shouldn't be happening or should be considered illegal. But the agent can able to done it that way it wouldn't be provab\n"
    WIKI_EXPLOIT_SCENARIO = "Per audit finding: farman1094 Finding Description This issue is agent can make the payment to one of his another address, and later use this amount to top-up himself. According to the protocol, this shouldn't be happeni\n"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = {'contract.has_state_var_matching': 'balance'}
    _MATCH = [{'function.name_matches': 'newRedemptionRequestId'}, {'function.kind': 'external'}, {'function.not_slither_synthetic': True}, {'function.not_in_skip_list': True}, {'function.body_not_contains_regex': {'regex': 'require\\s*\\('}}]

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
                info = [f, f" — agent-underlying-balance-can-be-inflated-which-cannot-be-pro-x: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
