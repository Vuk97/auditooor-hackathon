"""
a-claim-cannot-be-paid-out-or-escalated-if-the-protocol-agent-ch — generated from reference/patterns.dsl/a-claim-cannot-be-paid-out-or-escalated-if-the-protocol-agent-ch.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-claim-cannot-be-paid-out-or-escalated-if-the-protocol-agent-ch.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AClaimCannotBePaidOutOrEscalatedIfTheProtocolAgentCh(AbstractDetector):
    ARGUMENT = "a-claim-cannot-be-paid-out-or-escalated-if-the-protocol-agent-ch"
    HELP = "A claim cannot be paid out or escalated if the protocol agent changes after the claim has been initialized"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-claim-cannot-be-paid-out-or-escalated-if-the-protocol-agent-ch.yaml"
    WIKI_TITLE = "A claim cannot be paid out or escalated if the protocol agent changes after the claim has been initialized"
    WIKI_DESCRIPTION = "## Difficulty: High\n\n## Type: Data Validation\n\n## Description\nThe `escalate` and `payoutClaim` functions can be called only by the protocol agent that started the claim. Therefore, if the protocol agent role is reassigned after a claim is started, the new protocol agent will be unable to call these"
    WIKI_EXPLOIT_SCENARIO = "Per Solodit #16640: ## Difficulty: High\n\n## Type: Data Validation\n\n## Description\nThe `escalate` and `payoutClaim` functions can be called only by the protocol agent that started the claim. Therefore, if the protocol age"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.name_matches': '.*(escalate|payoutClaim).*'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.reads_state_var_matching': '.*(escalate|payoutClaim).*'}, {'function.body_not_contains_regex': '.*(accrue|update|sync|validate|check|refresh).*'}]

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
                info = [f, f" — a-claim-cannot-be-paid-out-or-escalated-if-the-protocol-agent-ch: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
