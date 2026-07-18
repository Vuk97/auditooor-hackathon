"""
a-node-exit-prevents-some-other-nodes-from-exiting-for-some-peri — generated from reference/patterns.dsl/a-node-exit-prevents-some-other-nodes-from-exiting-for-some-peri.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-node-exit-prevents-some-other-nodes-from-exiting-for-some-peri.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ANodeExitPreventsSomeOtherNodesFromExitingForSomePeri(AbstractDetector):
    ARGUMENT = "a-node-exit-prevents-some-other-nodes-from-exiting-for-some-peri"
    HELP = "A node exit prevents some other nodes from exiting for some period  Pending"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-node-exit-prevents-some-other-nodes-from-exiting-for-some-peri.yaml"
    WIKI_TITLE = "A node exit prevents some other nodes from exiting for some period  Pending"
    WIKI_DESCRIPTION = "#### Resolution\n\n\n\nSkale team’s comment:\n\n\n\n```\nknown issue, acknowledged, assigned as the work for the next few months as an improvement. Please assign as “Pending”.\n\n```\n\n\n\n#### Description\n\n\nWhen a node wants to exit, the `nodeExit` function should be called as many times, as there are schains i"
    WIKI_EXPLOIT_SCENARIO = "Per Solodit #13600: #### Resolution\n\n\n\nSkale team’s comment:\n\n\n\n```\nknown issue, acknowledged, assigned as the work for the next few months as an improvement. Please assign as “Pending”.\n\n```\n\n\n\n#### Description\n\n\nWhen"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)\\b(schain|schains|nodeExit)\\b'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.is_mutating': True}, {'function.name_matches_regex': '.*\\bnodeExit\\b.*'}, {'function.body_contains_regex': '(?i)\\b(schain|schains)\\b'}, {'function.body_contains_regex': '(?i)\\[\\s*\\w+\\s*\\]\\.length'}, {'function.body_contains_regex': '(?i)(delete\\s+\\w+\\s*\\[\\s*\\w+\\s*\\]|\\.pop\\s*\\(|cursor\\s*\\+\\=|cursor\\+\\+|\\-\\= 1|\\-\\-)'}, {'function.body_not_contains_regex': '(?i)\\bfor\\s*\\(|\\bwhile\\s*\\(|_removeAllSchains|processAllSchains|drainNodeExits'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" — a-node-exit-prevents-some-other-nodes-from-exiting-for-some-peri: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
