"""
glider-state-array-unbounded-no-remove — generated from reference/patterns.dsl/glider-state-array-unbounded-no-remove.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-state-array-unbounded-no-remove.yaml
Source: hexens-glider/state-arrays-can-grow-in-size-with-no-way-to-shrin
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderStateArrayUnboundedNoRemove(AbstractDetector):
    ARGUMENT = "glider-state-array-unbounded-no-remove"
    HELP = "Contract appends to a storage array via .push() but never exposes a .pop() or delete path. Any caller can grow the array until iteration over it exceeds block gas, permanently DoS'ing the consumer function."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-state-array-unbounded-no-remove.yaml"
    WIKI_TITLE = "Unbounded storage array — grief via permanent growth"
    WIKI_DESCRIPTION = "When a permissionless function appends to a storage array that is later iterated (e.g., rewards distribution, validator list), and no corresponding removal path exists, an attacker can spam entries until iteration costs exceed the block gas limit. The protocol becomes permanently stuck at the growth point."
    WIKI_EXPLOIT_SCENARIO = "Contract exposes addWhitelistSlot(address) with no access control. Attacker calls it in a loop, growing whitelist to 50k entries. Subsequent distributeRewards() iterates whitelist and reverts on out-of-gas. Rewards are permanently stranded."
    WIKI_RECOMMENDATION = "Either gate the push behind access control, or provide a symmetric remove() function, or switch to a mapping + enumerable set (OpenZeppelin EnumerableSet) and charge a removal bond."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_declaration_matching': '\\[\\]\\s+(public|private|internal)?'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '\\.push\\s*\\('}, {'function.body_not_contains_regex': '\\.pop\\s*\\(|delete\\s+\\w+\\['}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-state-array-unbounded-no-remove: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
