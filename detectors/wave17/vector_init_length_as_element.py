"""
vector-init-length-as-element — generated from reference/patterns.dsl/vector-init-length-as-element.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py vector-init-length-as-element.yaml
Source: parity-gap-closer-promoted-phase29
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class VectorInitLengthAsElement(AbstractDetector):
    ARGUMENT = "vector-init-length-as-element"
    HELP = "Dynamic array allocated as `new T[](1)` then element[0] set to a *length* value — author meant `new T[](len)`; downstream `arr[i]` OOB-reverts for i>=1."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/vector-init-length-as-element.yaml"
    WIKI_TITLE = "Array initialised with length stored as element instead of sized for length"
    WIKI_DESCRIPTION = "A dynamic array is constructed with a single slot (`new T[](1)`), and index [0] is assigned the intended length. Any subsequent indexing up to `len` reverts because the array only has one slot. The fix is `new T[](len)` (which zero-fills) followed by element writes inside a loop, or `T[] memory arr = new T[](len);`."
    WIKI_EXPLOIT_SCENARIO = "A cross-chain message handler computes `uint256 numPayloads = decodedBatch.payloads.length;`, then does `uint256[] memory out = new uint256[](1); out[0] = numPayloads;`. Downstream code does `for (uint i; i < numPayloads; ++i) process(out[i]);` — as soon as `numPayloads > 1` the loop OOB-reverts on out[1], bricking any multi-payload batch and locking funds."
    WIKI_RECOMMENDATION = "Replace `new T[](1); arr[0] = len;` with `new T[](len);` followed by an explicit loop that populates each index. Never conflate the array's *capacity* argument with an element *value*."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'new\\s+\\w+\\[\\]\\s*\\(\\s*1\\s*\\)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.body_contains_regex': 'new\\s+(uint\\d*|int\\d*|address|bytes\\d*|bool)\\s*\\[\\]\\s*\\(\\s*1\\s*\\)'}, {'function.body_contains_regex': '\\[\\s*0\\s*\\]\\s*=\\s*\\w*(len|length|size|count|total)\\w*'}, {'function.body_not_contains_regex': 'new\\s+\\w+\\[\\]\\s*\\(\\s*\\w*(len|length|size|count)\\w*\\s*\\)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — vector-init-length-as-element: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
