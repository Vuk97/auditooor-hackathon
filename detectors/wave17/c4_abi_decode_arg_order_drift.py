"""
c4-abi-decode-arg-order-drift — generated from reference/patterns.dsl/c4-abi-decode-arg-order-drift.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py c4-abi-decode-arg-order-drift.yaml
Source: code4arena/slice_aa-basin
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class C4AbiDecodeArgOrderDrift(AbstractDetector):
    ARGUMENT = "c4-abi-decode-arg-order-drift"
    HELP = "Wide abi.decode tuple containing adjacent small-width types (uint8 next to uint256) — one of the textbook failure modes where a mis-ordered decode silently reads wrong slots."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/c4-abi-decode-arg-order-drift.yaml"
    WIKI_TITLE = "abi.decode with wide tuple including uint8 — arg order drift risk"
    WIKI_DESCRIPTION = "When an encoder/decoder pair spans many fields AND mixes narrow (`uint8`) with wide (`uint256`/`address`) members, a single mis-ordered element produces compilable code that silently reads the wrong slot. Basin's `decimal1` swap was a concrete instance: the decoder read the reserve slot into the decimals1 position. No revert, no warning; value just corrupts."
    WIKI_EXPLOIT_SCENARIO = "Encoder writes `(reserves, decimals0, decimals1)` but decoder reads `(decimals0, decimals1, reserves)`. Pool sets `reserves = decimals1 = 18`, `decimals0 = reserves = large value`. Subsequent price calcs divide by 18-decimal scalar that's actually the raw reserve count — ratio off by 10^22."
    WIKI_RECOMMENDATION = "Define a named struct and decode into it (`abi.decode(data, (MyStruct))`). Named fields eliminate positional ambiguity. Alternatively snapshot the exact encoder sig in a comment next to the decoder."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(abi\\.decode|abi\\.encode|bytes\\s+(calldata|memory)\\s+\\w+)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_param_of_type': 'bytes'}, {'function.body_contains_regex': 'abi\\.decode\\s*\\(\\s*\\w+\\s*,\\s*\\([^)]{40,}\\)\\s*\\)'}, {'function.body_contains_regex': '(,\\s*uint8\\s*,\\s*uint256|,\\s*uint256\\s*,\\s*uint8|,\\s*uint256\\s*,\\s*address\\s*,\\s*uint8)'}, {'function.not_source_matches_regex': '(abi\\.decode\\s*\\(\\s*\\w+\\s*,\\s*\\(\\s*\\w+\\.\\w+Struct|abi\\.decode\\s*\\(\\s*\\w+\\s*,\\s*\\(\\s*[A-Z]\\w+\\s*\\)\\s*\\)|struct\\s+\\w+\\s*\\{[^}]*uint8[^}]*uint256)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}]

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
                info = [f, f" — c4-abi-decode-arg-order-drift: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
