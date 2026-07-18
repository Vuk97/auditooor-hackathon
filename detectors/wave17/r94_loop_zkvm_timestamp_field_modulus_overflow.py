"""
r94-loop-zkvm-timestamp-field-modulus-overflow — generated from reference/patterns.dsl/r94-loop-zkvm-timestamp-field-modulus-overflow.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-zkvm-timestamp-field-modulus-overflow.yaml
Source: solodit-53416-cantina-openvm
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopZkvmTimestampFieldModulusOverflow(AbstractDetector):
    ARGUMENT = "r94-loop-zkvm-timestamp-field-modulus-overflow"
    HELP = "r94-loop-zkvm-timestamp-field-modulus-overflow"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-zkvm-timestamp-field-modulus-overflow.yaml"
    WIKI_TITLE = "r94-loop-zkvm-timestamp-field-modulus-overflow"
    WIKI_DESCRIPTION = "r94-loop-zkvm-timestamp-field-modulus-overflow"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-zkvm-timestamp-field-modulus-overflow"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(BabyBear|Goldilocks|Mersenne31|zkVM|VmState|Stark|ZkVerifier|OpenVM)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(incrementTimestamp|advanceTimestamp|nextStep|tick|incrementClock|updatePc|updateStep)'}, {'function.source_matches_regex': '(BabyBear|Goldilocks|Mersenne31|timestamp\\s*:\\s*F\\b|step\\s*:\\s*F\\b|clock\\s*:\\s*F\\b)'}, {'function.not_source_matches_regex': '(rangeCheck|range_check|checked_add|require\\s*\\(\\s*\\w*(timestamp|step|clock)\\s*<\\s*\\w*(MAX|BOUND|LIMIT)|lessThanCheck|boundCheck)'}]

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
                info = [f, f" — r94-loop-zkvm-timestamp-field-modulus-overflow: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
