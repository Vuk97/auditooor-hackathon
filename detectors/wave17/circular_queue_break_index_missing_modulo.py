"""
circular-queue-break-index-missing-modulo — generated from reference/patterns.dsl/circular-queue-break-index-missing-modulo.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py circular-queue-break-index-missing-modulo.yaml
Source: auditooor-R75-code4rena-2024-04-gondi-47
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CircularQueueBreakIndexMissingModulo(AbstractDetector):
    ARGUMENT = "circular-queue-break-index-missing-modulo"
    HELP = "Circular-queue loop wraps access indices with `% N` but compares the break condition to `start + 1` without the modulo — off-by-one on the ring."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/circular-queue-break-index-missing-modulo.yaml"
    WIKI_TITLE = "Circular-queue break condition missing modulo causes oldest queue to be skipped or infinite loop"
    WIKI_DESCRIPTION = "A withdrawal-queue distributor iterates a ring buffer using `secondIdx = (idx + i) % totalQueues` for reads but uses `if (secondIdx == pendingQueueIndex + 1) break;` to terminate. When `pendingQueueIndex + 1 == totalQueues`, the wrapped secondIdx never equals `totalQueues` (it's always < totalQueues), so the loop runs an extra iteration and distributes to already-distributed queues. In the opposit"
    WIKI_EXPLOIT_SCENARIO = "Pool with 10 queues, pendingQueueIndex = 9. Loop runs from idx 9: secondIdx takes values 9, 0, 1, ..., 8. The break condition `secondIdx == 10` is never satisfied, so the loop walks every queue twice, corrupting shares accounting."
    WIKI_RECOMMENDATION = "Change break condition to `if (i != 0 && secondIdx == (pendingQueueIndex + 1) % totalQueues) break;`. Add a fuzz test sweeping `pendingQueueIndex` across all values in `[0, totalQueues]` and asserting each queue is visited exactly once."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'internal'}, {'function.body_contains_regex': '(?i)%\\s*totalQueues|%\\s*totalLength|%\\s*_length|%\\s*getMaxTotal'}, {'function.body_contains_regex': '(?i)if\\s*\\(\\s*\\w+Idx\\s*==\\s*_?\\w*Index\\s*\\+\\s*1\\s*\\)'}, {'function.body_not_contains_regex': '(?i)\\+\\s*1\\s*\\)\\s*%\\s*totalQueues|\\+\\s*1\\s*\\)\\s*%\\s*_length'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — circular-queue-break-index-missing-modulo: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
