"""
r94-loop-cross-timestamp-source-drift — generated from reference/patterns.dsl/r94-loop-cross-timestamp-source-drift.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-cross-timestamp-source-drift.yaml
Source: loop-cycle-38-cross-timestamp-sol-sibling
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopCrossTimestampSourceDrift(AbstractDetector):
    ARGUMENT = "r94-loop-cross-timestamp-source-drift"
    HELP = "r94-loop-cross-timestamp-source-drift"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-cross-timestamp-source-drift.yaml"
    WIKI_TITLE = "r94-loop-cross-timestamp-source-drift"
    WIKI_DESCRIPTION = "r94-loop-cross-timestamp-source-drift"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-cross-timestamp-source-drift"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(Pyth|publishTime|block\\.timestamp)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(?i)(getPrice|checkStaleness|validatePyth|priceFreshness|getLatestPrice)'}, {'function.source_matches_regex': 'block\\.timestamp\\s*-\\s*\\w*(publishTime|oracleTs)|(publishTime|oracleTs)\\s*-\\s*block\\.timestamp'}, {'function.not_source_matches_regex': 'Math\\.abs|SignedMath\\.abs|\\.abs\\s*\\(\\)|\nblock\\.timestamp\\s*>=\\s*\\w+|if\\s*\\(\\s*\\w+\\s*<\\s*block\\.timestamp\n'}]

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
                info = [f, f" — r94-loop-cross-timestamp-source-drift: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
