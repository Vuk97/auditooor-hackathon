"""
r94-loop-oracle-confidence-negative-accept — generated from reference/patterns.dsl/r94-loop-oracle-confidence-negative-accept.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-oracle-confidence-negative-accept.yaml
Source: loop-cycle-14-oracle-confidence-negative-sol-sibling
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopOracleConfidenceNegativeAccept(AbstractDetector):
    ARGUMENT = "r94-loop-oracle-confidence-negative-accept"
    HELP = "r94-loop-oracle-confidence-negative-accept"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-oracle-confidence-negative-accept.yaml"
    WIKI_TITLE = "r94-loop-oracle-confidence-negative-accept"
    WIKI_DESCRIPTION = "r94-loop-oracle-confidence-negative-accept"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-oracle-confidence-negative-accept"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(Pyth|PriceFeed|\\bconf\\b|confidence)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(?i)(updateIndex|updatePrice|validatePrice|checkFluctuation)'}, {'function.source_matches_regex': '(\\w+\\s*-\\s*\\w+)\\s*[<>]\\s*\\w+\\.conf|\ndelta\\s*[<>]\\s*\\w+\\.(conf|confidence)\n'}, {'function.not_source_matches_regex': '\\.abs\\s*\\(\\)|SignedMath\\.abs|\\babs\\s*\\(\\s*\\w\n'}]

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
                info = [f, f" — r94-loop-oracle-confidence-negative-accept: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
