"""
incorrect-is-source-logic — generated from reference/patterns.dsl/incorrect-is-source-logic.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py incorrect-is-source-logic.yaml
Source: zellic audit Astria Shared Sequencer April - Zellic Audit Report
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class IncorrectIsSourceLogic(AbstractDetector):
    ARGUMENT = "incorrect-is-source-logic"
    HELP = "isSource helper returns the raw sourcePort/sourceChannel prefix match for an IBC denom."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/incorrect-is-source-logic.yaml"
    WIKI_TITLE = "Incorrect isSource logic"
    WIKI_DESCRIPTION = "An IBC denom helper builds the sourcePort/sourceChannel prefix and treats a denom that starts with the prefix as source, rather than applying the polarity expected by the transfer path."
    WIKI_EXPLOIT_SCENARIO = "A prefixed IBC voucher denom reaches a helper whose source/native classification is inverted by returning the raw prefix match. Downstream transfer logic can then execute the wrong branch for the asset origin."
    WIKI_RECOMMENDATION = "Apply the ICS-20 source-prefix polarity expected by the transfer path and cover both prefixed and unprefixed denoms in tests."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(isSource|is_source|sourcePort|sourceChannel|denom)'}]
    _MATCH = [{'function.name_matches': '(?i)\\b(isSource|is_source|fromDenom|from_denom)\\b'}, {'function.body_contains_regex': '(?i)string\\.concat\\s*\\([^;{}]*source_?port[^;{}]*["\']\\/["\'][^;{}]*source_?channel[^;{}]*["\']\\/["\']'}, {'function.body_contains_regex': '(?i)(startsWith|starts_with|hasPrefix|has_prefix)\\s*\\(\\s*(denom|fromDenom|from_denom)[^,]*,\\s*(prefix|sourcePrefix|pathPrefix)'}, {'function.body_not_contains_regex': '(?i)(return\\s*\\(?\\s*!|is_?source\\s*=\\s*!)(startsWith|starts_with|hasPrefix|has_prefix)\\s*\\('}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — incorrect-is-source-logic: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
