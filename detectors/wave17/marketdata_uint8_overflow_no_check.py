"""
marketdata-uint8-overflow-no-check — generated from reference/patterns.dsl/marketdata-uint8-overflow-no-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py marketdata-uint8-overflow-no-check.yaml
Source: auditooor-R77-polymarket-MarketDataLib-incrementQuestionCount
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MarketdataUint8OverflowNoCheck(AbstractDetector):
    ARGUMENT = "marketdata-uint8-overflow-no-check"
    HELP = "MarketData.incrementQuestionCount adds 1 to byte[0] without overflow guard; 256th question wraps count to 0."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/marketdata-uint8-overflow-no-check.yaml"
    WIKI_TITLE = "MarketData uint8 overflow at 256th question"
    WIKI_DESCRIPTION = "MarketData is a bytes32 user-defined type where byte[0] holds questionCount as a uint8. The incrementQuestionCount function does `data = bytes32(uint256(data) + 1)` without checking if byte[0] is already 0xFF. On the 256th increment the count wraps to 0, corrupting market state."
    WIKI_EXPLOIT_SCENARIO = "A NegRisk market is configured with 255 questions. The 256th call to prepareMarket silently wraps questionCount to 0. All downstream logic that relies on questionCount (position arrays, payout validation) operates on the wrong cardinality, leading to out-of-bounds reads or invalid payout assertions."
    WIKI_RECOMMENDATION = "Add `require(uint256(uint8(data[0])) < 255, ...)` before incrementing, or use a uint16 for questionCount."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)incrementQuestionCount|MarketDataLib|MarketData'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '(?i)incrementQuestionCount'}, {'function.body_contains_regex': '(?i)bytes32\\(uint256\\(data\\)\\s*\\+\\s*INCREMENT\\)|bytes32\\(uint256\\(data\\)\\s*\\+\\s*1\\)'}, {'function.body_not_contains_regex': '(?i)require\\s*\\([^)]*255|require\\s*\\([^)]*0xFF|uint8.*<\\s*255|uint8.*<=\\s*254'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" — marketdata-uint8-overflow-no-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
