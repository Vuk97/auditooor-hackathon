"""
packed-byte-counter-no-cap-overflow — generated from reference/patterns.dsl/packed-byte-counter-no-cap-overflow.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py packed-byte-counter-no-cap-overflow.yaml
Source: auditooor-R77-polymarket-MarketData-incrementQuestionCount
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PackedByteCounterNoCapOverflow(AbstractDetector):
    ARGUMENT = "packed-byte-counter-no-cap-overflow"
    HELP = "Counter packed as high byte of a bytes32 is incremented by adding 2^248 without a cap check. Overflow at 255→256 flips adjacent byte fields (e.g., a boolean flag or a fee-bps field), silently corrupting state."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/packed-byte-counter-no-cap-overflow.yaml"
    WIKI_TITLE = "Packed-byte counter wraps into adjacent field without cap check"
    WIKI_DESCRIPTION = "Gas-optimized bit-packing represents a counter as the top byte of a bytes32, incrementing by `+= (1 << 248)`. At 255, the next increment carries into byte 1 — which holds an unrelated field (often a boolean flag or a uint16). No code-level cap prevents this. Result: the 256th increment silently corrupts adjacent packed state. In NegRisk's case, the `determined` flag flips or `feeBips` corrupts; ma"
    WIKI_EXPLOIT_SCENARIO = "NegRisk market reaches 256 questions via normal prepareQuestion calls. The 256th call's incrementQuestionCount carries `questionCount=255 + 1` into byte 1, flipping `determined` from false→true. Market is now treated as resolved even though no oracle has reported. Users can redeem losing-side positions (payout=0 on CTF, but the adapter's convertPositions logic now bypasses oracle checks, potential"
    WIKI_RECOMMENDATION = "Add an explicit cap before incrementing: `require(questionCount < 255, TooManyQuestions());`. For markets that legitimately need more than 255 questions, re-pack with a wider field (uint16 for count)."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)MarketData|type\\s+\\w+\\s+is\\s+bytes32|packed\\s+layout'}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.name_matches': '(?i)increment|_?increase|_?incr'}, {'function.body_contains_regex': '(?i)\\+\\s*\\(\\s*uint256\\s*\\(\\s*1\\s*\\)\\s*<<\\s*24[0-9]\\s*\\)|\\+\\s*\\(\\s*1\\s*<<\\s*24[0-9]\\s*\\)'}, {'function.body_not_contains_regex': '(?i)require\\s*\\(\\s*\\w+\\s*<\\s*(255|type\\s*\\(\\s*uint8\\s*\\)\\.max)|if\\s*\\(\\s*\\w+\\s*>=\\s*255\\s*\\)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — packed-byte-counter-no-cap-overflow: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
