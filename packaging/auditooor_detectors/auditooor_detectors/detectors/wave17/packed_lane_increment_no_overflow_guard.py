"""
packed-lane-increment-no-overflow-guard — generated from reference/patterns.dsl/packed-lane-increment-no-overflow-guard.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py packed-lane-increment-no-overflow-guard.yaml
Source: polymarket-draft-7
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PackedLaneIncrementNoOverflowGuard(AbstractDetector):
    ARGUMENT = "packed-lane-increment-no-overflow-guard"
    HELP = "Packed-lane bitmap counter is incremented (`slot += INCREMENT`, `<<=`, `slot[i]++`) without a `< type(uintN).max` guard — at lane-max the next call panics (0x11) on solc >=0.8 or silently carries into the neighbouring lane on pre-0.8/unchecked code, permanently bricking the function."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/packed-lane-increment-no-overflow-guard.yaml"
    WIKI_TITLE = "Packed-lane increment with no lane-max guard — DoS on Nth call (Polymarket Draft 7)"
    WIKI_DESCRIPTION = "An external/public function on a contract whose name encodes packed-storage semantics (MarketData / Packed / Bitmap / Layout / Registry / Storage) increments a fixed-width lane inside a packed uint256 slot. The body uses bit-shift literals, in-place shift-assignments, bitmask operations, or slot[i] indexing as packed-lane indicators, and provides no recognised lane-max guard (no `require(... < typ"
    WIKI_EXPLOIT_SCENARIO = "Polymarket NegRiskAdapter — `MarketDataLib.incrementQuestionCount` packs questionCount into byte 0 of a bytes32 MarketData slot. Constant `INCREMENT = uint256(bytes32(bytes1(0x01))) = 2^248` is added on every `prepareQuestion`. After 255 prepareQuestion calls on a single market, the questionCount byte holds 0xFF. The 256th call computes `0xFF + 0x01 = 0x100` — under solc 0.8.x checked arithmetic t"
    WIKI_RECOMMENDATION = "Add an explicit lane-max guard before the increment, e.g. `require(uint8(_data) < type(uint8).max, MaxQuestionsExceeded())` (or `< 255` for clarity). Emit a typed custom error so integrators see the actual constraint instead of a cryptic Panic(0x11). Alternatively, widen the lane (uint16 / uint32) i"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(MarketData|Packed|Bitmap|Layout|Registry|Storage)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(_?increment[A-Z]\\w*|_?advance[A-Z]\\w*|_?bump[A-Z]\\w*|_?_add1)$'}, {'function.body_contains_regex': '(?i)(<<\\s*\\d+|>>\\s*\\d+|bitand|<<=|>>=|mask|slot\\[\\d+\\])'}, {'function.body_not_contains_regex': '(?i)(<\\s*(?:type\\s*\\(\\s*uint8\\s*\\)|type\\s*\\(\\s*uint16\\s*\\)|255|65535|MAX_LANE)|==\\s*type\\s*\\(\\s*uint8\\s*\\)\\.max|Panic|OVERFLOW|overflowCheck)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — packed-lane-increment-no-overflow-guard: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
