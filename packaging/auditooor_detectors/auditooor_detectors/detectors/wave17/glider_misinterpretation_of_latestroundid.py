"""
glider-misinterpretation-of-latestroundid — generated from reference/patterns.dsl/glider-misinterpretation-of-latestroundid.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-misinterpretation-of-latestroundid.yaml
Source: glider/misinterpretation-of-latestroundid
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderMisinterpretationOfLatestroundid(AbstractDetector):
    ARGUMENT = "glider-misinterpretation-of-latestroundid"
    HELP = "Chainlink staleness guard compares `roundId >= latestRoundId` — this is tautologically true for a single latestRoundData call and does not detect stale data. Correct guard checks heartbeat against updatedAt."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-misinterpretation-of-latestroundid.yaml"
    WIKI_TITLE = "Chainlink staleness check compares roundId against latestRoundId"
    WIKI_DESCRIPTION = "`latestRoundData()` always returns the latest round, so `require(roundId >= latestRoundId)` is tautologically true and provides no staleness protection. The correct staleness guard is `require(block.timestamp - updatedAt <= HEARTBEAT, 'stale')` plus `require(answeredInRound >= roundId, 'incomplete')` to catch feeds paused mid-round."
    WIKI_EXPLOIT_SCENARIO = "Protocol uses Chainlink ETH/USD feed with a 1-hour heartbeat. Staleness check reads `(roundId, answer, , updatedAt, ) = feed.latestRoundData(); require(roundId >= latestRoundId)`. During a 3-hour ETH/USD feed outage, the protocol continues reading the pre-outage price and liquidates positions at a wildly off price."
    WIKI_RECOMMENDATION = "Use `require(block.timestamp - updatedAt <= heartbeat, 'stale')` with a heartbeat sourced from the feed's metadata. Additionally check `require(answer > 0)` and `require(answeredInRound >= roundId)`."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'latestRoundData|latestAnswer|AggregatorV3'}]
    _MATCH = [{'function.kind': 'any'}, {'function.body_contains_regex': 'latestRoundData\\s*\\(\\s*\\)'}, {'function.body_contains_regex': 'require\\s*\\(\\s*roundId\\s*>=\\s*latestRoundId|roundId\\s*==\\s*latestRoundId'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-misinterpretation-of-latestroundid: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
