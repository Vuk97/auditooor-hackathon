"""
gauge-removal-forgets-slope-sum — generated from reference/patterns.dsl/gauge-removal-forgets-slope-sum.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py gauge-removal-forgets-slope-sum.yaml
Source: auditooor-R75-c4-yield-2024-05-olas-36
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GaugeRemovalForgetsSlopeSum(AbstractDetector):
    ARGUMENT = "gauge-removal-forgets-slope-sum"
    HELP = "Nominee removal path updates pointsSum.bias but not pointsSum.slope — future checkpoints decay from an inflated slope baseline, corrupting weights."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/gauge-removal-forgets-slope-sum.yaml"
    WIKI_TITLE = "Gauge removal updates bias but not slope, persistently corrupting vote-weight math"
    WIKI_DESCRIPTION = "Curve-fork gauge controllers store the aggregate voting curve as a (bias, slope) pair advanced on each checkpoint. When a nominee/gauge is removed, both bias and slope must decrease by that nominee's contribution. Forgetting the slope subtraction leaves the sum decaying at an inflated rate; every subsequent `_getSum()` checkpoint returns a value larger than reality. Staking incentives are distribu"
    WIKI_EXPLOIT_SCENARIO = "Olas VoteWeighting.removeNominee / revokeRemovedNomineeVotingPower: pointsSum[nextTime].bias is updated, pointsSum[nextTime].slope is not. Over the next weeks the inflated slope drains bias faster than it should, then overshoots into negative territory — relative weights of remaining nominees are miscalculated; one nominee might capture 90% of incentives instead of 10%."
    WIKI_RECOMMENDATION = "Mirror every bias write with a matching slope write. Add an invariant test: `sum(pointsWeight[n].bias) == pointsSum.bias` and `sum(pointsWeight[n].slope) == pointsSum.slope` after any add/remove/revoke, fuzzed across millions of operations."

    _PRECONDITIONS = [
        {'contract.source_matches_regex': '.*'},
        {'contract.source_matches_regex': '(?i)\\b(voteWeighting|gaugeController|veToken|votingEscrow|boostController)\\b'},
    ]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(removeNominee|removeGauge|revoke|killGauge|retireGauge)'}, {'function.writes_storage_matching': '(?i)(pointsSum|pointsWeight|points_weight)'}, {'function.body_contains_regex': '(?i)(pointsSum|points_weight)\\s*\\[[^\\]]+\\]\\.bias\\s*(=|-=|\\+=)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_body_contains_regex': '(?i)(pointsSum|points_weight)\\s*\\[[^\\]]+\\]\\.slope\\s*(=|-=)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — gauge-removal-forgets-slope-sum: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
