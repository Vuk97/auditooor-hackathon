"""
zero-sentinel-for-signed-epoch-counter-enables-replay-rollover — generated from reference/patterns.dsl/zero-sentinel-for-signed-epoch-counter-enables-replay-rollover.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py zero-sentinel-for-signed-epoch-counter-enables-replay-rollover.yaml
Source: auditooor-R76-c4-intuition-bug-bounty-54-17
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ZeroSentinelForSignedEpochCounterEnablesReplayRollover(AbstractDetector):
    ARGUMENT = "zero-sentinel-for-signed-epoch-counter-enables-replay-rollover"
    HELP = "Epoch rollover uses `== 0` as sentinel on a SIGNED counter; deposits+redeems that net to zero allow rollover to fire a second time in the same epoch, corrupting utilization/emissions."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/zero-sentinel-for-signed-epoch-counter-enables-replay-rollover.yaml"
    WIKI_TITLE = "Signed per-epoch counter uses zero-as-sentinel → mid-epoch zero-crossing replays rollover"
    WIKI_DESCRIPTION = "An accumulator `mapping(uint=>int) counter[]` is rolled forward on the first operation in a new epoch via `if (counter[epoch] == 0) counter[epoch] = counter[epoch-1]`. Because the counter is SIGNED and active users can move it through zero (deposit cancels redeem, or vice versa), any subsequent call sees `counter[epoch] == 0` again and copies the previous epoch's value in a second time. The per-US"
    WIKI_EXPLOIT_SCENARIO = "Epoch N-1 ends with counter=1000. Alice deposits 500 → rollover copies 1000, counter=1500. Bob redeems 1500 → counter=0 legitimately. Charlie deposits 100 → rollover fires AGAIN, copies 1000, counter=1100. True delta should be +100, but reward computation sees +1100 and distributes inflated emissions. Repeatable by any address with capital to cycle deposit/redeem."
    WIKI_RECOMMENDATION = "Replace the zero-value sentinel with an explicit `mapping(uint => bool) epochRolledOver` flag set on the first rollover per epoch. Alternatively, record rollover state in a packed tuple (amount + initialized bit). Never conflate `value == 0` with `not yet initialised` for signed accumulators."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(?i)(totalUtilization|epochAccumulator|systemUtilization|bond(ing)?Total|personalUtilization)'}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.name_matches': '(?i)_?rollover|_?syncEpoch|_?carryForward|_?transitionEpoch'}, {'function.body_contains_regex': '(?i)\\[currentEpoch[a-zA-Z_]*\\]\\s*==\\s*0'}, {'function.body_not_contains_regex': '(?i)epochInitialized|isRolledOver|rolledOver\\[|_epochFlag|hasRolledOver'}, {'function.reads_storage_matching': '(?i)totalUtilization|systemUtilization|epochAccumulator'}, {'function.writes_storage_matching': '(?i)totalUtilization|systemUtilization|epochAccumulator'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — zero-sentinel-for-signed-epoch-counter-enables-replay-rollover: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
