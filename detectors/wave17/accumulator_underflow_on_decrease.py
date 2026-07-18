"""
accumulator-underflow-on-decrease — generated from reference/patterns.dsl/accumulator-underflow-on-decrease.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py accumulator-underflow-on-decrease.yaml
Source: solodit/cross-cluster-accumulator-underflow
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AccumulatorUnderflowOnDecrease(AbstractDetector):
    ARGUMENT = "accumulator-underflow-on-decrease"
    HELP = "External/public function decrements a balance/supply accumulator with -= but has no saturation guard (unchecked / SafeMath / >= precondition / Math.min / ternary). Out-of-order events or parameter changes can panic-revert on underflow and brick the accounting path."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/accumulator-underflow-on-decrease.yaml"
    WIKI_TITLE = "Accumulator underflow on decrease: unguarded -= on totalSupply / totalAssets / totalStaked"
    WIKI_DESCRIPTION = "The function subtracts from a protocol-wide accumulator (totalSupply, totalAssets, totalDeposited, totalStaked, totalLocked, or a generic `accumulator`) using -= without first asserting the running total is large enough. In Solidity >=0.8, any underflow panic-reverts, permanently bricking this code path. The bug typically manifests after an admin parameter change, a reward-rate recalibration, or a"
    WIKI_EXPLOIT_SCENARIO = "A staking contract tracks totalStaked. Admin raises the reward rate and calls a migration helper that reduces each user's recorded stake by a scaling factor, decrementing totalStaked once per user. Because no saturation guard or `>=` precondition exists and the migration rounds differently than the original deposits did, one loop iteration tries to subtract more than the running total. The tx reve"
    WIKI_RECOMMENDATION = "Always guard accumulator decrements. Either (a) wrap the write in `if (acc >= x) { acc -= x; } else { acc = 0; }`, (b) use `acc -= Math.min(acc, x)` for saturating subtraction, (c) revert with an explicit custom error that surfaces the mismatch, or (d) restructure the flow so decrement cannot exceed"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(totalSupply|totalAssets|totalDeposited|totalStaked|totalLocked|accumulator|total)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': {'regex': 'total(Supply|Assets|Deposited|Staked|Locked)\\s*-=|accumulator\\s*-='}}, {'function.body_not_contains_regex': 'unchecked|SafeMath|if\\s*\\(.*total\\w+\\s*>=|Math\\.min|Math\\.max|\\?\\s*.*-.*:\\s*0'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — accumulator-underflow-on-decrease: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
