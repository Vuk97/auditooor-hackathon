"""
vesting-schedule-underflow-freeze — generated from reference/patterns.dsl/vesting-schedule-underflow-freeze.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py vesting-schedule-underflow-freeze.yaml
Source: solodit/C0086
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class VestingScheduleUnderflowFreeze(AbstractDetector):
    ARGUMENT = "vesting-schedule-underflow-freeze"
    HELP = "Vesting-amount accessor performs raw subtraction against a time/accumulator that can underflow after parameter change (vestingRate reduction, cliff move) — panics on Solidity 0.8 and permanently freezes tokens."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/vesting-schedule-underflow-freeze.yaml"
    WIKI_TITLE = "Vesting schedule underflow freezes vested tokens"
    WIKI_DESCRIPTION = "Vesting contracts that compute the currently vested amount via raw subtraction (e.g., `elapsed = now - start`, `remaining = total - claimed`) will panic-revert on Solidity 0.8 when admin-controlled parameters (vestingRate, cliff, start) are updated to values that make the minuend smaller than the subtrahend. Because the accessor is used by release()/claim(), ALL subsequent withdrawals revert and t"
    WIKI_EXPLOIT_SCENARIO = "Admin reduces vestingRate mid-schedule. The recomputed `totalVested` is now smaller than `claimed`. The next call to `releasable()` executes `totalVested - claimed`, which underflows, panics with 0x11, and reverts. Every future release() call reverts identically. The user's remaining entitlement is permanently frozen in the contract. Variant: the subtrahend is `block.timestamp - start` where `star"
    WIKI_RECOMMENDATION = "Wrap the subtraction in a saturating helper: `return a >= b ? a - b : 0;`, or reject admin updates that would invalidate the invariant `totalVested >= claimed`. Never use raw subtraction in a user-facing accessor whose inputs can be modified after construction."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(vesting|vested|vest|cliff|vestingSchedule)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '(vested|releasable|available|claimable|_baseVested|vestedAmount|calculateVested)'}, {'function.body_contains_regex': {'regex': '(block\\.timestamp|now|totalVested|unlocked|start|cliff|vestingRate)\\s*-\\s*'}}, {'function.body_not_contains_regex': '(unchecked\\s*\\{|SafeMath|subCap|saturat|Math\\.max|\\?\\s*.*-.*:\\s*0|if\\s*\\(.*<.*\\)\\s*(return\\s+0|return;))'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — vesting-schedule-underflow-freeze: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
