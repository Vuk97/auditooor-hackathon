"""
vesting-timewarp-underflow-dos — generated from reference/patterns.dsl/vesting-timewarp-underflow-dos.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py vesting-timewarp-underflow-dos.yaml
Source: solodit/C0091
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class VestingTimewarpUnderflowDos(AbstractDetector):
    ARGUMENT = "vesting-timewarp-underflow-dos"
    HELP = "Vesting accessor computes elapsed = block.timestamp - startTime with no lower-bound floor; panic-reverts when an admin mutates vestingRate/unlockRate/startTime mid-schedule (or time passes cliff+duration), permanently DoSing claim()."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/vesting-timewarp-underflow-dos.yaml"
    WIKI_TITLE = "Vesting time-warp underflow DoS on parameter change"
    WIKI_DESCRIPTION = "A vesting-amount accessor (claimable / releasable / _baseVested) computes elapsed time via raw `block.timestamp - startTime` arithmetic. Solidity 0.8 panics on underflow, so any condition that pushes startTime above block.timestamp — admin-updated vestingRate/startTime, cliff move, or simply running past cliff+duration without a cap — makes every subsequent call to release()/claim() revert. Distin"
    WIKI_EXPLOIT_SCENARIO = "User has a vesting schedule with startTime=T0. Admin calls setVestingRate() which recomputes startTime to T0+Δ for alignment, now greater than block.timestamp. The next call to releasable() evaluates `block.timestamp - startTime`, which underflows, panics with 0x11, and reverts. Every subsequent release() reverts identically. The vested balance is permanently DoSed until a new admin action re-alig"
    WIKI_RECOMMENDATION = "Gate every time-delta subtraction with a floor: `uint256 elapsed = block.timestamp >= startTime ? block.timestamp - startTime : 0;`. Reject admin updates that would invalidate `startTime <= block.timestamp`. Cap elapsed at `duration` before multiplying by rate so overflow of the product is not mista"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(vesting|vest|cliff|vestingRate|unlockRate|startTime)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '(_baseVested|vested|claimable|releasable|_computeVested|releasableAmount|unlockedAmount)'}, {'function.body_contains_regex': 'block\\.timestamp\\s*-\\s*\\w*(start|vestingStart|cliffEnd)|(\\w+\\s*-\\s*block\\.timestamp)|timeWarp|_timeSinceStart'}, {'function.body_not_contains_regex': 'if\\s*\\(\\s*block\\.timestamp\\s*<|require\\s*\\(\\s*block\\.timestamp\\s*>=|Math\\.min|Math\\.max|\\bunchecked\\b|\\?\\s*.*-.*:\\s*0'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — vesting-timewarp-underflow-dos: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
