"""
lockup-bypass-zero-duration — generated from reference/patterns.dsl/lockup-bypass-zero-duration.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py lockup-bypass-zero-duration.yaml
Source: solodit/C0111
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LockupBypassZeroDuration(AbstractDetector):
    ARGUMENT = "lockup-bypass-zero-duration"
    HELP = "Lock / stake-and-lock / admin lockup-setter writes a lock-duration storage field without validating the supplied duration is within [min, max] and non-zero; admin can brick every user's unlock path by setting it to 0, or trap every deposit forever by setting it to uint256.max."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/lockup-bypass-zero-duration.yaml"
    WIKI_TITLE = "Lockup duration written without range check — bypass or permanent freeze"
    WIKI_DESCRIPTION = "Staking, vesting, and governance lockup contracts expose either (a) user entry points that accept a user-supplied lock duration, or (b) privileged setters that mutate the global lockupTime / lockPeriod / unlockTime storage. When these functions write the duration without a require(duration >= MIN && duration <= MAX) guard, two symmetrical failures emerge: setting the duration to 0 makes the unlock"
    WIKI_EXPLOIT_SCENARIO = "(1) A governance action calls setLockupTime(0). The function writes `lockupTime = 0` with no guard. Existing stakers whose unlockTime was calculated as `deposit_ts + lockupTime` suddenly see `block.timestamp >= deposit_ts + 0`, so they can withdraw now — but the function that re-reads lockupTime on a re-lock path also applies 0 to anyone trying to top up, effectively skipping the lock entirely. (2"
    WIKI_RECOMMENDATION = "Every function that writes a lock-duration or lockup-window storage field MUST enforce `require(duration >= MIN_LOCK && duration <= MAX_LOCK)` with constants documented by the protocol. For admin setters, apply the same bounds and additionally guard against retroactive application to already-locked "

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'lock|lockup|lockupTime|unlockTime|lockPeriod|lockEnd'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'lock|stakeAndLock|_setLockup|setLockPeriod|setLockupTime|updateLockup|configureLock|extendLock|increaseStakeAndLock'}, {'function.writes_storage_matching': 'lock|lockup'}, {'function.body_not_contains_regex': 'require\\s*\\(.*(lockup|lockPeriod|duration|_time|unlockTime|lockEnd).{0,40}(>|>=|<|<=)|require\\s*\\(.*(lockup|lockPeriod|duration|_time|unlockTime|lockEnd)\\s*!=\\s*0'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — lockup-bypass-zero-duration: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
