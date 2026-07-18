"""
lockup-bypass-duration-vs-timestamp — generated from reference/patterns.dsl/lockup-bypass-duration-vs-timestamp.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py lockup-bypass-duration-vs-timestamp.yaml
Source: auditooor/RG-N3-narrowing-2026-05-08
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LockupBypassDurationVsTimestamp(AbstractDetector):
    ARGUMENT = "lockup-bypass-duration-vs-timestamp"
    HELP = "Lockup setter writes a storage field whose param is either a duration (`block.timestamp + duration`) or an absolute timestamp (`block.timestamp >= unlockTime`) without the matching guard. Duration params need `>= MIN_DURATION`; timestamp params need `> block.timestamp + MIN_DELAY`. Refined from lock"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/lockup-bypass-duration-vs-timestamp.yaml"
    WIKI_TITLE = "Lockup setter conflates duration vs timestamp param without shape-matched guard"
    WIKI_DESCRIPTION = "Lockup, vesting, and deadline-extension functions accept either an additive duration parameter or an absolute future-timestamp parameter. The two shapes need different guards. A duration param needs `require(duration >= MIN_DURATION && duration <= MAX_DURATION)` and a non-zero check; an absolute timestamp param needs `require(unlockTime > block.timestamp + MIN_DELAY)` to ensure the lock is at leas"
    WIKI_EXPLOIT_SCENARIO = "(1) Duration shape: `setLockup(uint256 dur)` writes `unlockTime = block.timestamp + dur` with no guard. Caller passes 0 → unlockTime = now → withdraw immediately, no lock applied. (2) Timestamp shape: `setUnlockAt(uint256 t)` writes `unlockTime = t` and only checks `block.timestamp >= unlockTime` on withdraw. Caller passes `t = 1` → unlockTime = 1 → withdraw immediately, no lock applied. The detec"
    WIKI_RECOMMENDATION = "Pick a single shape (duration OR timestamp) per function and guard accordingly. Duration: `require(duration >= MIN_DURATION && duration <= MAX_DURATION)`. Timestamp: `require(unlockTime > block.timestamp + MIN_DELAY)`. If the function is internally routed through `onlyVault` / `onlyTrustedRole` and "

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'lock|lockup|lockupTime|unlockTime|lockPeriod|lockEnd|expiry|deadline'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(lock|stakeAndLock|setLockup|setLockPeriod|setLockupTime|setUnlock(Time|At)?|setExpiry|setDeadline|extendLock|extendDeadline|configureLock|updateLockup|increaseStakeAndLock)'}, {'function.writes_storage_matching': '(lock|lockup|unlock|expiry|deadline)'}, {'function.body_contains_regex': '(block\\.timestamp\\s*\\+\\s*\\w+|block\\.timestamp\\s*(>=|<=|>|<)\\s*\\w+)'}, {'function.body_not_contains_regex': 'require\\s*\\(.*(duration|unlock|deadline|expiry|delay).{0,40}(>=|>|<=|<).{0,80}(MIN|MAX|block\\.timestamp)|require\\s*\\(.*(duration|delay).{0,40}!=\\s*0'}, {'function.is_mutating': True}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — lockup-bypass-duration-vs-timestamp: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
