"""
retroactive-lockup-change-breaks-existing — generated from reference/patterns.dsl/retroactive-lockup-change-breaks-existing.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py retroactive-lockup-change-breaks-existing.yaml
Source: solodit-cluster-C0141
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RetroactiveLockupChangeBreaksExisting(AbstractDetector):
    ARGUMENT = "retroactive-lockup-change-breaks-existing"
    HELP = "Admin setter mutates the global lockup / restriction policy field but applies the new value retroactively to all already-locked positions, either trapping (lockupTime set to a larger value) or prematurely releasing (lockupTime set to 0) users who committed under the old policy."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/retroactive-lockup-change-breaks-existing.yaml"
    WIKI_TITLE = "Retroactive lockup-policy change traps or releases existing positions"
    WIKI_DESCRIPTION = "The contract maintains a global lockup/restriction policy in storage (lockupTime, lockPeriod, lockDuration, unlockTime, restriction) and exposes a privileged setter (setLockupPeriod, updateLockTime, setRestriction, configureLock, increaseLockTime, etc.) that overwrites it in place. Because each user's unlockTime is computed on deposit as `deposit_ts + lockupTime`, and the withdraw path re-reads th"
    WIKI_EXPLOIT_SCENARIO = "(1) Alice stakes under `lockupTime = 30 days`; her position's unlockTime is computed as 30 days hence. (2) Governance calls `setLockupPeriod(365 days)` — the function writes `lockupTime = 365 days` with no grandfathering. (3) Alice's withdraw call now reverts because the contract re-derives `unlockTime = deposit_ts + 365 days`, trapping her for an extra 11 months. (4) Conversely, governance could "
    WIKI_RECOMMENDATION = "Every lockup / restriction setter MUST persist the new value with a `effectiveAfter = block.timestamp` cutoff and re-use the old value for positions whose `deposit_ts < effectiveAfter`. Equivalently, snapshot `lockupTime` into each position on deposit so the withdraw path reads the per-position fiel"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'lockup|lockPeriod|lockDuration|unlockTime|restriction'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'setLockup|updateLockTime|setRestriction|changeLockDuration|_setLockupPeriod|configureLock|increaseLockTime|setLockPeriod|setLockDuration|setUnlockTime'}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyAdmin', 'onlyRoles', 'onlyGovernance', 'onlyRole', 'onlyGovernor'], 'negate': False}}, {'function.writes_storage_matching': 'lockup|lockPeriod|lockDuration|unlockTime|restriction'}, {'function.body_not_contains_regex': 'onlyForNewPositions|futurePositions|_applyOnlyToNew|existingPositions|grandfather|applyPrePolicyTo|_migrateExistingLocks|effectiveAfter\\s*=|appliesTo\\s*\\(\\s*position|pendingLockup|scheduledLockup'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — retroactive-lockup-change-breaks-existing: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
