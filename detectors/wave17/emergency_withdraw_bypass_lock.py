"""
emergency-withdraw-bypass-lock — generated from reference/patterns.dsl/emergency-withdraw-bypass-lock.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py emergency-withdraw-bypass-lock.yaml
Source: solodit/C0212
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EmergencyWithdrawBypassLock(AbstractDetector):
    ARGUMENT = "emergency-withdraw-bypass-lock"
    HELP = "emergencyWithdraw lets users exit a timelocked stake without honoring the lock deadline, applying a penalty, or settling reward accruals — turning the 'emergency' hatch into a zero-cost bypass."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/emergency-withdraw-bypass-lock.yaml"
    WIKI_TITLE = "emergencyWithdraw bypasses timelock / staking penalty"
    WIKI_DESCRIPTION = "Staking and vesting contracts routinely expose an `emergencyWithdraw` (or `forceExit`, `panicWithdraw`, `emergencyExit`) intended for break-glass scenarios. When the emergency path does not honor the `lockEnd` / `unlockTime` / `lockPeriod` deadline, does not apply an early-exit penalty, and does not settle reward accruals, any staker can call it the moment they want out. The result: users escape t"
    WIKI_EXPLOIT_SCENARIO = "A staker deposits 1000 tokens with a 30-day `lockEnd`. After 1 day they call `emergencyWithdraw()`. The function transfers 1000 tokens back without checking `block.timestamp >= lockEnd`, without charging the advertised 10% early-exit penalty, and without updating `rewardPerTokenStored`. The staker has effectively ignored the lock entirely, collected full principal, and their share of already-accru"
    WIKI_RECOMMENDATION = "Any `emergencyWithdraw`-style exit MUST (a) enforce the same lock deadline as the normal withdraw path, OR (b) apply an explicit penalty that is at least equal to the locked-yield opportunity cost, AND (c) settle reward accruals before transferring. Document which of these three it honors; audit rev"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '(withdraw|unstake)'}, {'contract.has_state_var_matching': '(lockEnd|lockUntil|unlockTime|lockPeriod)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '(emergencyWithdraw|forceExit|panicWithdraw|emergencyExit)'}, {'function.body_not_contains_regex': '(block\\.timestamp\\s*<|require\\s*\\(.*(lockEnd|unlockTime|lockUntil|lockPeriod)|penalty|fee\\s*=)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — emergency-withdraw-bypass-lock: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
