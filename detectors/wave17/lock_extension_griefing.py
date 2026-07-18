"""
lock-extension-griefing — generated from reference/patterns.dsl/lock-extension-griefing.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py lock-extension-griefing.yaml
Source: solodit-novel/slice_aa-lock-grief
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LockExtensionGriefing(AbstractDetector):
    ARGUMENT = "lock-extension-griefing"
    HELP = "`depositFor(victim, 0, MAX_LOCK)` or `extendLock(victim, MAX_LOCK)` callable by any third party extends the victim's lock duration without consent. Griefer keeps victim's stake locked indefinitely."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/lock-extension-griefing.yaml"
    WIKI_TITLE = "Third party can extend victim's lock duration (griefing)"
    WIKI_DESCRIPTION = "ve-token / lockup contracts often expose `depositFor(user, amount, unlockTime)` to let sponsors top up others' positions. If the function writes `unlockTime` without requiring `msg.sender == user` (or at least `unlockTime >= existingUnlock`), anyone can call with zero amount and max duration to grief the victim — their position stays locked arbitrarily long."
    WIKI_EXPLOIT_SCENARIO = "Victim's lock expires in 1 week. Attacker calls `depositFor(victim, 0, block.timestamp + MAX_LOCK)`. The function updates victim's unlock to +4 years. Victim's funds are now locked for 4 years."
    WIKI_RECOMMENDATION = "Either require `msg.sender == user`, or ensure `depositFor` cannot reduce utility: refuse when `amount == 0`, and never decrease-by-extension (only extend if caller owns the position)."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'lock|locks|lockEnd|lockedUntil|veToken'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(depositFor|lockFor|extendLock|increaseLockTime)'}, {'function.has_param_name_matching': 'user|account|to|recipient'}, {'function.writes_storage_matching': 'lock|end|duration|unlock'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*msg\\.sender\\s*==\\s*(user|account|recipient|to)|require\\s*\\(\\s*\\w+\\s*==\\s*msg\\.sender'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — lock-extension-griefing: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
