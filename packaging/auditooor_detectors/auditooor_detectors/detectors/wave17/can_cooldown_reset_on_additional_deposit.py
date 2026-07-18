"""
can-cooldown-reset-on-additional-deposit — generated from reference/patterns.dsl/can-cooldown-reset-on-additional-deposit.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py can-cooldown-reset-on-additional-deposit.yaml
Source: cantina/2024-2025-cooldown-reset-griefing-class
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CanCooldownResetOnAdditionalDeposit(AbstractDetector):
    ARGUMENT = "can-cooldown-reset-on-additional-deposit"
    HELP = "Deposit-for-user with zero amount resets victim's cooldown timer — griefer pushes withdrawal arbitrarily far into the future at zero cost."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/can-cooldown-reset-on-additional-deposit.yaml"
    WIKI_TITLE = "Cooldown timer reset on deposit-for-user enables griefing"
    WIKI_DESCRIPTION = "A staking or unstaking system records a per-user cooldown timestamp that ticks down until the user can withdraw. If the cooldown is bumped to `block.timestamp + COOLDOWN` on EVERY call to `deposit(user, amount)` — regardless of `amount` or caller identity — any third party can call `deposit(victim, 0)` right before the victim's cooldown expires and reset it. Gas-efficient grief, no economic disinc"
    WIKI_EXPLOIT_SCENARIO = "Cantina competition class: user stakes 1000 tokens, cooldown set to `now + 7d`. One minute before day 7 ends, attacker calls `deposit(user, 0)`. `_updateUser` sets `cooldownEnd = now + 7d`. Victim waits another 7 days; attacker reruns. Loop indefinitely for <$1 of gas per reset — victim's stake permanently inaccessible."
    WIKI_RECOMMENDATION = "Two-layer fix: (a) enforce `require(msg.sender == user || amount > 0)` so zero-amount third-party calls cannot reset; (b) change the cooldown policy to a max — `cooldownEnd = max(cooldownEnd, block.timestamp + COOLDOWN)` ensures an additional deposit never SHORTENS cooldown but the PRE-EXISTING time"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'cooldown|cooldownEnd|unlockAt|withdrawalDelay'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_param_name_matching': '(?i)(user|account|to|recipient|onBehalfOf)'}, {'function.writes_storage_matching': '(cooldown|cooldownEnd|unlockAt|withdrawalDelay|lastStake)'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*(user|account|to|recipient|onBehalfOf)\\s*==\\s*msg\\.sender|require\\s*\\(\\s*msg\\.sender\\s*==\\s*(user|account|to|recipient|onBehalfOf)'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*amount\\s*>\\s*0'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — can-cooldown-reset-on-additional-deposit: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
