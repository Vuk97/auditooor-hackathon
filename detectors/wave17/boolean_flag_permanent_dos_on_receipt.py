"""
boolean-flag-permanent-dos-on-receipt — generated from reference/patterns.dsl/boolean-flag-permanent-dos-on-receipt.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py boolean-flag-permanent-dos-on-receipt.yaml
Source: code4arena/slice_ac-THORWallet-M01
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BooleanFlagPermanentDosOnReceipt(AbstractDetector):
    ARGUMENT = "boolean-flag-permanent-dos-on-receipt"
    HELP = "A per-user boolean flag is set on receipt/bridge-arrival and later gates the user's transfers/claims, but the contract never exposes a path to clear it. Attacker sends 1 wei to victim, permanently DoS'ing victim."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/boolean-flag-permanent-dos-on-receipt.yaml"
    WIKI_TITLE = "Permanent per-user boolean flag set on receipt gates future ops"
    WIKI_DESCRIPTION = "Contracts that categorize users based on past events via a permanent boolean (`isBridgedTokenHolder[x] = true` inside `_credit`) create a weaponizable surface: any party can set that flag on a victim's account by sending them 1 wei, and the victim is then subject to whatever restrictions the flag implies (transfer limit, fee, restricted redemption) — possibly forever."
    WIKI_EXPLOIT_SCENARIO = "A cross-chain bridge marks every recipient of a bridged token in `isBridgedTokenHolder`. Because bridged holders are treated differently on later transfers (fee, one-time-only move), the attacker bridges 1 wei to the target. The target's subsequent, possibly-ordinary transfer now reverts or is taxed — a griefing attack with dust-level cost."
    WIKI_RECOMMENDATION = "Replace the permanent flag with a per-tx or per-amount check: verify the source of the tokens at transfer-time, not via a sticky bit. If a sticky bit is essential, expose a permissioned `clear(user)` path or make the bit user-clearable on request with a nominal cool-down."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(isBridgedTokenHolder|isHolder|isLocked|isBanned|hasReceived)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '(isBridgedTokenHolder|isHolder|isLocked|isBanned|hasReceived)\\s*\\[\\s*(\\w+|to|recipient|user|receiver)\\s*\\]\\s*='}, {'contract.has_no_function_body_matching': '(isBridgedTokenHolder|isHolder|isLocked|isBanned|hasReceived)\\s*\\[\\s*\\w+\\s*\\]\\s*=\\s*false'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — boolean-flag-permanent-dos-on-receipt: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
