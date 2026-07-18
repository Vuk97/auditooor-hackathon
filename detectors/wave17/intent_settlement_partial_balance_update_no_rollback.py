"""
intent-settlement-partial-balance-update-no-rollback — generated from reference/patterns.dsl/intent-settlement-partial-balance-update-no-rollback.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py intent-settlement-partial-balance-update-no-rollback.yaml
Source: auditooor-R75-zellic-aori-HIGH
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class IntentSettlementPartialBalanceUpdateNoRollback(AbstractDetector):
    ARGUMENT = "intent-settlement-partial-balance-update-no-rollback"
    HELP = "A settlement function performs two non-reverting balance mutations (e.g. decreaseLocked then increaseUnlocked), checks a combined success flag, and returns on failure — but does not roll back the first mutation if the second failed. One side of the order is updated while the other isn't, leaving bal"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/intent-settlement-partial-balance-update-no-rollback.yaml"
    WIKI_TITLE = "Partial balance update in intent/order settlement without snapshot-rollback"
    WIKI_DESCRIPTION = "To avoid reverts that would DoS batch settlement, protocols often call balance-mutation helpers with NoRevert semantics that return bool. If the code pattern is `success1 = mutate(...); success2 = mutate(...); if (!success1 || !success2) return;` then when success1 is false but success2 is true, the second mutation is never undone. The offerer's locked balance is unchanged, the filler's unlocked b"
    WIKI_EXPLOIT_SCENARIO = "A solver with a compromised offerer account has the offerer's locked balance drained to zero. When _settleOrder runs for that offerer, decreaseLockedNoRevert returns false (insufficient locked balance), but increaseUnlockedNoRevert on the filler succeeds. The filler's unlocked balance is credited without consuming the offerer's locked balance. The order stays Active and can be 'settled' again on a"
    WIKI_RECOMMENDATION = "Either (a) snapshot both balance storage slots to memory cache before mutating and restore them if either helper returns false, or (b) perform an off-chain precheck and then use a reverting mutation — do not silently return on failure after a partial mutation."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(NoRevert|tryIncrease|tryDecrease|Balance|Locked)'}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.name_matches': '(_settle|settle|_fill|fill|_execute)[A-Za-z0-9_]*[Oo]rder'}, {'function.body_contains_regex': 'bool\\s+(success|ok|result)[A-Z][a-zA-Z]*\\s*=\\s*[a-zA-Z_0-9.]+(decrease|increase|transfer|lock|unlock)[A-Z]?[a-zA-Z]*NoRevert'}, {'function.body_contains_regex': 'if\\s*\\(\\s*!\\s*[a-zA-Z_]+\\s*\\|\\|\\s*!\\s*[a-zA-Z_]+\\s*\\)\\s*\\{[^}]*return'}, {'function.body_not_contains_regex': 'balances\\s*\\[[^\\]]+\\]\\s*=\\s*[a-zA-Z_]+(Cache|Snapshot|Before)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — intent-settlement-partial-balance-update-no-rollback: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
