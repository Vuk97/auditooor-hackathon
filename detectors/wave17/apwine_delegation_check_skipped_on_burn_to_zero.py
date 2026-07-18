"""
apwine-delegation-check-skipped-on-burn-to-zero — generated from reference/patterns.dsl/apwine-delegation-check-skipped-on-burn-to-zero.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py apwine-delegation-check-skipped-on-burn-to-zero.yaml
Source: auditooor-R76-immunefi-apwine-$100k
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ApwineDelegationCheckSkippedOnBurnToZero(AbstractDetector):
    ARGUMENT = "apwine-delegation-check-skipped-on-burn-to-zero"
    HELP = "Delegation-sanity check in _beforeTokenTransfer is guarded by `to != address(0)`, skipping burns. User delegates yield, burns tokens (withdraws underlying), delegation persists — attacker farms forever."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/apwine-delegation-check-skipped-on-burn-to-zero.yaml"
    WIKI_TITLE = "Delegation check skipped on burn due to `to != address(0)` guard"
    WIKI_DESCRIPTION = "A yield-delegating token (APWine PT, stkTokens, vote-delegation tokens) enforces an invariant in the transfer hook: a user cannot transfer out more than (balance - delegatedAmount). The guard is wrapped in `if (to != address(0)) { ... }` — but burns route to zero. A user delegates future yield to an attacker, then burns PTs to withdraw the underlying. The delegation record still exists and claims "
    WIKI_EXPLOIT_SCENARIO = "APWine PT's _beforeTokenTransfer skipped the delegation check when `to == address(0)`. Attacker flow: deposit IBTs → mint PT → delegate FYT to attacker-controlled address → burnFrom (withdraw IBTs) → totalDelegationsReceived stays inflated → attacker claims yield. Repeat. $100k bounty; fix moved the check to `_withdraw`."
    WIKI_RECOMMENDATION = "Delegation accounting must be updated inside the burn path, not skipped. Either drop the `to != 0` guard (require delegation == 0 before burn) or call `_decreaseDelegation(from, amount)` explicitly in burn/withdraw. Add invariant: `sum(delegations(to=x)) <= sum(balance(y) for y delegating to x)`."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(?i)(delegation|delegated|delegates|delegatee)'}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.name_matches': '(?i)_beforeTokenTransfer|_update|_transferHook'}, {'function.body_contains_regex': '(?i)if\\s*\\(\\s*to\\s*!=\\s*address\\s*\\(\\s*0\\s*\\)|to\\s*==\\s*address\\s*\\(\\s*0\\s*\\)\\s*\\?\\s*|if\\s*\\(\\s*from\\s*!=\\s*address\\s*\\(\\s*0\\s*\\)\\s*&&\\s*to\\s*!=\\s*address\\s*\\(\\s*0\\s*\\)'}, {'function.body_contains_regex': '(?i)delegation|delegated|_delegates|delegatedAmount'}, {'function.body_not_contains_regex': '(?i)_updateDelegationOnBurn|clearDelegationsOnBurn|_withdraw.*delegation'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — apwine-delegation-check-skipped-on-burn-to-zero: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
