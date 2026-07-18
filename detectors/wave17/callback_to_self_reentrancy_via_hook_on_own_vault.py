"""
callback-to-self-reentrancy-via-hook-on-own-vault — generated from reference/patterns.dsl/callback-to-self-reentrancy-via-hook-on-own-vault.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py callback-to-self-reentrancy-via-hook-on-own-vault.yaml
Source: auditooor-R75-spearbit-hook-griefing-HIGH
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CallbackToSelfReentrancyViaHookOnOwnVault(AbstractDetector):
    ARGUMENT = "callback-to-self-reentrancy-via-hook-on-own-vault"
    HELP = "Function holds nonReentrant while calling a user-supplied hook, but a sibling external function on the same contract lacks the guard. Hook re-enters the sibling mid-flight, mutating shared state that the outer function still trusts."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/callback-to-self-reentrancy-via-hook-on-own-vault.yaml"
    WIKI_TITLE = "User-supplied hook re-enters a sibling unguarded function on the same contract"
    WIKI_DESCRIPTION = "The outer entry point (e.g. `swap` or `rebalance`) carries `nonReentrant` and then calls a user-specified hook/strategy/adapter address. Devs assume `nonReentrant` covers the whole contract — it does not, it only guards functions that *share* the guard. Any sibling function without the modifier (for example a separately-added `flashDeposit` or `claimRewards`) is entered re-entrantly by the hook. T"
    WIKI_EXPLOIT_SCENARIO = "Manager.swap() is nonReentrant. It calls `hook.beforeSwap(user, amount)` on a user-registered hook. The hook calls `Manager.claimRewards()` — a newer function added without the reentrancy modifier. claimRewards transfers accrued rewards and zeroes the user's reward balance. Control returns to swap(), which reads the now-zero reward balance in its post-hook accounting, double-crediting the user bec"
    WIKI_RECOMMENDATION = "Apply `nonReentrant` to every external / public state-mutating function on any contract that ever calls an untrusted address. Prefer a contract-level mutex (single slot covers all entry points) over per-function guards. Statically verify: for each contract that has at least one `nonReentrant` functi"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': 'deposit|withdraw|swap|rebalance|harvest'}, {'contract.has_field_matching': 'hook|strategy|adapter|callback|executor'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': 'hook\\.\\w+\\s*\\(|strategy\\.\\w+\\s*\\(|adapter\\.\\w+\\s*\\(|callback\\.\\w+\\s*\\(|IHook\\(.*\\)\\.\\w+\\('}, {'function.has_modifier': 'nonReentrant'}, {'contract.has_function_without_modifier': 'nonReentrant'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — callback-to-self-reentrancy-via-hook-on-own-vault: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
