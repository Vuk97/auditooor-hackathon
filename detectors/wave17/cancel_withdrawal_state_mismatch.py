"""
cancel-withdrawal-state-mismatch — generated from reference/patterns.dsl/cancel-withdrawal-state-mismatch.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py cancel-withdrawal-state-mismatch.yaml
Source: code4arena/slice_ac-Kinetiq-M03
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CancelWithdrawalStateMismatch(AbstractDetector):
    ARGUMENT = "cancel-withdrawal-state-mismatch"
    HELP = "cancelWithdrawal does not unwind all state changes the paired enqueue made (queueTotal, activeRequests, pending maps). Counters drift with every cancel/enqueue cycle."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/cancel-withdrawal-state-mismatch.yaml"
    WIKI_TITLE = "cancelWithdrawal does not mirror enqueueWithdrawal state changes"
    WIKI_DESCRIPTION = "Cancel/undo functions must be exact inverses of their paired request/enqueue function. Missing a single counter decrement — e.g. `queueTotal -= amount` or `activeRequests[user] -= 1` — means the counter drifts upward on every cycle, eventually tripping bounds or corrupting exit logic."
    WIKI_EXPLOIT_SCENARIO = "Kinetiq M-03: `enqueueWithdraw` updates `pendingWithdraw[user]`, `queueTotal`, and `activeRequests[user]`. `cancelWithdraw` decrements only `pendingWithdraw[user]`. Attacker repeatedly enqueues and cancels a 1-wei withdrawal; `queueTotal` and `activeRequests[attacker]` grow without bound, eventually exceeding a bound check that breaks the withdrawal processor for all users."
    WIKI_RECOMMENDATION = "Factor enqueue and cancel into complementary private helpers (`_enqueue`/`_dequeue`) that share a single manifest of state mutations. Unit-test: enqueue-then-cancel must restore exact pre-call state."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(enqueue|requestWithdraw|queueWithdraw)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(cancelWithdraw|undoRequest|revokeWithdraw|dequeueWithdraw)'}, {'function.body_contains_regex': 'pendingWithdraw|queuedAmount'}, {'contract.has_function_body_matching': 'function\\s+(enqueueWithdraw|requestWithdraw|queueWithdraw)[^{]*\\{[^}]*(queueTotal|totalPending|activeRequests)\\s*\\+='}, {'function.body_not_contains_regex': '(queueTotal|totalPending|activeRequests)\\s*-='}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — cancel-withdrawal-state-mismatch: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
