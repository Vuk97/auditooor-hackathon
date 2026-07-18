"""
queue-accounting-stale-on-slot-rotation — generated from reference/patterns.dsl/queue-accounting-stale-on-slot-rotation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py queue-accounting-stale-on-slot-rotation.yaml
Source: auditooor-R75-code4rena-2024-04-gondi-48
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class QueueAccountingStaleOnSlotRotation(AbstractDetector):
    ARGUMENT = "queue-accounting-stale-on-slot-rotation"
    HELP = "Slot-rotation clears outstandingValues for the rotated slot but leaves queueAccounting/shareFraction populated — future claims read the stale entry."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/queue-accounting-stale-on-slot-rotation.yaml"
    WIKI_TITLE = "Slot rotation forgets to clear queueAccounting, leaking stale share fractions into next generation"
    WIKI_DESCRIPTION = "A withdrawal-queue contract rotates the `lastQueueIndex` slot by `delete _queueOutstandingValues[lastQueueIndex]` but omits `delete _queueAccounting[lastQueueIndex]`. After rotation that slot is re-purposed as the new pending queue, but any subsequent `queueClaimAll` still reads the previous generation's `thisQueueFraction` and distributes a share of received funds to ghost claimants, starving rea"
    WIKI_EXPLOIT_SCENARIO = "Generation N has queueAccounting[last] = {fraction = 0.25}. `deployWithdrawalQueue` rotates, clearing outstanding values but not accounting. Generation N+1 receives 100 ETH from loan repayments. `queueClaimAll` reads the stale 0.25 fraction and sends 25 ETH to the old (already-empty) queue — funds are locked or misallocated."
    WIKI_RECOMMENDATION = "Every slot-clearing path must `delete` every mapping keyed by that slot index. Prefer a single `resetSlot(idx)` helper that clears all per-slot state in one place. Add a test that rotates a slot twice and asserts all per-slot mappings read as zero."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(queue|withdrawal|claim)'}, {'contract.has_state_var_matching': '(?i)(queue.*OutstandingValues|OutstandingValues.*queue)'}, {'contract.has_state_var_matching': '(?i)(queue.*(Accounting|ShareFraction)|(Accounting|ShareFraction).*(queue|slot))'}, {'contract.has_function_matching': '(?i)queueClaimAll|claimAll|claimQueue|deploy\\w*Queue|rotate\\w*Slot'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)deploy\\w*Queue|rotate\\w*Slot|rollOver\\w*|advance\\w*Epoch'}, {'function.body_contains_regex': '(?i)delete\\s+_?\\w*OutstandingValues\\s*\\[\\s*\\w*Index\\s*\\]'}, {'function.body_contains_regex': '(?i)lastQueueIndex|nextQueueIndex|queueIndex'}, {'function.body_contains_regex': '(?i)lastQueueIndex\\s*=\\s*nextQueueIndex|nextQueueIndex\\s*=\\s*\\('}, {'function.body_contains_regex': '(?i)(queueAccounting|shareFraction)'}, {'function.body_not_contains_regex': '(?i)delete\\s+_?\\w*(Accounting|ShareFraction|Info|Meta)\\s*\\[\\s*\\w*Index\\s*\\]'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — queue-accounting-stale-on-slot-rotation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
