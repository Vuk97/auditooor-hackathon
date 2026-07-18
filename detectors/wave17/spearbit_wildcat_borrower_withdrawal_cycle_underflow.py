"""
spearbit-wildcat-borrower-withdrawal-cycle-underflow — generated from reference/patterns.dsl/spearbit-wildcat-borrower-withdrawal-cycle-underflow.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py spearbit-wildcat-borrower-withdrawal-cycle-underflow.yaml
Source: auditooor-R75-spearbit-wildcat-HIGH
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SpearbitWildcatBorrowerWithdrawalCycleUnderflow(AbstractDetector):
    ARGUMENT = "spearbit-wildcat-borrower-withdrawal-cycle-underflow"
    HELP = "Withdrawal-cycle accounting subtracts a newly-scaled fulfillment amount from a counter that stores pre-scale-change values. After a delinquency penalty updates scaleFactor, the counter becomes inconsistent — underflow or overpayment follows."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/spearbit-wildcat-borrower-withdrawal-cycle-underflow.yaml"
    WIKI_TITLE = "Wildcat-style withdrawal queue desynced across scale-factor changes"
    WIKI_DESCRIPTION = "The market stores `outstandingWithdrawals` as a scaled quantity (shares of normalised debt). When a delinquency penalty fires, `scaleFactor` moves and the *normalised* value of all existing scaled quantities changes implicitly. Subsequent withdrawal fulfillments compute `amount = scaled * scaleFactor_now` and subtract *that* from the stored counter — but the counter was accumulated with older scal"
    WIKI_EXPLOIT_SCENARIO = "At T0, lender queues 100 share-units of withdrawal; `outstandingWithdrawals = 100`, scaleFactor = 1.0. At T1 delinquency penalty bumps scaleFactor to 1.10 (borrower owes more). At T2 borrower fulfills, contract computes `amount = 100 * 1.10 = 110 assets`, transfers them, and subtracts `110` from `outstandingWithdrawals` — underflow, revert. Withdrawal batch is now frozen; lenders can't exit. Alter"
    WIKI_RECOMMENDATION = "Store `outstandingWithdrawals` in a scale-invariant unit (raw normalised assets, not shares). On every scaleFactor update, recompute the stored counter to the new scale in a single transition. Add an invariant: sum over pending-batches of scaled(pending) == outstandingWithdrawals. Fuzz with random d"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': 'queueWithdrawal|processUnpaidWithdrawalBatch|_processWithdrawal'}, {'contract.has_field_matching': 'scaleFactor|accruedProtocolFees|delinquency'}]
    _MATCH = [{'function.kind': 'internal_or_public'}, {'function.name_matches': '^(_?processUnpaidWithdrawalBatch|executeWithdrawal|_claimWithdrawal)$'}, {'function.body_contains_regex': 'outstandingWithdrawals\\s*-='}, {'function.body_not_contains_regex': 'rescaleOutstanding|outstandingWithdrawals\\s*=.*scaleFactor|normalize\\('}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — spearbit-wildcat-borrower-withdrawal-cycle-underflow: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
