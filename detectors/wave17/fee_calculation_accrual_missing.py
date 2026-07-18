"""
fee-calculation-accrual-missing — generated from reference/patterns.dsl/fee-calculation-accrual-missing.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fee-calculation-accrual-missing.yaml
Source: solodit/C0204
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FeeCalculationAccrualMissing(AbstractDetector):
    ARGUMENT = "fee-calculation-accrual-missing"
    HELP = "Fee-rate setter or fee-charging entry point does not invoke the accrual helper first; pending fees under the previous rate are silently re-priced at the new rate."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fee-calculation-accrual-missing.yaml"
    WIKI_TITLE = "Fee calculation: missing accrual before rate change or fee charge"
    WIKI_DESCRIPTION = "The contract exposes an accrual helper (e.g. accrueFee / _accrue / updateFee / collectFee) but external/public functions that change the fee rate or charge fees do not call it first. Any fees that had accumulated under the old rate are re-priced at the new rate, producing silent over- or under-charging and, in some deployments, protocol insolvency."
    WIKI_EXPLOIT_SCENARIO = "Owner calls setFeePerSecond(newRate). Between the last accrual and this call, feePerSecond_old * dt of fees had built up but were never materialized into lastFeeCollected. The next interaction computes owed fees using newRate for the entire interval, either overcharging users (insolvency for the user) or undercharging (insolvency for the protocol)."
    WIKI_RECOMMENDATION = "At the top of every fee-rate setter and fee-charging entry point, call the accrual helper (accrueFee / _accrue / updateFee / collectFee) so all pending fees are materialized under the current rate BEFORE the rate changes or new fees are levied."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': 'accrueFee|_accrue|updateFee|collectFee|lastFee'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'setFee|changeFee|setRate|configureFee|chargeFee|collectFees|updateFeeRate|setFeePerSecond|setFeePerShare'}, {'function.calls_function_matching': {'regex': 'accrue|_accrue|updateFee|collectFee', 'negate': True}}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fee-calculation-accrual-missing: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
