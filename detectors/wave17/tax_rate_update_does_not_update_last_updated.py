"""
tax-rate-update-does-not-update-last-updated — generated from reference/patterns.dsl/tax-rate-update-does-not-update-last-updated.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py tax-rate-update-does-not-update-last-updated.yaml
Source: auditooor-R75-code4rena-2024-07-munchables-86
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class TaxRateUpdateDoesNotUpdateLastUpdated(AbstractDetector):
    ARGUMENT = "tax-rate-update-does-not-update-last-updated"
    HELP = "updateTaxRate sets the new rate but doesn't write lastUpdated = now — next accrual applies the new rate over the full stale interval, back-dating the change."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/tax-rate-update-does-not-update-last-updated.yaml"
    WIKI_TITLE = "Rate update forgets to set lastUpdated, back-dating the new rate to the last settlement"
    WIKI_DESCRIPTION = "`updateTaxRate(new)` writes `plotMetadata[landlord].currentTaxRate = new` but does not write `plotMetadata[landlord].lastUpdated = block.timestamp`. Subsequent `_farmPlots` calls compute `schnibblesTotal = (timestamp - lastToilDate) * rate` with `rate = new` spanning back to the previous lastToilDate. Rewards/tax for the interval before the update are mis-charged at the new rate."
    WIKI_EXPLOIT_SCENARIO = "A landlord has earned 100 schnibbles at 5% tax (5 owed to landlord). Before any farmer claims, landlord calls updateTaxRate(50%). Next _farmPlots applies 50% to the full 100 → landlord collects 50, not the 5 they were entitled to."
    WIKI_RECOMMENDATION = "Before writing the new rate, settle accrual for every affected account: call an internal `_checkpoint(landlord)` that applies the old rate up to `block.timestamp`, then write `lastUpdated = block.timestamp` and the new rate. Fuzz test asserting total tax = sum of `rate_i * dt_i`."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)setTaxRate|updateTaxRate|setInterestRate|setFeeRate|updateRate'}, {'function.body_contains_regex': '(?i)(currentTaxRate|taxRate|interestRate|feeRate)\\s*=\\s*new\\w*Rate'}, {'function.body_not_contains_regex': '(?i)lastUpdated\\s*=\\s*(block\\.timestamp|_now|uint\\w*\\(\\s*block\\.timestamp)|_checkpoint\\w*\\(|_settleAccrual\\('}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — tax-rate-update-does-not-update-last-updated: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
