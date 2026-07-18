"""
fx-silo-irm-k-not-updated-zero-debt — generated from reference/patterns.dsl/fx-silo-irm-k-not-updated-zero-debt.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fx-silo-irm-k-not-updated-zero-debt.yaml
Source: github:silo-finance/silo-contracts-v2@e3dd4b0
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FxSiloIrmKNotUpdatedZeroDebt(AbstractDetector):
    ARGUMENT = "fx-silo-irm-k-not-updated-zero-debt"
    HELP = "Dynamic kink IRM returns (0, state.k) immediately when total borrow assets is zero, skipping the k-adjustment logic. This means k is frozen at its last value when all debt is repaid, and the market resumes with a stale k rather than the correct k after an idle period."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fx-silo-irm-k-not-updated-zero-debt.yaml"
    WIKI_TITLE = "Dynamic kink IRM early-returns stale k on zero-debt — interest model resumes incorrectly after full repayment"
    WIKI_DESCRIPTION = "Dynamic IRM implementations that early-return (rcomp=0, k=state.k) when total borrow is zero prevent k from being updated during zero-debt periods. When k should drift toward kmin during idle periods, skipping the update causes the market to resume with an inflated k value, producing unexpectedly high interest rates on the first borrow after a quiescent period."
    WIKI_EXPLOIT_SCENARIO = "Silo M-02 (2024): after all debt is repaid, the IRM's k remains at its last elevated value. The next borrower pays interest as if the IRM never had time to decay, because the zero-debt period was entirely skipped in k-update calculations."
    WIKI_RECOMMENDATION = "Let the full k-adjustment logic run even when _tba==0; only zero out rcomp at the end: `if (_tba == 0) rcomp = 0;`. This ensures k decays properly during idle periods while still reporting zero interest on zero debt."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '^compoundInterestRate$|^rcomp$'}]
    _MATCH = [{'function.kind': 'internal_or_external_or_public'}, {'function.name_matches': 'compoundInterest|rcomp|calcInterest|getInterestRate'}, {'function.body_contains_regex': '_tba\\s*==\\s*0|tba\\s*==\\s*0|debtAssets\\s*==\\s*0'}, {'function.body_contains_regex': 'return\\s*\\(0,\\s*_state\\.k\\)|return\\s*\\(0,\\s*k\\)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fx-silo-irm-k-not-updated-zero-debt: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
