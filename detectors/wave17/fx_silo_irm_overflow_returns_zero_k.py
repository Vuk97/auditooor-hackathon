"""
fx-silo-irm-overflow-returns-zero-k — generated from reference/patterns.dsl/fx-silo-irm-overflow-returns-zero-k.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fx-silo-irm-overflow-returns-zero-k.yaml
Source: github:silo-finance/silo-contracts-v2@f12498e
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FxSiloIrmOverflowReturnsZeroK(AbstractDetector):
    ARGUMENT = "fx-silo-irm-overflow-returns-zero-k"
    HELP = "IRM overflow guards return (0, 0) for k instead of (0, kmin). Returning k=0 violates the invariant that k is always between kmin and kmax, causing the next compoundInterestRate call to use k=0 and compute incorrect (near-zero) interest rates."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fx-silo-irm-overflow-returns-zero-k.yaml"
    WIKI_TITLE = "IRM overflow guard returns k=0 instead of k=kmin — post-overflow interest rate drops to near-zero"
    WIKI_DESCRIPTION = "Interest rate models that guard against overflow by returning (rcomp=0, k=0) violate the model invariant: k must always be in [kmin, kmax]. After an overflow event, the stored k=0 will be below kmin, causing the model to immediately compute near-zero interest rates on the next call until k climbs back up, giving borrowers a free-interest window."
    WIKI_EXPLOIT_SCENARIO = "Silo (2024): a timestamp or asset value overflows its int256 cast. The guard returns (0, 0), writing k=0 to state. All borrowers in that silo effectively get zero interest until the model rebuilds k from 0, potentially spanning many blocks."
    WIKI_RECOMMENDATION = "Return (0, cfg.kmin) from overflow guards instead of (0, 0): `if (overflow) return (0, cfg.kmin);`. This preserves the k-invariant and prevents post-overflow zero-rate exploitation."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '^getCurrentInterestRate$|^getCompoundInterestRate$'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'getCurrentInterestRate|getCompoundInterest|calcInterest'}, {'function.body_contains_regex': 'wouldOverflowOnCastToInt256|wouldOverflow'}, {'function.body_contains_regex': 'return\\s*\\(0,\\s*0\\)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fx-silo-irm-overflow-returns-zero-k: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
