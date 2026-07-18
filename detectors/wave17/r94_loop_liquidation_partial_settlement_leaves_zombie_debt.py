"""
r94-loop-liquidation-partial-settlement-leaves-zombie-debt — generated from reference/patterns.dsl/r94-loop-liquidation-partial-settlement-leaves-zombie-debt.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-liquidation-partial-settlement-leaves-zombie-debt.yaml
Source: solodit-57323-codehawks-raac-stabilitypool
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopLiquidationPartialSettlementLeavesZombieDebt(AbstractDetector):
    ARGUMENT = "r94-loop-liquidation-partial-settlement-leaves-zombie-debt"
    HELP = "r94-loop-liquidation-partial-settlement-leaves-zombie-debt"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-liquidation-partial-settlement-leaves-zombie-debt.yaml"
    WIKI_TITLE = "r94-loop-liquidation-partial-settlement-leaves-zombie-debt"
    WIKI_DESCRIPTION = "r94-loop-liquidation-partial-settlement-leaves-zombie-debt"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-liquidation-partial-settlement-leaves-zombie-debt"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(StabilityPool|TroveManager|Liquidate|Borrower|RAAC|Lending|CDP)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(liquidate|liquidateBorrower|liquidatePosition|liquidateTrove|liquidateWithPool|closePositionByLiquidation|seizeAndRepay)'}, {'function.source_matches_regex': '(debt\\s*-=\\s*\\w*(pool|available|spDeposits)|borrower\\.debt\\s*=\\s*borrower\\.debt\\s*-\\s*\\w*(pool|available)|\\w*repayable\\s*=\\s*\\w*Math\\.min\\s*\\(\\s*\\w*debt\\s*,)'}, {'function.not_source_matches_regex': '(borrower\\.debt\\s*=\\s*0|debt\\s*=\\s*0\\s*;|require\\s*\\(\\s*\\w*poolAvailable\\s*>=\\s*\\w*debt|revert\\s+\\w*InsufficientStabilityPool|position\\.debt\\s*=\\s*0\\s*;|clearDebt\\s*\\(|zeroDebt\\s*\\()'}]

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
                info = [f, f" — r94-loop-liquidation-partial-settlement-leaves-zombie-debt: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
