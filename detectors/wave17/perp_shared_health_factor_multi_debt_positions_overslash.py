"""
perp-shared-health-factor-multi-debt-positions-overslash — generated from reference/patterns.dsl/perp-shared-health-factor-multi-debt-positions-overslash.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py perp-shared-health-factor-multi-debt-positions-overslash.yaml
Source: auditooor-R75-c4-2024-06-size-H201
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PerpSharedHealthFactorMultiDebtPositionsOverslash(AbstractDetector):
    ARGUMENT = "perp-shared-health-factor-multi-debt-positions-overslash"
    HELP = "Account-wide health check combined with pro-rata collateral assignment to individual debt positions: when only ONE debt position is under-water, ALL become liquidatable, and liquidators choose which to liquidate. Borrower loses MORE collateral than the specific under-water position required."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/perp-shared-health-factor-multi-debt-positions-overslash.yaml"
    WIKI_TITLE = "Account-wide health factor + pro-rata collateral per position over-slashes on multi-position accounts"
    WIKI_DESCRIPTION = "Fixed-rate lending markets (Size, Morpho Fixed) compute a single account-level `collateralRatio = totalCollateral / totalDebt`. When CR drops below threshold, all debt positions are liquidatable. Each position is assigned a pro-rata slice of total collateral. A liquidator picks the positions that give them the best reward (usually the ones whose share of collateral × liquidationBonus is largest). "
    WIKI_EXPLOIT_SCENARIO = "(1) Bob has two debt positions: P1 backed by tight collateral (~130% CR-specific) and P2 heavily over-collateralised (~300% CR-specific). Account-wide: (130 + 300) / (P1_debt + P2_debt) is well above 130%. (2) Market dips, P1's specific CR drops to 125%, P2 still at 280%. Account CR = (125 + 280) / 2 (equal debt assumed) = 202.5% — above 130% threshold, so no liquidation. (3) Market dips again: P1"
    WIKI_RECOMMENDATION = "Switch to per-position isolated collateral accounting: each debt position binds a specific collateral amount; health is position-local. Or keep account-wide health but when liquidating, require liquidators to liquidate the position(s) that drive the account to insolvency (the highest-CR, most-underw"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(collateralRatio|healthFactor|debtToken|creditPosition|debtPosition|RiskLibrary)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.state_mutability': 'view'}, {'function.name_matches': '(collateralRatio|_collateralRatio|healthFactor|isLiquidatable|computeHealth)'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': '(collateralToken\\.balanceOf\\s*\\(\\s*account|debtToken\\.balanceOf\\s*\\(\\s*account|account\\s*->\\s*\\w*total)'}, {'function.body_contains_regex': '(mulDivDown|mulDivUp|divWad)'}, {'function.body_not_contains_regex': '(perPosition|positionSpecific|debtPosition\\.\\w*|isolatedMargin|positionId)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — perp-shared-health-factor-multi-debt-positions-overslash: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
