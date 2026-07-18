"""
ec-liquidation-bonus-exceeds-debt — generated from reference/patterns.dsl/ec-liquidation-bonus-exceeds-debt.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py ec-liquidation-bonus-exceeds-debt.yaml
Source: economic-mining-R61
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EcLiquidationBonusExceedsDebt(AbstractDetector):
    ARGUMENT = "ec-liquidation-bonus-exceeds-debt"
    HELP = "Liquidation seizes collateral proportional to total collateral rather than capping at repaid_debt * (1 + bonus); liquidator captures excess beyond incentive amount."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/ec-liquidation-bonus-exceeds-debt.yaml"
    WIKI_TITLE = "Liquidation bonus uncapped — seize amount based on collateral not debt"
    WIKI_DESCRIPTION = "The liquidation function computes collateral-to-seize as a percentage of the borrower's total collateral rather than basing it on the repaid debt with a bonus cap. In healthy positions that become temporarily undercollateralized, or during cascading liquidations, the liquidator can seize far more collateral than the incentive-justified amount, causing excess loss to the borrower or generating bad "
    WIKI_EXPLOIT_SCENARIO = "User has $10,000 collateral, $9,000 debt. Price drops 1%: collateral=$9,900, LTV = 90.9% > threshold. Liquidator repays $9,000 debt. Buggy contract: seized = $9,900 * 1.10 (110%) = $10,890 — more than collateral exists. Protocol takes $990 loss (bad debt)."
    WIKI_RECOMMENDATION = "Cap the seized collateral: `uint256 maxSeize = repaidDebt * (1 + liquidationBonus) / price; uint256 actualSeize = min(borrowerCollateral, maxSeize)`. If maxSeize > borrowerCollateral, the full collateral position is liquidated and bad debt should be socialized to the insurance fund, not silently abs"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'liquidat|seize|liquidationBonus|LIQUIDATION_BONUS'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'liquidat|seize|_liquidate'}, {'function.body_contains_regex': 'collateral.*\\*.*bonus|seize.*=.*collateral|totalCollateral.*bonus|bonus.*totalCollateral'}, {'function.body_not_contains_regex': 'min\\s*\\(|Math\\.min|seizedCollateral\\s*<=|cap.*seize|maxSeize'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — ec-liquidation-bonus-exceeds-debt: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
