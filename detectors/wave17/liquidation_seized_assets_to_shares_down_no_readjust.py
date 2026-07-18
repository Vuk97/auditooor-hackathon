"""
liquidation-seized-assets-to-shares-down-no-readjust - generated from reference/patterns.dsl/liquidation-seized-assets-to-shares-down-no-readjust.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py liquidation-seized-assets-to-shares-down-no-readjust.yaml
Source: auditooor-fire4-lt-solodit-40874
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LiquidationSeizedAssetsToSharesDownNoReadjust(AbstractDetector):
    ARGUMENT = "liquidation-seized-assets-to-shares-down-no-readjust"
    HELP = "Liquidation computes repaidAssets from a fixed seized collateral amount, rounds repaidShares down from that intermediate, and does not readjust repaidAssets from the final share value."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/liquidation-seized-assets-to-shares-down-no-readjust.yaml"
    WIKI_TITLE = "Fixed seized-assets liquidation rounds repaidShares down without final asset readjustment"
    WIKI_DESCRIPTION = "In the source Morpho finding, a liquidator can provide a fixed seizedAssets value. The code converts that seized collateral into repaidAssets, then rounds repaidShares down from repaidAssets. If the final repaidShares value is zero or lower than the seized collateral value implies, the borrower loses collateral without a matching debt-share reduction."
    WIKI_EXPLOIT_SCENARIO = "The source report describes splitting liquidation into tiny fixed-seized chunks. Each chunk can burn zero or too few borrow shares while still seizing collateral computed from the rounded-up repay asset intermediate. The borrower becomes less healthy and the market can inherit bad debt."
    WIKI_RECOMMENDATION = "For the fixed seized-assets branch, round shares in the protocol-favoring direction and then recompute the asset amount from the final settled share value, e.g. repaidShares = repaidAssets.toSharesUp(...); repaidAssets = repaidShares.toAssetsUp(...)."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(repaidAssets|repaidShares|seizedAssets|toSharesDown|toSharesUp|toAssetsUp)'}, {'contract.has_function_matching': '(?i)^liquidate'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^liquidate'}, {'function.has_param_name_matching': '(?i)(seizedAssets|collateralToSeize|collateralAmount)'}, {'function.body_contains_regex': '(?s)\\brepaidAssets\\s*=\\s*[^;]*(seizedAssets|collateralToSeize|collateralAmount)'}, {'function.body_contains_regex': '(?s)\\brepaidAssets\\s*=\\s*[^;]*(mulDivUp|wDivUp|toAssetsUp)'}, {'function.body_contains_regex': '(?s)\\brepaidShares\\s*=\\s*[^;]*repaidAssets'}, {'function.body_contains_regex': '(?s)\\brepaidShares\\s*=\\s*[^;]*(toSharesDown|mulDivDown|wDivDown)'}, {'function.body_not_contains_regex': '(?s)\\brepaidShares\\s*=\\s*[^;]*toSharesUp|\\brepaidAssets\\s*=\\s*[^;]*toAssetsUp\\s*\\(\\s*repaidShares|\\brepaidAssets\\s*=\\s*[^;]*repaidShares[^;]*toAssetsUp'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" - liquidation-seized-assets-to-shares-down-no-readjust: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
