"""
fx-silo-totalassets-underestimation — generated from reference/patterns.dsl/fx-silo-totalassets-underestimation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fx-silo-totalassets-underestimation.yaml
Source: github:silo-finance/silo-contracts-v2@107f6bd
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FxSiloTotalassetsUnderestimation(AbstractDetector):
    ARGUMENT = "fx-silo-totalassets-underestimation"
    HELP = "maxWithdraw subtracts 1 from liquidity for rounding fractions but omits the same adjustment for _totalAssets. This causes convertToShares(_totalAssets) to over-estimate total shares, making maxWithdraw return fewer assets than actually withdrawable."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fx-silo-totalassets-underestimation.yaml"
    WIKI_TITLE = "maxWithdraw adjusts liquidity for rounding but not totalAssets — users get lower max withdrawal than available"
    WIKI_DESCRIPTION = "ERC4626 maxWithdraw implementations that subtract 1 from liquidity to account for rounding fractions must apply the same adjustment to _totalAssets used in share-to-asset conversions. Omitting the adjustment causes the share conversion to use a higher totalAssets than liquidity, yielding a lower share count, and therefore a lower max withdrawable amount than is actually available."
    WIKI_EXPLOIT_SCENARIO = "Silo (2024): maxWithdraw computes `liquidity -= 1` but passes the un-adjusted _totalAssets to convertToShares. For positions at the boundary, users receive a maxWithdraw estimate that is 1 share lower than the actual withdrawable amount, leaving dust inaccessible."
    WIKI_RECOMMENDATION = "Apply the same -1 adjustment to both liquidity and _totalAssets: `unchecked { liquidity -= 1; _totalAssets -= 1; }`. This ensures the share conversion uses a consistent view of total assets."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '^maxWithdraw$|^_maxWithdraw'}]
    _MATCH = [{'function.kind': 'internal_or_external_or_public'}, {'function.name_matches': 'maxWithdraw|maxRedeem|availableLiquidity'}, {'function.body_contains_regex': 'liquidity\\s*-=\\s*1'}, {'function.body_not_contains_regex': '_totalAssets\\s*-=\\s*1|totalAssets\\s*-=\\s*1'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fx-silo-totalassets-underestimation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
