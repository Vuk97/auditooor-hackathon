"""
perp-short-burn-without-zero-collateral-check — generated from reference/patterns.dsl/perp-short-burn-without-zero-collateral-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py perp-short-burn-without-zero-collateral-check.yaml
Source: auditooor-R75-c4-2023-03-polynomial-H206
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PerpShortBurnWithoutZeroCollateralCheck(AbstractDetector):
    ARGUMENT = "perp-short-burn-without-zero-collateral-check"
    HELP = "Position NFT is burnt whenever the short size reaches zero, without verifying collateral is also zero. Remaining collateral becomes inaccessible — the NFT that owned it no longer exists. Either refund collateral first or refuse to burn while collateral > 0."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/perp-short-burn-without-zero-collateral-check.yaml"
    WIKI_TITLE = "Short-position NFT burn triggered on zero shortAmount without zero-collateral check"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. Short-position primitives use an ERC721 to represent the position. `adjustPosition(shortAmount, collateralAmount)` mutates both fields; when shortAmount drops to 0 the code unconditionally `_burn(tokenId)`s the NFT. If collateralAmount is still > 0, the collateral sits under a tokenId that has no owner."
    WIKI_EXPLOIT_SCENARIO = "(1) Alice has a short with shortAmount=100, collateralAmount=5000. (2) Alice calls `closeTrade(tokenId, amount=100, collateralAmount=4000)` intending to close the short and withdraw 4000, leaving 1000 as a 'reserve' (perhaps she meant to re-open later). (3) `adjustPosition` computes new shortAmount=0, new collateralAmount=1000. Because shortAmount is 0, the NFT is burnt. (4) Alice's 1000 collatera"
    WIKI_RECOMMENDATION = "Two options. (a) Refuse to burn while collateral > 0: `if (position.shortAmount == 0 && position.collateralAmount == 0) _burn(positionId);`. (b) Auto-refund residual collateral to the owner before burn: `if (position.shortAmount == 0) { if (position.collateralAmount > 0) token.safeTransfer(ownerOf(p"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(ShortToken|shortPosition|shortAmount|collateralAmount|PerpPosition)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(adjustPosition|_adjustPosition|closeShort|burnPosition|_closePosition|settleShort)'}, {'function.body_contains_regex': '(shortAmount\\s*==\\s*0|position\\.short\\s*==\\s*0|size\\s*==\\s*0)'}, {'function.body_contains_regex': '_burn\\s*\\(|burn\\s*\\(\\s*positionId|burn\\s*\\(\\s*tokenId'}, {'function.body_not_contains_regex': '(collateralAmount\\s*==\\s*0|collateral\\s*==\\s*0|require[^)]*collateral[^)]*0)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — perp-short-burn-without-zero-collateral-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
