"""
w68-share-price-manipulation-donation — generated from reference/patterns.dsl/w68-share-price-manipulation-donation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py w68-share-price-manipulation-donation.yaml
Source: W6-8 zero-coverage detector batch (auditooor capability lift)
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class W68SharePriceManipulationDonation(AbstractDetector):
    ARGUMENT = "w68-share-price-manipulation-donation"
    HELP = "ERC4626 share price manipulated via donation attack because totalAssets reads raw token balance"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/w68-share-price-manipulation-donation.yaml"
    WIKI_TITLE = "ERC4626 share price manipulated via donation attack"
    WIKI_DESCRIPTION = "Share price is computed from the vault's raw token balanceOf(this), so a direct token donation inflates totalAssets and manipulates the share price."
    WIKI_EXPLOIT_SCENARIO = "ERC4626 share price manipulated via donation attack because totalAssets reads raw token balance"
    WIKI_RECOMMENDATION = "Use internally tracked asset accounting instead of raw balanceOf."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(totalAssets|convertToShares|convertToAssets|previewDeposit|previewMint|previewWithdraw|previewRedeem|pricePerShare|balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\))'}]
    _MATCH = [{'function.name_matches': '.*(totalAssets|convert|deposit|preview|toShares|toAssets|pricePerShare).*'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.body_contains_regex': '(?i)balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*\\)'}, {'function.body_not_contains_regex': '(?i)(tracked|internalAssets|storedAssets|_totalAssets|totalDeposited|accountedAssets|cachedAssets)'}]

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
                info = [f, f" — w68-share-price-manipulation-donation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
