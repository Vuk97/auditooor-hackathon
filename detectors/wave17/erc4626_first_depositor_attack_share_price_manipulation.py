"""
erc4626-first-depositor-attack-share-price-manipulation — generated from reference/patterns.dsl/erc4626-first-depositor-attack-share-price-manipulation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py erc4626-first-depositor-attack-share-price-manipulation.yaml
Source: Hexens Glider query: erc4626-first-depositor-attack-share-price-manipul
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Erc4626FirstDepositorAttackSharePriceManipulation(AbstractDetector):
    ARGUMENT = "erc4626-first-depositor-attack-share-price-manipulation"
    HELP = "ERC4626 deposit or mint path reads bootstrap share accounting without a first-deposit or virtual-offset guard"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/erc4626-first-depositor-attack-share-price-manipulation.yaml"
    WIKI_TITLE = "ERC4626 First Depositor Attack - Share Price Manipulation"
    WIKI_DESCRIPTION = "Detects ERC4626-style deposit or mint flows that read total-supply or total-asset accounting but do not call a bootstrap helper, virtual-offset helper, or first-deposit guard."
    WIKI_EXPLOIT_SCENARIO = "An attacker seeds an empty vault, donates underlying to skew the exchange rate, and frontruns the next depositor so the victim receives near-zero shares."
    WIKI_RECOMMENDATION = "Use a bootstrap branch, virtual shares/assets, or an equivalent first-deposit guard to prevent hostile exchange-rate initialization."

    _PRECONDITIONS = [{'contract.has_function_matching': 'deposit|mint'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches_regex': '.*(deposit|mint).*'}, {'function.reads_state_var_matching': '.*(totalSupply|totalShares|shareSupply|totalAssets|managedAssets|assetBalance).*'}, {'function.not_internal_calling_regex': '.*(virtual|VIRTUAL|bootstrap|initialDeposit|firstDeposit|seed|_decimalsOffset).*'}, {'function.not_high_level_calling_regex': '.*(virtual|VIRTUAL|bootstrap|initialDeposit|firstDeposit|seed|_decimalsOffset).*'}, {'function.not_in_skip_list': True}]

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
                info = [f, f" — erc4626-first-depositor-attack-share-price-manipulation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
