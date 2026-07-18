"""
fx-euler-esr-gulp-inflation-low-supply — generated from reference/patterns.dsl/fx-euler-esr-gulp-inflation-low-supply.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fx-euler-esr-gulp-inflation-low-supply.yaml
Source: auditooor-R71-fixdiff-mined-euler-vault-kit-807ecb79
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FxEulerEsrGulpInflationLowSupply(AbstractDetector):
    ARGUMENT = "fx-euler-esr-gulp-inflation-low-supply"
    HELP = "gulp()/skim()/accrueRewards() folds excess asset balance into a smeared-interest accumulator without checking a minimum total-share supply. A first-depositor or dust-share attacker can donate tokens before gulp and inflate their share price unboundedly."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fx-euler-esr-gulp-inflation-low-supply.yaml"
    WIKI_TITLE = "gulp()/skim() missing min-supply guard — donation inflation against low-supply ERC-4626"
    WIKI_DESCRIPTION = "Savings-rate / reward-distribution vaults expose gulp() to let anyone fold excess underlying balance into a totalAssets smear. Without refusing to gulp when share supply is below a safety threshold (e.g., 10× virtual-shares), an attacker owning most shares donates to the vault and calls gulp(); shares are credited with the donation over the smear window, then attacker redeems for a multiple of the"
    WIKI_EXPLOIT_SCENARIO = "Euler ESR Cantina fix (2024): attacker deposits minimum allowed shares, donates large amount of underlying to the contract address, calls gulp(), shares are credited the donation over the smear window, redeems for a multiple. Classic first-depositor/donation inflation adapted for smeared-interest vaults."
    WIKI_RECOMMENDATION = "At top of gulp(): `if (totalSupply() < MIN_SHARES_FOR_GULP) return;` where MIN_SHARES_FOR_GULP >= 10 * VIRTUAL_AMOUNT. Alternative: use OpenZeppelin ERC-4626's virtual-shares inflation mitigation at mint + require minimum-shares check at gulp."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '^gulp$|^accrueRewards$'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^gulp$|^skim$|^accrueRewards$'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': 'assetBalance|balanceOf\\(address\\(this\\)\\).*_totalAssets|interestLeft'}, {'function.body_not_contains_regex': 'totalSupply\\(\\)\\s*<\\s*MIN_|MIN_SHARES_FOR_GULP|virtual\\s*shares|DEAD_SHARES'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fx-euler-esr-gulp-inflation-low-supply: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
