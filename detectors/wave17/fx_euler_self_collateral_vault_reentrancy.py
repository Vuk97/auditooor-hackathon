"""
fx-euler-self-collateral-vault-reentrancy — generated from reference/patterns.dsl/fx-euler-self-collateral-vault-reentrancy.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fx-euler-self-collateral-vault-reentrancy.yaml
Source: auditooor-R71-fixdiff-mined-euler-vault-kit-74e0e010
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FxEulerSelfCollateralVaultReentrancy(AbstractDetector):
    ARGUMENT = "fx-euler-self-collateral-vault-reentrancy"
    HELP = "setLTV allows the vault to register itself (or a vault whose underlying is itself) as collateral; during liquidation, collateral transfer reenters the liability vault and deadlocks on the reentrancy guard, making the position unliquidatable."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fx-euler-self-collateral-vault-reentrancy.yaml"
    WIKI_TITLE = "Vault accepts self-referential collateral — reentrancy deadlock during liquidation"
    WIKI_DESCRIPTION = "Lending vaults configured such that the collateral asset is the vault itself (direct self-collateralization) or a nested vault whose underlying is the liability vault create a reentrancy deadlock during liquidation: liability vault's liquidate() holds the reentrancy lock, then controls-collateral-transfers shares of the collateral vault, which calls back into the liability vault (to check status, "
    WIKI_EXPLOIT_SCENARIO = "Euler cantina-141 / self-collateral issue (2024): governor sets the vault as its own collateral with 95% LTV, or sets an eeTST (wrapper of eTST) as collateral for eTST. When borrower goes underwater, liquidate() reverts with E_Reentrancy when it tries to transfer the wrapping vault's shares (which call back into eTST). Protocol accumulates unrecoverable bad debt."
    WIKI_RECOMMENDATION = "In setLTV: `if (collateral == address(this)) revert E_InvalidLTVAsset();` — and attempt `oracle.getQuote(1e18, collateral, unitOfAccount)` during setLTV so nested-vault collateral whose pricing loops back through this vault triggers E_Reentrancy at config time, not at liquidation time."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '^setLTV$|^addCollateral$|^registerCollateral$'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^setLTV$|^addCollateral$|^registerCollateral$'}, {'function.body_contains_regex': 'collateral|vault'}, {'function.body_not_contains_regex': 'collateral\\s*==\\s*address\\(this\\)|self.*collateral|E_InvalidLTVAsset'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fx-euler-self-collateral-vault-reentrancy: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
