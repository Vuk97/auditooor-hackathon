"""
aave-auto-collateral-enable-isolated-or-ltv-zero — generated from reference/patterns.dsl/aave-auto-collateral-enable-isolated-or-ltv-zero.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py aave-auto-collateral-enable-isolated-or-ltv-zero.yaml
Source: auditooor-R71-fixdiff-mined-aave-v3-core-ea4867086d
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AaveAutoCollateralEnableIsolatedOrLtvZero(AbstractDetector):
    ARGUMENT = "aave-auto-collateral-enable-isolated-or-ltv-zero"
    HELP = "Aave-style supply/liquidation/transfer path auto-enables the reserve as collateral for a recipient without filtering out zero-LTV or isolation-mode assets."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/aave-auto-collateral-enable-isolated-or-ltv-zero.yaml"
    WIKI_TITLE = "Auto-enable-as-collateral on first receipt accepts LTV=0 / isolated assets"
    WIKI_DESCRIPTION = "Aave v3 originally auto-activated any first-time received aToken balance as collateral via validateUseAsCollateral(), which only blocks the recipient from enabling a new collateral *while* in isolation mode. It does not prevent the enablement when the asset itself has LTV=0 (frozen / risk-deprecated) or when the asset is an isolated-mode asset supplied to someone who did not opt in. PR #820 split "
    WIKI_EXPLOIT_SCENARIO = "(1) Governance sets asset X LTV=0 as a risk freeze, expecting existing positions to lose weighting but no new collateral exposure. (2) Attacker performs a tiny supply or pushes a dust aToken transfer to a victim who has no X balance. (3) Forked code automatically calls setUsingAsCollateral(reserve.id, true) because validateUseAsCollateral returns true for non-isolation users. (4) Protocol now comp"
    WIKI_RECOMMENDATION = "Split validation into two functions: `validateUseAsCollateral` (user-initiated, may allow isolated if user chose it) and `validateAutomaticUseAsCollateral` (system-triggered on first receipt) — the automatic path must return false when `reserveConfig.getLtv() == 0` AND when `reserveConfig.getDebtCei"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': 'executeSupply|executeLiquidation|executeMintUnbacked|executeFinalizeTransfer|_transfer|setUsingAsCollateral'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'executeSupply|executeMintUnbacked|executeLiquidation|executeFinalizeTransfer|_transfer|finalizeTransfer'}, {'function.body_contains_regex': 'isFirstSupply|balanceToBefore\\s*==\\s*0|liquidatorPreviousATokenBalance\\s*==\\s*0'}, {'function.body_contains_regex': 'setUsingAsCollateral\\s*\\('}, {'function.body_not_contains_regex': 'validateAutomaticUseAsCollateral|ISOLATED_COLLATERAL_SUPPLIER|getLtv\\(\\)\\s*==\\s*0|reserveConfig\\.getLtv\\(\\)\\s*==\\s*0|ltv\\s*==\\s*0|debtCeiling\\s*!=\\s*0\\s*\\?\\s*false'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — aave-auto-collateral-enable-isolated-or-ltv-zero: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
