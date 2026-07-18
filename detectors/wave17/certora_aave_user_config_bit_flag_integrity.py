"""
certora-aave-user-config-bit-flag-integrity — generated from reference/patterns.dsl/certora-aave-user-config-bit-flag-integrity.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py certora-aave-user-config-bit-flag-integrity.yaml
Source: certora-aave-v3-core/UserConfiguration/borrowingFlagIntegrity
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CertoraAaveUserConfigBitFlagIntegrity(AbstractDetector):
    ARGUMENT = "certora-aave-user-config-bit-flag-integrity"
    HELP = "Debt/collateral balance goes to zero but the matching user-config bit is not cleared — Aave Certora invariant `borrowingFlagIntegrity` violated."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/certora-aave-user-config-bit-flag-integrity.yaml"
    WIKI_TITLE = "User-config bitmap and balance desynchronize (borrowing/collateral flag leak)"
    WIKI_DESCRIPTION = "Aave's Certora spec proves that `userConfig.isBorrowing(assetId) == (variableDebt[asset][user] > 0)` for every reserve. If a repay / burn / liquidation path drops the debt balance to zero without calling `setBorrowing(assetId, false)` — or inversely, if a flag is flipped without touching the balance — the bitmap lies. Consumers that iterate the bitmap to price collateral / detect isolated-mode / a"
    WIKI_EXPLOIT_SCENARIO = "A `batchRepay(assets[], amounts[])` iterates assets, calling the internal `_repay` which decrements scaled variable debt, but forgets to call `setBorrowing(assetId, false)` when the balance reaches zero (only the per-asset `repay` entrypoint sets the flag). User repays fully via batch path; isBorrowing stays true; collateral is still locked as backing — user cannot withdraw despite holding no debt"
    WIKI_RECOMMENDATION = "Every place that zeroes a per-user debt balance must call `userConfig.setBorrowing(assetId, false)` in the same tx. Every place that zeroes an aToken balance must call `setUsingAsCollateral(assetId, false)`. Mirror Certora's `borrowingFlagIntegrity` as a per-handler invariant."

    _PRECONDITIONS = [{'contract.has_state_var_matching': '(?i)(userConfig|_userConfig|configuration|bitmap|bitmask)'}, {'contract.source_matches_regex': '(?i)(borrowing|collateral).*(flag|bit|mask|enabled|setBorrowing|setUsing)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': '(?i)^(repay|withdraw|burn|liquidation|seize|_repay|_withdraw|finalizeTransfer|transferOnLiquidation)[A-Za-z0-9_]*'}, {'function.body_not_contains_regex': '(?i)(setBorrowing|setUsingAsCollateral|_setBorrowing|_setUsingAsCollateral|configuration\\..*set|userConfig\\..*set)'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': '(?i)(balanceOf|scaledBalance|debtBalance|_balances|repay|burn|subDebt)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — certora-aave-user-config-bit-flag-integrity: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
