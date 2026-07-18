"""
aave-liquidation-state-update-after-external-call — generated from reference/patterns.dsl/aave-liquidation-state-update-after-external-call.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py aave-liquidation-state-update-after-external-call.yaml
Source: auditooor-R71-fixdiff-mined-aave-v3-core-7fbdc6ea5f-cd508a713d
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AaveLiquidationStateUpdateAfterExternalCall(AbstractDetector):
    ARGUMENT = "aave-liquidation-state-update-after-external-call"
    HELP = "Aave-style liquidation disables collateral flag AFTER the aToken transfer / burn path — on ERC777-style reentrant collateral the borrower can re-enter during the callback with the collateral flag still set, reading stale HF state."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/aave-liquidation-state-update-after-external-call.yaml"
    WIKI_TITLE = "Liquidation CEI violation: collateral flag cleared after token movement enables ERC777 reentry"
    WIKI_DESCRIPTION = "In Aave v3 executeLiquidationCall the `userConfig.setUsingAsCollateral(collateralReserve.id, false)` update was originally placed AFTER `_burnDebtTokens()`, AFTER `transferUnderlyingTo(...)`, and AFTER the `safeTransferFrom(msg.sender, ...)` debt pull. If the collateral aToken wraps a hook-enabled token (ERC777, ERC1363, custom transfer hook) the borrower can reenter the Pool during the token tran"
    WIKI_EXPLOIT_SCENARIO = "(1) Reserve X uses an ERC777-style underlying. (2) Borrower's health drops below 1; liquidator calls liquidationCall. (3) During IAToken.burn()/transferUnderlyingTo(), X's tokenReceived hook fires a callback into the borrower contract. (4) Inside the hook, borrower calls Pool.withdraw or Pool.borrow; validateHFAndLtv reads the not-yet-cleared usingAsCollateral bit and thinks reserve X is still con"
    WIKI_RECOMMENDATION = "Move `userConfig.setUsingAsCollateral(reserve.id, false)` and `userConfig.setBorrowing(...)` updates BEFORE any external call in the liquidation path: burn debt tokens, transfer the collateral aToken, transfer the liquidation protocol fee, and pull the debt asset. Any mutation that the attacker's re"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': 'executeLiquidationCall|_liquidationCall|liquidationCall'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': 'executeLiquidationCall|liquidationCall|_liquidate'}, {'function.body_contains_regex': 'setUsingAsCollateral\\s*\\(\\s*\\w+\\s*\\.\\s*id\\s*,\\s*false\\s*\\)|ReserveUsedAsCollateralDisabled'}, {'function.body_contains_regex': 'transferOnLiquidation|safeTransfer|burn\\(\\s*msg\\.sender'}, {'function.post_external_call_mutates_state': True}, {'function.body_not_contains_regex': 'actualCollateralToLiquidate\\s*==\\s*userCollateralBalance[\\s\\S]{0,200}setUsingAsCollateral\\s*\\(\\s*\\w+\\s*\\.\\s*id\\s*,\\s*false\\s*\\)[\\s\\S]{0,400}_burnDebtTokens|setUsingAsCollateral\\(\\w+\\.id,\\s*false\\).*_burnDebtTokens'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — aave-liquidation-state-update-after-external-call: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
