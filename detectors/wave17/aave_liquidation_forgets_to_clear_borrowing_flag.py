"""
aave-liquidation-forgets-to-clear-borrowing-flag — generated from reference/patterns.dsl/aave-liquidation-forgets-to-clear-borrowing-flag.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py aave-liquidation-forgets-to-clear-borrowing-flag.yaml
Source: auditooor-R71-fixdiff-mined-aave-v3-core-f9ec711421
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AaveLiquidationForgetsToClearBorrowingFlag(AbstractDetector):
    ARGUMENT = "aave-liquidation-forgets-to-clear-borrowing-flag"
    HELP = "Liquidation path burns partial debt (variable-only or mixed stable+variable) without clearing userConfig.setBorrowing() when the burn actually zeros the reserve debt — leaves a dangling borrow flag."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/aave-liquidation-forgets-to-clear-borrowing-flag.yaml"
    WIKI_TITLE = "Liquidation fails to clear userConfig.borrowing on partial-type debt burn"
    WIKI_DESCRIPTION = "Aave v3 executeLiquidationCall originally only cleared the borrowing bit when `userTotalDebt == actualDebtToLiquidate` at the top of the function. But two other branches can individually zero out the user's debt for the reserve: (a) the `userVariableDebt > 0` branch that burns only variable debt, if the user had zero stable debt and actualDebtToLiquidate equaled the variable debt, and (b) the mixe"
    WIKI_EXPLOIT_SCENARIO = "A user has 100 USDC variable debt and 0 stable debt on the USDC reserve, plus variable debt on WETH. Liquidator liquidates the full USDC variable debt. Pre-fix: userConfig.borrowing[USDC] stays set. The user now tries to open a normal WETH borrow — if USDC is siloed, the siloed-borrowing check sees usdc still 'borrowed' and reverts with SILOED_BORROWING_VIOLATION, even though the USDC debt is zero"
    WIKI_RECOMMENDATION = "Inside every debt-burn branch of liquidation, after the actual burn call, emit the borrowing-cleared flag based on post-burn debt: in the variable-only branch use `if (userStableDebt == 0 && userVariableDebt == actualDebtToLiquidate) userConfig.setBorrowing(debtReserve.id, false);`; in the stable br"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': 'executeLiquidationCall|liquidationCall|_liquidate'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': 'executeLiquidationCall|liquidationCall|_liquidate'}, {'function.body_contains_regex': 'userVariableDebt|userStableDebt|actualDebtToLiquidate'}, {'function.body_contains_regex': 'burn\\s*\\(.*debt|IVariableDebtToken|IStableDebtToken'}, {'function.body_not_contains_regex': 'userStableDebt\\s*==\\s*0\\s*&&\\s*userVariableDebt\\s*==\\s*actualDebtToLiquidate[\\s\\S]{0,120}setBorrowing\\s*\\(\\s*\\w+\\.id\\s*,\\s*false|userStableDebt\\s*==\\s*actualDebtToLiquidate\\s*-\\s*userVariableDebt[\\s\\S]{0,120}setBorrowing\\s*\\(\\s*\\w+\\.id\\s*,\\s*false|userTotalDebt\\s*==\\s*actualDebtToLiquidate[\\s\\S]{0,120}setBorrowing'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — aave-liquidation-forgets-to-clear-borrowing-flag: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
