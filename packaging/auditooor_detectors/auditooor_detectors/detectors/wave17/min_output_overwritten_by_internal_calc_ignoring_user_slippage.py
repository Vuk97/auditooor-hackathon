"""
min-output-overwritten-by-internal-calc-ignoring-user-slippage — generated from reference/patterns.dsl/min-output-overwritten-by-internal-calc-ignoring-user-slippage.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py min-output-overwritten-by-internal-calc-ignoring-user-slippage.yaml
Source: lisa-mine-r99-case-02986-sherlock-notional-2022-09
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MinOutputOverwrittenByInternalCalcIgnoringUserSlippage(AbstractDetector):
    ARGUMENT = "min-output-overwritten-by-internal-calc-ignoring-user-slippage"
    HELP = "Vault settlement helper recomputes `params.minPrimary` from an oracle-derived time-weighted balance and then scales it ONLY by a global slippage cap (e.g. `balancerPoolSlippageLimitPercent`) — completely overwriting whatever min-output the caller passed in. The user-supplied `oracleSlippagePercent` "
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/min-output-overwritten-by-internal-calc-ignoring-user-slippage.yaml"
    WIKI_TITLE = "Settlement min-output recomputed from oracle and global cap, ignoring user-supplied slippage"
    WIKI_DESCRIPTION = "Pattern fires on `_executeSettlement`-style internal helpers that compute `params.minPrimary = poolContext._getTimeWeightedPrimaryBalance(...)` and then immediately overwrite it with `params.minPrimary = params.minPrimary * vaultSettings.poolSlippageLimitPercent / VAULT_PERCENT_BASIS`, with no read of `params.callbackData.oracleSlippagePercent` (or `secondaryTradeParams` decoded form). The functio"
    WIKI_EXPLOIT_SCENARIO = "A leveraged-vault user opens a position with a settlement type that allows up to 5% slippage. Months later real slippage on the underlying Balancer pool spikes to 2% (still within user tolerance, but above the global 1% `balancerPoolSlippageLimitPercent`). The user calls settlement; `_executeSettlement` overrides their 5% threshold with the global 1% cap, computes a min-out so tight that the actua"
    WIKI_RECOMMENDATION = "After computing the oracle-derived baseline, decode the user's `oracleSlippagePercent` from `params.callbackData` (or `params.secondaryTradeParams`) and apply it: `params.minPrimary = params.minPrimary * (poolSlippageLimit - userOracleSlippagePercent) / VAULT_PERCENT_BASIS`. Validate the user input "

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '_executeSettlement|executeSettlement|_settleVault|_redeem.*Settle|_executeRedeem.*Settle'}]
    _MATCH = [{'function.kind': 'internal'}, {'function.name_matches': '_executeSettlement|_settleVault|_executeRedeem.*Settlement'}, {'function.body_contains_regex': '\\bparams\\.(minPrimary|minOut|minAmountOut|minAmount|minOutput)\\s*=\\s*[A-Za-z_]\\w*\\.?_?get(TimeWeighted|Oracle|Internal)'}, {'function.body_contains_regex': '\\bparams\\.(minPrimary|minOut|minAmountOut|minAmount|minOutput)\\s*=\\s*params\\.\\1\\s*\\*\\s*\\w+\\.(vaultSettings|poolSlippageLimit|globalSlippage)'}, {'function.body_not_contains_regex': 'oracleSlippagePercent|userSlippagePercent|callbackData\\.|abi\\.decode\\(\\s*params\\.(secondaryTradeParams|callbackData)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — min-output-overwritten-by-internal-calc-ignoring-user-slippage: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
