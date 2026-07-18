"""
r94-loop-unsafe-cast-uint256-to-uint128-no-safecast — generated from reference/patterns.dsl/r94-loop-unsafe-cast-uint256-to-uint128-no-safecast.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-unsafe-cast-uint256-to-uint128-no-safecast.yaml
Source: loop-cycle-83-sol-sibling
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopUnsafeCastUint256ToUint128NoSafecast(AbstractDetector):
    ARGUMENT = "r94-loop-unsafe-cast-uint256-to-uint128-no-safecast"
    HELP = "r94-loop-unsafe-cast-uint256-to-uint128-no-safecast"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-unsafe-cast-uint256-to-uint128-no-safecast.yaml"
    WIKI_TITLE = "r94-loop-unsafe-cast-uint256-to-uint128-no-safecast"
    WIKI_DESCRIPTION = "r94-loop-unsafe-cast-uint256-to-uint128-no-safecast"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-unsafe-cast-uint256-to-uint128-no-safecast"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(uint128|u128)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(updatePosition|updateFunding|updateReserves|updateBalance|updateShares|updateSupply|updateDebt|accrueInterest|accrueFees|accrueRewards|accrueFunding|recordTrade|recordDeposit|recordWithdraw|settleFunding|settlePosition|settleTrade|applyFunding|applyFees|applyRewards|convertToShares|convertToAssets|convertAmount|deposit|withdraw|mint|burn)$'}, {'function.source_matches_regex': 'uint128\\s*\\(\\s*\\w*(amount|balance|total|supply|reserve|shares|principal|debt)'}, {'function.not_source_matches_regex': '(SafeCast\\.toUint128|toU128\\s*\\(|u128::try_from)'}]

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
                info = [f, f" — r94-loop-unsafe-cast-uint256-to-uint128-no-safecast: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
