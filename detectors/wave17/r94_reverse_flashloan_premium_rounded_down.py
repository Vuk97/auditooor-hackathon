"""
r94-reverse-flashloan-premium-rounded-down — generated from reference/patterns.dsl/r94-reverse-flashloan-premium-rounded-down.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-reverse-flashloan-premium-rounded-down.yaml
Source: reverse-port-from-rust_wave1
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94ReverseFlashloanPremiumRoundedDown(AbstractDetector):
    ARGUMENT = "r94-reverse-flashloan-premium-rounded-down"
    HELP = "Flash-loan premium uses floor division (amount * bps / 10000); rounds in the BORROWER's favour so protocol collects slightly less than the documented rate. Should use a ceil-div helper."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-reverse-flashloan-premium-rounded-down.yaml"
    WIKI_TITLE = "Flash-loan premium rounded down instead of up"
    WIKI_DESCRIPTION = "Integer division in Solidity truncates toward zero. When a flash-loan premium is computed as `premium = amount * feeBps / 10000`, any remainder is silently discarded in the borrower's favour. Over many loans this costs the protocol systematic wei-dust, and for small-amount loans the premium can round down to zero entirely. Fees owed TO the protocol MUST round up; fees owed BY the protocol (rewards"
    WIKI_EXPLOIT_SCENARIO = "Pool offers flash loans at `premium = amount * 9 / 10000` (0.09%, Aave V3 default). Attacker loans `amount = 11110`; the exact premium is 9.999 but floor-division gives 9. They repay 11119 instead of the intended 11120. Across 1M loans at varying denominations, the protocol is under-paid by roughly `0.5 * numLoans` wei per unit — an exploit amplifier for low-decimal assets or assets like GUSD (2 d"
    WIKI_RECOMMENDATION = "Use `Math.mulDiv(amount, feeBps, 10000, Math.Rounding.Up)` from OpenZeppelin or `mulDivUp(amount, feeBps, 10000)` from Solmate / FixedPointMathLib for any fee owed to the protocol. Do NOT use the same helper for rewards owed to users. Unit-test the path with `amount = 1` and confirm `premium >= 1`."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(flashLoan|flash|FlashLoan)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(flashLoan|_flashLoan|flashBorrow|flashFee|_flashFee|executeFlashLoan|_calculateFlashFee|_calculatePremium|flashLoanSimple)$'}, {'function.body_contains_regex': '\\b(premium|fee|flashFee|flashLoanPremium)\\s*=\\s*[^;]*\\*\\s*[^;]*\\s*/\\s*(10000|1e4|BASIS_POINTS|BPS|PRECISION|WAD|10\\*\\*18)'}, {'function.body_not_contains_regex': '(mulDivUp|mulDivRoundingUp|Math\\.Rounding\\.Up|ceilDiv|\\+\\s*(10000|1e4|BASIS_POINTS|BPS|PRECISION|WAD)\\s*-\\s*1|\\.divUp|_ceil|ceilMul|FixedPointMathLib\\.mulDivUp)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — r94-reverse-flashloan-premium-rounded-down: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
