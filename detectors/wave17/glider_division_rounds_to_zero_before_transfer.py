"""
glider-division-rounds-to-zero-before-transfer — generated from reference/patterns.dsl/glider-division-rounds-to-zero-before-transfer.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-division-rounds-to-zero-before-transfer.yaml
Source: hexens-glider/division-rounding-to-zero-with-lp-token-minting
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderDivisionRoundsToZeroBeforeTransfer(AbstractDetector):
    ARGUMENT = "glider-division-rounds-to-zero-before-transfer"
    HELP = "Computed amount = numerator / divisor, then flows to a token transfer without a `require(amount > 0)` guard. When divisor > numerator the division rounds to 0, the transfer succeeds with zero tokens, and downstream shares/receipts still mint — classic free-share mint."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-division-rounds-to-zero-before-transfer.yaml"
    WIKI_TITLE = "Division rounds to zero before transfer — free-mint vector"
    WIKI_DESCRIPTION = "Integer division `a / b` returns 0 when `b > a`. If the quotient is used as a transfer amount AND receipt/share tokens are minted on the same call, an attacker supplies tiny `a` so the transfer sends 0 tokens but the receipt is still issued. Classic on assimilators, vaults, and LP minting paths."
    WIKI_EXPLOIT_SCENARIO = "Vault assimilator: `amount = (_amount * DECIMALS) / _rate; token.safeTransferFrom(msg.sender, address(this), amount); _mintShares(msg.sender, _amount);`. Attacker sets `_amount` small enough that `amount == 0`. Vault receives nothing, attacker gets shares proportional to `_amount`."
    WIKI_RECOMMENDATION = "After any division that feeds a transfer, assert `require(amount > 0, \"dust\")`. Prefer rounding-up for user-pays paths (mulDivUp) and reject zero outcomes explicitly."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'safeTransferFrom|safeTransfer|transferFrom'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '=\\s*[^;]*(\\/|\\.div\\()[^;]*;'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.body_contains_regex': '(safeTransferFrom|safeTransfer|transferFrom)\\s*\\('}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*\\w+\\s*>\\s*0[,\\)]|if\\s*\\(\\s*\\w+\\s*==\\s*0\\s*\\)\\s*revert|assert\\s*\\(\\s*\\w+\\s*>\\s*0'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-division-rounds-to-zero-before-transfer: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
