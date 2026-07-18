"""
integer-overflow-clamp-arithmetic-loss - generated from reference/patterns.dsl/integer-overflow-clamp-arithmetic-loss.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py integer-overflow-clamp-arithmetic-loss.yaml
Source: auditooor-fire4-rwrq-integer-overflow-clamp-19086bdd96a5
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class IntegerOverflowClampArithmeticLoss(AbstractDetector):
    ARGUMENT = "integer-overflow-clamp-arithmetic-loss"
    HELP = "Arithmetic path loses a clamp, saturation floor, or sentinel branch across confirmed fee-truncation, bond-debt underflow, and unchecked bonding-curve multiplication shapes."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/integer-overflow-clamp-arithmetic-loss.yaml"
    WIKI_TITLE = "Integer arithmetic clamp loss permits fee truncation, decay underflow, or unchecked curve multiplication"
    WIKI_DESCRIPTION = "Confirmed integer-overflow-clamp samples share one source shape: a financial arithmetic path computes a boundary-sensitive value without the branch or saturation that preserves the intended sentinel case. The anchors are protocol-fee truncation when LP fee is zero, bond debt decay that subtracts below zero, and bonding-curve buy logic that multiplies inside unchecked arithmetic."
    WIKI_EXPLOIT_SCENARIO = "A swap engine uses a rounded generic protocol-fee formula even when the whole fee belongs to the protocol, a bond market returns lastDebt - decay after a long idle period, or a bonding-curve buy path multiplies desired tokens by a curve coefficient inside unchecked arithmetic. Each path drops the clamp that should preserve the exact boundary value."
    WIKI_RECOMMENDATION = "Add the missing boundary branch or saturating arithmetic. For fee splitting, special-case all-protocol-fee swaps. For debt decay, floor at zero or subtract Math.min(debt, decay). For bonding curves, remove unchecked multiplication or cap operands before multiplying."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(protocolFee|lpFee|PIPS|debt|decay|bond|curve|NLAMM|theta|slope|step|coefficient|curveK|virtualReserve)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '(?i)^(quote|swap|_swap|computeSwap|swapStep|debtDecay|_currentDebt|_decayDebt|marketPrice|_marketPrice|findMarketFor|_updateDebt|totalDebt|buy|purchase|mint|deposit|invest|enter)\\w*$'}, {'function.body_contains_regex': '(?s)(protocolFee\\s*\\/\\s*(PIPS|1_?000_?000|1e6)|\\*\\s*protocolFee\\s*\\/|debt\\s*-\\s*decay|lastDebt\\s*-\\s*|totalDebt\\s*-=\\s*|unchecked\\s*\\{[^}]*\\*[^}]*\\})'}, {'function.body_contains_regex': '(?is)(amountIn\\s*\\+\\s*feeAmount|step\\.amountIn\\s*\\+\\s*step\\.feeAmount|debt|decay|lastDebt|totalDebt|(amount|value|desired|tokensOut|shares|qty|cost|toMint|mintAmount)\\s*\\*\\s*(scale|theta|k|slope|coefficient|curveK|step|factor|priceFactor|reserve|virtualReserve)|(scale|theta|k|slope|coefficient|curveK|step|factor|priceFactor|reserve|virtualReserve)\\s*\\*\\s*(amount|value|desired|tokensOut|shares|qty|cost|toMint|mintAmount))'}, {'function.body_not_contains_regex': '(?is)(swapFee\\s*==\\s*protocolFee|lpFee\\s*==\\s*0\\s*\\?.*feeAmount|Math\\.min|decay\\s*>\\s*lastDebt\\s*\\?\\s*0\\s*:|if\\s*\\([^)]*debt\\s*>=?|require\\s*\\([^;]*(desired|amount|value)\\s*<=?\\s*(MAX|maxBuy|maxAmount|type\\s*\\(\\s*uint\\d+\\s*\\)\\.max|2\\s*\\*\\*\\s*\\d+)|FullMath\\.mulDiv\\s*\\(|MulDiv\\s*\\(|SafeMath\\.mul\\s*\\(|Math\\.mulDiv\\s*\\()'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" - integer-overflow-clamp-arithmetic-loss: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
