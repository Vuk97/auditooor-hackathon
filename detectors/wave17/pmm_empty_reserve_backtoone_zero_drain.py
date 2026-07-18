"""
pmm-empty-reserve-backtoone-zero-drain — generated from reference/patterns.dsl/pmm-empty-reserve-backtoone-zero-drain.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py pmm-empty-reserve-backtoone-zero-drain.yaml
Source: auditooor-R75-c4-lending-abracadabra-193
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PmmEmptyReserveBacktooneZeroDrain(AbstractDetector):
    ARGUMENT = "pmm-empty-reserve-backtoone-zero-drain"
    HELP = "PMM sellX function's `backToOnePayX = state.X0 - state.X` collapses to 0 when reserve is empty. The `payAmount == backToOnePayAmount` branch then fires for pay=0, returning the other-side reserve as receive amount. Free drain."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/pmm-empty-reserve-backtoone-zero-drain.yaml"
    WIKI_TITLE = "PMM pricing allows zero-pay drain when target reserve empty"
    WIKI_DESCRIPTION = "DODO-style Proactive Market Maker math handles three regimes (R = ONE, ABOVE_ONE, BELOW_ONE) based on how far the reserve has drifted from target. In the ABOVE_ONE / BELOW_ONE regime, `backToOnePay = target - reserve` represents the amount needed to drag the AMM back to balanced. When the reserve on that side is fully empty (`reserve = target = 0`), the quantity collapses to zero. Code then hits t"
    WIKI_EXPLOIT_SCENARIO = "Pool has 1000 USDC (base) + 1000 DAI (quote). Attacker drains quote via legit swap → Q=0, Q0=0, R=ABOVE_ONE. Attacker calls `querySellQuote(0)`. Inside: `backToOnePayQuote = 0 - 0 = 0`. Branch `payQuoteAmount == backToOnePayQuote` is true (0 == 0). `receiveBaseAmount = state.B - state.B0 = 1000 - 0 = 1000`. Attacker receives 1000 USDC base for 0 quote. Pool is drained."
    WIKI_RECOMMENDATION = "Reject zero-input swaps at function entry: `require(payAmount > 0, \"ZeroPay\");`. Also assert the target reserves are non-zero before pricing: `require(state.B0 > 0 && state.Q0 > 0, \"PoolUninit\");`. When handling equality branches, confirm `backToOnePay > 0` before using it as a signal."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(PMM|MagicLp|querySell|DODO|sellBaseToken|sellQuoteToken)'}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.name_matches': '(?i)(sellBaseToken|sellQuoteToken|_?querySell|_?querySellBase|_?querySellQuote|_?sellBase|_?sellQuote)'}, {'function.body_contains_regex': '(?i)backToOne(PayBase|PayQuote|ReceiveBase|ReceiveQuote)\\s*=\\s*state\\.(B0|Q0)\\s*-\\s*state\\.(B|Q)'}, {'function.body_not_contains_regex': '(?i)(payBaseAmount\\s*==\\s*0|payQuoteAmount\\s*==\\s*0|payAmount\\s*>\\s*0|require\\s*\\(\\s*pay\\w*Amount\\s*>\\s*0|state\\.(B0|Q0)\\s*>\\s*0|state\\.(B0|Q0)\\s*!=\\s*0)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — pmm-empty-reserve-backtoone-zero-drain: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
