"""
curator-cooldown-bypass-via-refund-reentrancy — generated from reference/patterns.dsl/curator-cooldown-bypass-via-refund-reentrancy.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py curator-cooldown-bypass-via-refund-reentrancy.yaml
Source: auditooor-R75-code4rena-2024-08-phi-25
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CuratorCooldownBypassViaRefundReentrancy(AbstractDetector):
    ARGUMENT = "curator-cooldown-bypass-via-refund-reentrancy"
    HELP = "buy/trade refunds excess ETH before writing the cooldown timestamp — attacker re-enters during the refund and bypasses the cooldown flashloan guard."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/curator-cooldown-bypass-via-refund-reentrancy.yaml"
    WIKI_TITLE = "Refund-before-cooldown-update lets flashloan bypass anti-flashloan guard"
    WIKI_DESCRIPTION = "A cooldown-based flashloan mitigation writes `lastTradeTimestamp[credId][curator] = block.timestamp` at the end of the buy path. Immediately before, the function refunds excess ETH to the buyer via `msg.sender.call{value: ...}`. An attacker whose fallback re-enters during the refund finds the cooldown still at its previous (stale) value and can call `sell`/`distribute` to extract rewards acquired "
    WIKI_EXPLOIT_SCENARIO = "Attacker uses flashloan to buy 100 shares (intentionally overpaying so excess is refunded). During the refund callback they call `distribute(credId)` and then `sell(100)`. The sell succeeds because `block.timestamp - lastTradeTimestamp` still reads as the previous trade. Attacker repays flashloan and keeps a large slice of reward distribution."
    WIKI_RECOMMENDATION = "Update `lastTradeTimestamp` before sending the refund (strict CEI). Alternatively, use nonReentrant and refund via pull-payment. Add a re-entrancy test using a malicious `receive()` that attempts sell during refund."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.name_matches': '(?i)_?handleTrade|_?buyShare|_?buySubject|_?_trade'}, {'function.body_contains_regex': '(?i)safeTransferETH|call\\{value:|\\.transfer\\(|sendValue'}, {'function.body_contains_regex': '(?i)lastTradeTimestamp|cooldown\\w*|lastBuyTime'}, {'function.body_contains_regex_ordered': ['(?i)safeTransferETH|call\\{value:', '(?i)lastTradeTimestamp\\s*\\[[^\\]]*\\]\\s*(\\[[^\\]]*\\])?\\s*=\\s*block\\.timestamp']}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — curator-cooldown-bypass-via-refund-reentrancy: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
