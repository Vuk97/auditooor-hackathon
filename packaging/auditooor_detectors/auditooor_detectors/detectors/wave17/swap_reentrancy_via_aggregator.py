"""
swap-reentrancy-via-aggregator — generated from reference/patterns.dsl/swap-reentrancy-via-aggregator.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py swap-reentrancy-via-aggregator.yaml
Source: solodit-cluster-C0285
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SwapReentrancyViaAggregator(AbstractDetector):
    ARGUMENT = "swap-reentrancy-via-aggregator"
    HELP = "Payable aggregator/bridge swap wrapper performs an external call to a user-controllable router (1inch/LiFi/0x/paraswap) with no nonReentrant guard — reentry via the aggregator callback path can re-execute the swap or double-spend msg.value."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/swap-reentrancy-via-aggregator.yaml"
    WIKI_TITLE = "Swap reentrancy via external aggregator call"
    WIKI_DESCRIPTION = "A public payable function that wraps an external aggregator (1inch, LiFi, 0x, paraswap) forwards user-supplied calldata and msg.value to the router. Without a reentrancy guard, the router (or a token in the swap path with a transfer hook: ERC777, ERC1155, ERC223) can reenter the wrapper, causing the swap to be executed multiple times against a single msg.value deposit or letting a refund path be d"
    WIKI_EXPLOIT_SCENARIO = "A bridge exposes `swapAndBridge(router, calldata, bridgeParams) payable`. The wrapper calls `router.call{value: msg.value}(calldata)`. The attacker supplies a router contract they control. On invocation, the attacker's router reenters `swapAndBridge` before the outer call returns, observing the still-positive contract balance and dispatching a second bridge transfer on the same msg.value. Funds co"
    WIKI_RECOMMENDATION = "Apply OpenZeppelin's `nonReentrant` modifier (or an equivalent `lock` guard) to every external/public payable function that forwards control to a user-supplied aggregator address. Whitelist the aggregator callee when possible. Keep the function non-payable and settle msg.value via a separate escrow "

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(swap|swapTokens|swapAndBridge|swapViaAggregator|bridgeAndSwap|_swap)$'}, {'function.is_payable': True}, {'function.has_external_call': True}, {'function.has_modifier': {'includes': ['nonReentrant', 'reentrancyGuard', 'lock'], 'negate': True}}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — swap-reentrancy-via-aggregator: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
