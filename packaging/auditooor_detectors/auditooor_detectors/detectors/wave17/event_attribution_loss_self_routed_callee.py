"""
event-attribution-loss-self-routed-callee — generated from reference/patterns.dsl/event-attribution-loss-self-routed-callee.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py event-attribution-loss-self-routed-callee.yaml
Source: polymarket-cantina-49
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EventAttributionLossSelfRoutedCallee(AbstractDetector):
    ARGUMENT = "event-attribution-loss-self-routed-callee"
    HELP = "A function on an Adapter/Proxy/Collateral contract calls an external contract and passes address(this) as the recipient/_to/beneficiary argument — but the callee's event has an indexed topic for the recipient, so the originating user address is lost from the event log. Off-chain TVL and attribution "
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/event-attribution-loss-self-routed-callee.yaml"
    WIKI_TITLE = "Self-routed call passes proxy address as recipient, destroying user-level event attribution"
    WIKI_DESCRIPTION = "A function `f(...)` on a contract C (Adapter/Proxy/Collateral) calls an external target T and passes `address(C)` as the `_to` / `recipient` / `beneficiary` argument. T's event `Unwrapped(caller, asset, to, amount)` indexes `to`, so the event topic carries C's address rather than the originating user's address. Sibling functions on C that pass `msg.sender` are correct. The asymmetry means that spl"
    WIKI_EXPLOIT_SCENARIO = "Polymarket CtfCollateralAdapter.splitPosition(amount, recipient) internally calls CollateralToken.unwrap(_to: address(this), ...). The resulting Unwrapped event has the CtfCollateralAdapter's address as the `to` topic, not the original user's EOA. A Dune dashboard counting unwrap events by user to compute total volume gets the adapter's address for every split — the volume appears as a single enti"
    WIKI_RECOMMENDATION = "Change the caller-side parameter to pass msg.sender instead of address(this) wherever the user is the beneficiary:\n```solidity\n// Inside CtfCollateralAdapter.splitPosition:\n CollateralToken.unwrap(msg.sender, ...);  // not address(this)\n```\nFor cases where address(this) is the intended benefici"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(CTF|Collateral|Adapter|Proxy|Wrapper|Bridge)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(split|unwrap|mint|redeem|convert|offramp|bridge|transfer)'}, {'function.body_contains_regex': '(?i)(\\.unwrap\\(address\\s*\\(\\s*this\\s*\\)|\\.mint\\(address\\s*\\(\\s*this\\s*\\)|\\.redeem\\(address\\s*\\(\\s*this\\s*\\)|\\.transfer\\(address\\s*\\(\\s*this\\s*\\))'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)mock|test|fixture|interface'}]

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
                info = [f, f" — event-attribution-loss-self-routed-callee: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
