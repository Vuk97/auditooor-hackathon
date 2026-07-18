"""
adapter-routed-call-emits-event-with-self-origin — generated from reference/patterns.dsl/adapter-routed-call-emits-event-with-self-origin.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py adapter-routed-call-emits-event-with-self-origin.yaml
Source: cantina-polymarket-49
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AdapterRoutedCallEmitsEventWithSelfOrigin(AbstractDetector):
    ARGUMENT = "adapter-routed-call-emits-event-with-self-origin"
    HELP = "Adapter forwards a callee call with `address(this)` (or its own `msg.sender`) in both caller and `to` positions. The callee's event then carries adapter-on-adapter as indexed topics — original user origin is lost from the event log. Off-chain indexers cannot attribute the action to the user."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/adapter-routed-call-emits-event-with-self-origin.yaml"
    WIKI_TITLE = "Adapter-routed callee call emits event with adapter-as-self origin, losing user attribution"
    WIKI_DESCRIPTION = "When an Adapter / Router / Wrapper / Forwarder contract exposes an external function (e.g. `splitPosition(user, amount)`) that forwards work to a callee contract (e.g. `CollateralToken.unwrap(_to: address(this), amount)`), the callee's event (`Unwrapped(msg.sender, to, amount)`) records `(adapter, adapter, amount)` as indexed topics. The original `user` parameter — the only entity that observably "
    WIKI_EXPLOIT_SCENARIO = "CtfCollateralAdapter.splitPosition(user, amount) calls CollateralToken.unwrap(_to: address(this), amount). CollateralToken emits Unwrapped(msg.sender=adapter, to=adapter, amount). The original `user` is never indexed. An off-chain TVL indexer (Dune, internal accounting, governance attribution) joins on the (caller, to) topic pair and books the unwrap against the adapter's own balance — causing per"
    WIKI_RECOMMENDATION = "Either (a) pass `user` (or `msg.sender`) into the callee directly so the callee's event records the real origin (preferred — matches sibling `mergePositions` / `redeemPosition` paths), or (b) emit a dedicated adapter-side event `RoutedSplit(user, amount, ...)` carrying the originating user as an ind"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(Adapter|Router|Wrapper|Proxy|Forwarder|Hook|Bridge)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(splitPosition|mergePositions|redeemPosition|convertPositions|forward|routeFor|executeFor)'}, {'function.body_contains_regex': '(?i)(\\.\\s*(?:unwrap|wrap|transfer|burn|mint)\\s*\\(\\s*(?:msg\\.sender|address\\(this\\))|\\.\\s*\\w+\\s*\\(\\s*(?:address\\(this\\)|msg\\.sender)\\s*,\\s*(?:address\\(this\\)|msg\\.sender))'}, {'function.not_body_contains_regex': '(?i)(emit\\s+\\w+\\s*\\(\\s*(?:user|from|origin|original))'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — adapter-routed-call-emits-event-with-self-origin: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
