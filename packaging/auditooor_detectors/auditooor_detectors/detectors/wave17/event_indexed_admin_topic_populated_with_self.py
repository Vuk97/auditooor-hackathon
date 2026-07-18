"""
event-indexed-admin-topic-populated-with-self — generated from reference/patterns.dsl/event-indexed-admin-topic-populated-with-self.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py event-indexed-admin-topic-populated-with-self.yaml
Source: polymarket-cantina-46
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EventIndexedAdminTopicPopulatedWithSelf(AbstractDetector):
    ARGUMENT = "event-indexed-admin-topic-populated-with-self"
    HELP = "A renounce/remove/revoke function on an Auth-shaped contract emits a two-indexed-topic event with the SAME address in both topics (typically `msg.sender, msg.sender`). The admin-attribution topic is destroyed; off-chain governance dashboards mis-attribute the action."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/event-indexed-admin-topic-populated-with-self.yaml"
    WIKI_TITLE = "Renounce-self event populates both indexed topics with the caller, destroying admin-attribution semantics"
    WIKI_DESCRIPTION = "Auth/Role/Permission contracts often declare role-mutation events with two indexed address topics — typically the subject (`operator`/`role-holder`) and the actor (`admin`/`granter`) — so that off-chain indexers and governance dashboards can join on the actor topic and reconstruct who performed each privileged change. When a self-renounce function reuses the same admin-removal event but passes `ms"
    WIKI_EXPLOIT_SCENARIO = "Polymarket CTFExchange `Auth.renounceOperatorRole()` emits `RemovedOperator(msg.sender, msg.sender)` against an event declared `RemovedOperator(address indexed removedOperator, address indexed admin)`. A Dune dashboard counting admin-driven removals by joining on the admin topic over-attributes removals to whichever admin coincidentally holds an operator role, and silently misses self-renounces en"
    WIKI_RECOMMENDATION = "Either (a) introduce a distinct event for the self-renounce path (e.g. `RenouncedOperatorRole(address indexed operator)`) so off-chain consumers can disambiguate by event signature, or (b) emit `address(0)` (or a sentinel) in the actor topic when the action is a self-renounce so indexers can filter "

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(Auth|Role|Access|Permission|Admin)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(renounce\\w+|remove\\w+|revoke\\w+)'}, {'function.body_contains_regex': 'emit\\s+\\w+\\s*\\(\\s*msg\\.sender\\s*,\\s*msg\\.sender\\s*\\)|emit\\s+\\w+\\s*\\(\\s*(\\w+)\\s*,\\s*\\1\\s*\\)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — event-indexed-admin-topic-populated-with-self: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
