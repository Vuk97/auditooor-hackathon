"""
certora-state-machine-forward-transition-only — generated from reference/patterns.dsl/certora-state-machine-forward-transition-only.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py certora-state-machine-forward-transition-only.yaml
Source: certora-examples/StateMachine/forwardOnly
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CertoraStateMachineForwardTransitionOnly(AbstractDetector):
    ARGUMENT = "certora-state-machine-forward-transition-only"
    HELP = "State-machine field is rewritten without an equality-check against the expected predecessor — Certora `forwardOnly` invariant violated."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/certora-state-machine-forward-transition-only.yaml"
    WIKI_TITLE = "Status transition without predecessor check (backward move enables replay)"
    WIKI_DESCRIPTION = "Certora's canonical state-machine spec enforces: for every status transition `s -> s'`, s must be the documented predecessor of s'. The enforcement is almost always a `require(current == EXPECTED)` before the write. A mutator that writes `entry.status = Closed` without that guard lets a closed entry be re-opened, or an un-created entry be jumped past initialization. Symptoms include orders that re"
    WIKI_EXPLOIT_SCENARIO = "Prediction-market order lifecycle: NEW → FILLED → CANCELED. The cancel path writes `order.status = Canceled` and refunds. A patch adds `refundOrder(id)` that re-sets status to NEW (for user convenience) without checking current. Attacker places an order, fills it partially, then calls `refundOrder` — status reverts to NEW, attacker re-cancels and receives a second refund. Net drain: one refund fre"
    WIKI_RECOMMENDATION = "Every state write must begin with `require(current == expectedPredecessor)`. Consider encoding the state machine as a library with a single `transition(from, to)` helper that encapsulates the check. Prove the Certora `forwardOnly` rule per status field."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(?i)(status|state|phase|stage|lifecycle|positionStatus|orderStatus|auctionState)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.writes_storage_matching': '(?i)(status|state|phase|stage|lifecycle|positionStatus|orderStatus|auctionState)'}, {'function.body_contains_regex': '(?i)\\.(status|state|phase|stage|positionStatus|orderStatus|auctionState)\\s*='}, {'function.body_not_contains_regex': '(?i)(require[^;]*(status|state|phase|stage|orderStatus|positionStatus|auctionState)|if\\s*\\([^)]*(status|state|phase|stage|orderStatus|positionStatus|auctionState)[^)]*==|assert[^;]*(status|state|phase|stage))'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — certora-state-machine-forward-transition-only: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
