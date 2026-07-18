"""
setter-missing-event-emission — generated from reference/patterns.dsl/setter-missing-event-emission.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py setter-missing-event-emission.yaml
Source: solodit-cluster/C0018
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SetterMissingEventEmission(AbstractDetector):
    ARGUMENT = "setter-missing-event-emission"
    HELP = "Privileged setter (set*/update*/change*/configure* gated by onlyOwner / onlyAdmin / onlyRole / onlyGovernance) mutates state without emitting any event. Off-chain indexers and governance dashboards cannot track the configuration change."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/setter-missing-event-emission.yaml"
    WIKI_TITLE = "Privileged setter missing event emission"
    WIKI_DESCRIPTION = "A state-mutating setter on a privileged surface (onlyOwner, onlyAdmin, onlyRole, onlyGovernance, onlyTimelock, onlyManager) updates critical protocol configuration — owner, fee, treasury receiver, oracle, rate, strategy — without emitting any event. Off-chain indexers, subgraphs, monitoring dashboards, governance explorers, and reconciliation pipelines reconstruct protocol configuration from event"
    WIKI_EXPLOIT_SCENARIO = "Governance calls `setFeeReceiver(newTreasury)` to redirect protocol revenue. The function writes the new address but emits no event. The public dashboard that displays the current treasury continues to show the stale address for days; users and analysts cannot distinguish a legitimate rotation from a compromised-multisig redirection. Forensic reconstruction after an incident requires a full state "
    WIKI_RECOMMENDATION = "Emit an event on every privileged state mutation. Declare a descriptive event (e.g. `event FeeReceiverUpdated(address indexed previous, address indexed next)`) and emit it at the end of the setter with both the old and new value. For setters that write multiple fields, emit one event per logical cha"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(set|update|change|configure)[A-Z][A-Za-z0-9_]+$'}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyAdmin', 'onlyRole', 'onlyRoles', 'onlyGovernance', 'onlyGovernor', 'onlyGov', 'onlyTimelock', 'onlyManager', 'onlyAuthorized'], 'negate': False}}, {'function.writes_storage_matching': '.*'}, {'function.body_not_contains_regex': 'emit\\s+\\w+\\s*\\(|_emitEvent\\s*\\('}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — setter-missing-event-emission: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
