"""
optimistic-proposal-consumed-before-window - generated from reference/patterns.dsl/optimistic-proposal-consumed-before-window.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py optimistic-proposal-consumed-before-window.yaml
Source: auditooor capability lift 2026-06-02 sibling generalizer
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class OptimisticProposalConsumedBeforeWindow(AbstractDetector):
    ARGUMENT = "optimistic-proposal-consumed-before-window"
    HELP = "Optimistic proposal execution or installation consumes queued proposal state before proving that the liveness window elapsed cleanly."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/optimistic-proposal-consumed-before-window.yaml"
    WIKI_TITLE = "Optimistic proposal consumed before liveness finalization"
    WIKI_DESCRIPTION = "A public proposal consumer executes a target call, selector installation, role grant, or upgrade from queued proposal state without requiring the challenge window to be closed, unchallenged, uncancelled, and bound to the current payload commitment."
    WIKI_EXPLOIT_SCENARIO = "Optimistic proposal execution or installation consumes queued proposal state before proving that the liveness window elapsed cleanly."
    WIKI_RECOMMENDATION = "Before consuming queued proposal state, require the liveness window to have elapsed, require no challenge or cancel flag, and bind execution to the current proposal hash or operation id."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(proposal|proposals|optimistic|govern|timelock|challenge|challenged|dispute|liveUntil|readyAt|eta|selector|payload)'}, {'contract.has_state_var_matching': '(?i)(proposal|proposals|payload|selector|target|challenge|dispute|liveUntil|readyAt|eta|queued|pending|executed|applied)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i).*(execute|apply|finalize|resolve|enact).*(proposal|payload|change|selector|upgrade)?.*'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.body_contains_regex': '(?i)(Proposal\\s+storage|proposals\\s*\\[|_proposals\\s*\\[|pendingProposal|queuedProposal|proposalPayload|payloadHash|proposalHash)'}, {'function.body_contains_regex': '(?i)(\\.call\\s*\\(|\\.delegatecall\\s*\\(|\\.\\s*set[A-Z][A-Za-z0-9_]*\\s*\\(|grantRole\\s*\\(|upgradeTo\\s*\\(|selectorTarget\\s*\\[|moduleForSelector\\s*\\[)'}, {'function.body_not_contains_regex': '(?i)(challenged|unchallenged|dispute(Window|Period)?|liveUntil|readyAt|eta|delayEnd|gracePeriod|cancell?ed|block\\.timestamp\\s*>=|state\\s*\\(\\s*\\w+\\s*\\)\\s*==\\s*ProposalState\\.(Succeeded|Queued)|proposal(State|Version|Nonce|Salt)|currentHash|expectedHash|operationId|stale hash|window open)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" - optimistic-proposal-consumed-before-window: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
