"""
pending-state-external-call-without-terminal-reset - generated from reference/patterns.dsl/pending-state-external-call-without-terminal-reset.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py pending-state-external-call-without-terminal-reset.yaml
Source: auditooor state-corruption-via-race lane 2026-06-02
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PendingStateExternalCallWithoutTerminalReset(AbstractDetector):
    ARGUMENT = "pending-state-external-call-without-terminal-reset"
    HELP = "A pending transaction state is marked active before an external dispatcher call, but the function has no terminal reset, timeout, nonce, or version guard."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/pending-state-external-call-without-terminal-reset.yaml"
    WIKI_TITLE = "Pending state external call has no terminal reset"
    WIKI_DESCRIPTION = "A public function marks a transaction, request, or message as pending before invoking an external dispatcher. Without a same-path reset, timeout, nonce, or version guard, an interrupted or stale pending state can corrupt later settlement logic."
    WIKI_EXPLOIT_SCENARIO = "An attacker starts a request that marks its id as pending and routes through an external dispatcher. If the dispatcher never reaches the expected terminal path, later attempts with the same id are blocked or settle against stale pending state."
    WIKI_RECOMMENDATION = "Bind pending state to a nonce or version, add a timeout or cancellation path, and clear or terminalize the state in a try/catch or equivalent failure path."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(pending|inFlight|executing|processing|status|request|message|txId|msgId|relay|bridge|dispatch|settle|finalize)'}, {'contract.has_state_var_matching': '(?i)(pending|inFlight|executing|processing|status|request|message|txState|transactionState)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_external_call': True}, {'function.pre_external_call_mutates_state': True}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.body_contains_regex': '(?i)(require\\s*\\(\\s*!\\s*(pending|inFlight|executing|processing)\\s*(\\[[^\\]]+\\])?|require\\s*\\([^)]*(status|state)\\s*(==|!=)\\s*(0|1|Status\\.(None|Pending|Ready)|State\\.(None|Pending|Ready))|pending\\s*\\[|inFlight\\s*\\[|executing\\s*=|processing\\s*=|\\.status\\s*=|state\\s*\\[)'}, {'function.body_contains_regex': '(?i)((pending|inFlight|executing|processing)\\s*(\\[[^\\]]+\\])?\\s*=\\s*(true|1|Status\\.Pending|State\\.Pending)|\\.status\\s*=\\s*(1|Status\\.Pending|State\\.Pending)|state\\s*\\[[^\\]]+\\]\\s*=\\s*(1|Status\\.Pending|State\\.Pending))'}, {'function.body_not_contains_regex': '(?i)(try\\s+|catch\\s*\\{|(pending|inFlight|executing|processing)\\s*(\\[[^\\]]+\\])?\\s*=\\s*(false|0|Status\\.None|State\\.None|Status\\.Complete|State\\.Complete)|\\.status\\s*=\\s*(0|Status\\.None|Status\\.Complete|State\\.None|State\\.Complete)|timeout|deadline|expiresAt|startedAt|block\\.timestamp|nonce|version|sequence|requestNonce|currentHash|expectedHash|finalized)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" - pending-state-external-call-without-terminal-reset: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
