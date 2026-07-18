"""
pending-tx-state-mutex-missing — generated from reference/patterns.dsl/pending-tx-state-mutex-missing.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py pending-tx-state-mutex-missing.yaml
Source: auditooor-cross-cluster
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PendingTxStateMutexMissing(AbstractDetector):
    ARGUMENT = "pending-tx-state-mutex-missing"
    HELP = "Function sets an in-flight/pending/executing mutex before an external call but never clears it on revert. If the external call reverts, the mutex stays stuck at `true` forever — the function is bricked for all future callers."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/pending-tx-state-mutex-missing.yaml"
    WIKI_TITLE = "Pending-tx mutex never cleared on revert — one failed call bricks the function forever"
    WIKI_DESCRIPTION = "The contract gates concurrent invocations with a boolean mutex (pending / status / executing / _locked / inFlight). The happy path sets the flag to true, performs an external call, and sets it back to false. When the external call reverts, Solidity unwinds all state writes — including the mutex set — but any path that does NOT use try/catch will also unwind the caller's frame. The real bug appears"
    WIKI_EXPLOIT_SCENARIO = "A cross-chain bridge contract sets `inFlight[msgId] = true` when a user calls `send()`, then emits the message and expects `receive()` on the destination chain to clear the flag. An attacker routes through a destination chain where the relayer is offline. The flag is never cleared. Every subsequent `send()` from this user reverts on `require(!inFlight[msgId], 'already pending')`. The user can neve"
    WIKI_RECOMMENDATION = "Use try/catch around the external call and reset the mutex in the catch block. Alternatively, make the mutex time-bounded (`require(block.timestamp > startedAt[msgId] + TIMEOUT)`) so a stuck flag self-heals. Never rely on an unbounded async callback to clear a liveness-critical mutex."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'pending|status|executing|locked|inFlight|processing'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': 'pending\\[.*\\]\\s*=\\s*true|status\\[.*\\]\\s*=\\s*1|executing\\s*=\\s*true|_locked\\s*=\\s*true|inFlight\\s*=\\s*true'}, {'function.has_external_call': True}, {'function.body_not_contains_regex': 'try\\s+|catch\\s*\\{|pending\\[.*\\]\\s*=\\s*false|status\\s*=\\s*0|executing\\s*=\\s*false|_locked\\s*=\\s*false'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — pending-tx-state-mutex-missing: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
