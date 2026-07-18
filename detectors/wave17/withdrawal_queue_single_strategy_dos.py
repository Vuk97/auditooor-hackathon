"""
withdrawal-queue-single-strategy-dos — generated from reference/patterns.dsl/withdrawal-queue-single-strategy-dos.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py withdrawal-queue-single-strategy-dos.yaml
Source: solodit/C0213
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class WithdrawalQueueSingleStrategyDos(AbstractDetector):
    ARGUMENT = "withdrawal-queue-single-strategy-dos"
    HELP = "Batch withdrawal processor iterates a queue/strategy list with no try/catch or skip-on-fail; a single failing entry reverts the whole batch and DoS's every pending user withdrawal."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/withdrawal-queue-single-strategy-dos.yaml"
    WIKI_TITLE = "Batch withdrawal queue DoS: one failing strategy/request blocks all pending redeems"
    WIKI_DESCRIPTION = "Vaults and staking systems batch user withdrawal requests or strategy unwinds into a single processor loop. When the loop has no per-iteration try/catch and no skip-on-fail branch, any single reverting entry — a malicious strategy, a griefing request, a token with a transfer hook that reverts — propagates up and reverts the whole call. Every other pending user is blocked until the bad entry is sur"
    WIKI_EXPLOIT_SCENARIO = "An attacker submits a withdrawal request backed by a token whose transfer() reverts on a condition they control (e.g., a blacklist, a pause, a hook that reads mutable state). Every subsequent `processWithdrawals()` call iterates the queue, hits the poisoned entry, reverts, and rolls back all legitimate withdrawals processed in the same batch. Honest users cannot exit until the attacker's request i"
    WIKI_RECOMMENDATION = "Wrap each per-entry call in try/catch (Solidity 0.6+), record the failure, skip the entry, and continue the loop. Emit a `WithdrawalSkipped` event so operators can triage. For strategy-array processors, additionally guard against reentrancy and enforce that only whitelisted strategies can be enqueue"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(withdrawQueue|pendingWithdrawals|withdrawRequests|redeemQueue|strategies)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(processWithdrawals|redeem|claimWithdrawals|executeWithdrawals|_processQueue|dequeueWithdrawals)'}, {'function.body_contains_regex': '(for\\s*\\(.*length|while\\s*\\(|\\.forEach|strategies\\[|queue\\[)'}, {'function.body_not_contains_regex': '(try\\s+|catch\\s*\\{|continue;|if\\s*\\(\\s*!\\s*success\\s*\\)\\s*\\{|skip)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — withdrawal-queue-single-strategy-dos: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
