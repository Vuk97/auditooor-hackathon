"""
pause-asymmetric-deposit-vs-withdraw — generated from reference/patterns.dsl/pause-asymmetric-deposit-vs-withdraw.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py pause-asymmetric-deposit-vs-withdraw.yaml
Source: code4arena/slice_ac-Kinetiq-M02
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PauseAsymmetricDepositVsWithdraw(AbstractDetector):
    ARGUMENT = "pause-asymmetric-deposit-vs-withdraw"
    HELP = "A Pausable contract guards the deposit / stake / submit path with `whenNotPaused` but the matching withdrawal-confirmation or redemption path has no pause check. The pause lever is therefore one-sided and cannot fully halt funds in emergencies."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/pause-asymmetric-deposit-vs-withdraw.yaml"
    WIKI_TITLE = "Asymmetric pause guard: deposit gated, withdraw-confirm unguarded (or vice-versa)"
    WIKI_DESCRIPTION = "Pausable systems rely on pairing guards across every direction of value flow. Missing `whenNotPaused` on one side of a paired flow (deposit vs confirmWithdrawal, stake vs unstake) breaks the 'emergency pause' invariant: an admin can no longer stop both sides, leaving the protocol exposed even when half the system is frozen."
    WIKI_EXPLOIT_SCENARIO = "Kinetiq pauses staking after discovering an oracle issue. `stake()` reverts with `Paused`. But `confirmWithdrawal()` is unguarded, so a whale who queued 10% of TVL right before the pause can still dequeue and pull funds — crystallizing the bad oracle read into real loss."
    WIKI_RECOMMENDATION = "For every `whenNotPaused`-guarded path, ensure the paired inverse path shares the same guard. Alternatively use a two-level pause (deposit-only-paused vs total-paused) to make the asymmetry explicit instead of accidental."

    _PRECONDITIONS = [{'contract.inherits_none_of': []}, {'contract.source_matches_regex': 'Pausable|paused\\(\\)|whenNotPaused'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(confirmWithdraw|confirmWithdrawal|finalizeWithdraw|completeWithdraw|settleWithdraw|executeWithdraw|claimWithdraw|redeem)'}, {'function.body_not_contains_regex': 'whenNotPaused|require\\s*\\(\\s*!paused'}, {'function.body_not_contains_regex': '_requireNotPaused'}, {'contract.has_function_body_matching': 'function\\s+(deposit|submit|stake)[^{]*whenNotPaused'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — pause-asymmetric-deposit-vs-withdraw: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
