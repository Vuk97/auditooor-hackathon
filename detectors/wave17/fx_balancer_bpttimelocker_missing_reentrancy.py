"""
fx-balancer-bpttimelocker-missing-reentrancy — generated from reference/patterns.dsl/fx-balancer-bpttimelocker-missing-reentrancy.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fx-balancer-bpttimelocker-missing-reentrancy.yaml
Source: github:balancer/balancer-v3-monorepo@b100677
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FxBalancerBpttimelockerMissingReentrancy(AbstractDetector):
    ARGUMENT = "fx-balancer-bpttimelocker-missing-reentrancy"
    HELP = "BPTTimeLocker.withdrawBPT() burns lock tokens and transfers BPT but lacks a reentrancy guard. The _burn + safeTransfer pattern where state is deleted after transfer is exploitable via reentrancy on token callbacks."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fx-balancer-bpttimelocker-missing-reentrancy.yaml"
    WIKI_TITLE = "BPTTimeLocker.withdrawBPT missing nonReentrant modifier — burn-then-transfer reentrancy"
    WIKI_DESCRIPTION = "Token locker contracts that burn the lock token and then transfer the underlying asset without a reentrancy guard are vulnerable when the underlying token has transfer hooks (ERC777, ERC20 with callbacks). An attacker's receive hook can re-enter withdrawBPT before the unlock timestamp storage is deleted, re-checking a stale state and draining the locker."
    WIKI_EXPLOIT_SCENARIO = "Balancer LBP audit (2025): BPTTimeLocker.withdrawBPT has no nonReentrant modifier. An attacker creates a hook receiver, calls withdrawBPT, re-enters during safeTransfer (ERC777 hook), and withdraws again before _unlockTimestamps[id] is deleted."
    WIKI_RECOMMENDATION = "Add the nonReentrant (or ReentrancyGuardTransient for gas efficiency) modifier to withdrawBPT(). Additionally, ensure state updates (delete _unlockTimestamps, _burn) happen before external calls (safeTransfer) per checks-effects-interactions pattern."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '^withdrawBPT$|^withdraw$'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^withdrawBPT$|^withdraw$'}, {'function.body_contains_regex': '_burn|burn\\('}, {'function.body_contains_regex': 'safeTransfer|transfer\\('}, {'function.body_not_contains_regex': 'nonReentrant|ReentrancyGuard|_nonReentrantBefore'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fx-balancer-bpttimelocker-missing-reentrancy: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
