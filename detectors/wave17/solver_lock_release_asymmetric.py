"""
solver-lock-release-asymmetric — generated from reference/patterns.dsl/solver-lock-release-asymmetric.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py solver-lock-release-asymmetric.yaml
Source: solodit-cluster-C0118
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SolverLockReleaseAsymmetric(AbstractDetector):
    ARGUMENT = "solver-lock-release-asymmetric"
    HELP = "Solver-lock release function zeroes only a subset of the slots the acquire path sets, leaving residual lock-state that traps subsequent solvers or causes double-increment of callIndex."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/solver-lock-release-asymmetric.yaml"
    WIKI_TITLE = "Asymmetric solver lock acquire/release"
    WIKI_DESCRIPTION = "Intent-based protocols pair an acquire step (`_trySolverLock`) with a release step (`_releaseSolverLock`) that should restore every slot the acquire mutated. The clustered findings show release paths that zero only the primary `solver` slot but leave `callIndex`, `claimant`, or `inFlight` populated from the acquire. Subsequent solvers see a half-reset state and either (a) revert on the `require(ca"
    WIKI_EXPLOIT_SCENARIO = "Alice (solver 1) acquires the lock on intent #7 — `_trySolverLock` sets solver = alice, callIndex = 1, claimant = alice. Alice's fill fails and `_releaseSolverLock` runs, which only clears `solver`. callIndex stays at 1 and claimant stays at alice. Bob (solver 2) tries to acquire — the acquire increments callIndex to 2 (the 'incremented twice' finding), which bricks the per-intent accounting. Alte"
    WIKI_RECOMMENDATION = "Replace the explicit slot-by-slot reset with a single `delete solverContext` struct-delete that zeros every field in one op; OR add a unit test that asserts post-release storage equals pre-acquire storage for every slot the acquire touches. Use a transient-storage pattern (EIP-1153) when the lock is"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '(trySolverLock|acquireSolverLock|_trySolverLock|_acquireSolverLock)'}, {'contract.has_function_matching': '(releaseSolverLock|_releaseSolverLock|unlockSolver)'}]
    _MATCH = [{'function.kind': 'internal|external_or_public'}, {'function.name_matches': '^(_releaseSolverLock|releaseSolverLock|unlockSolver)$'}, {'function.writes_storage_matching': '(solver|lock|locked|callIndex|claimant|inFlight)'}, {'function.body_contains_regex': '(solver\\s*=\\s*address\\s*\\(\\s*0\\s*\\)|solverLock\\s*=\\s*0|locked\\s*=\\s*false|delete\\s+solverState)'}, {'function.body_not_contains_regex': 'delete\\s+(solverContext|solverState|lockState|ctx)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — solver-lock-release-asymmetric: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
