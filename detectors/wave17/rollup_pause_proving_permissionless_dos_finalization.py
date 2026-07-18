"""
rollup-pause-proving-permissionless-dos-finalization — generated from reference/patterns.dsl/rollup-pause-proving-permissionless-dos-finalization.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py rollup-pause-proving-permissionless-dos-finalization.yaml
Source: auditooor-R75-c4-mined-2024-03-taiko-62
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RollupPauseProvingPermissionlessDosFinalization(AbstractDetector):
    ARGUMENT = "rollup-pause-proving-permissionless-dos-finalization"
    HELP = "A rollup/bridge exposes `pauseProving()` / `pauseExits()` as external and state-mutating but lacks any access-control modifier. Anyone can toggle the pause flag, stalling the proving/verifying/withdrawal pipeline indefinitely. Finalization halts, L2->L1 withdrawals freeze, and every time a guardian "
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/rollup-pause-proving-permissionless-dos-finalization.yaml"
    WIKI_TITLE = "Rollup pauseProving is permissionless, enabling indefinite finalization halt"
    WIKI_DESCRIPTION = "`pauseProving(bool _pause)` is declared `external` and writes `_state.slotB.provingPaused = _pause`. It has no onlyOwner/onlyAdmin modifier. `proveBlock` and `verifyBlocks` both use `whenProvingNotPaused`. An attacker calls `pauseProving(true)` every block, ensuring the flag can never be sustained as false by an honest admin. No proofs can be submitted, no blocks finalize, and L1 withdrawals (whic"
    WIKI_EXPLOIT_SCENARIO = "1. Attacker monitors mempool for any `pauseProving(false)` tx from admin. 2. Attacker frontruns with `pauseProving(true)`. 3. Admin's unpause reverts with `L1_INVALID_PAUSE_STATUS` (already paused). 4. Attacker repeats. Every proof / verify / finalization halts. L1→L2 deposits still queue up but cannot be finalized on L2; L2→L1 withdrawals held by Merkle-root dispatch freeze. Rollup is effectively"
    WIKI_RECOMMENDATION = "Add `onlyOwner`/`onlyAdmin`/`onlyRole(PAUSER_ROLE)` to `pauseProving` (and sibling `pauseBridge`/`pauseExits`). Canonical test: deploy, simulate non-owner calling pauseProving → must revert with 'AccessDenied'. Additionally, require a deadman-switch: pauseProving can only stay paused for N blocks be"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'LibProving|Rollup|TaikoL1|StateBridge'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(pauseProving|pauseProof|pauseBridge|pauseFinalization|pauseExits|pauseRollup)$'}, {'function.body_contains_regex': '_state\\.\\w+\\.\\w+Paused\\s*=\\s*_pause|paused\\s*=\\s*_pause|provingPaused\\s*=\\s*_pause'}, {'function.body_not_contains_regex': '(onlyOwner|onlyAdmin|only\\w+|_authorizePause|hasRole\\s*\\(|require\\s*\\(\\s*msg\\.sender\\s*==\\s*owner|accessControl)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — rollup-pause-proving-permissionless-dos-finalization: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
