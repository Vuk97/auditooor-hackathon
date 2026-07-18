"""
pausable-inherits-but-no-exposure — generated from reference/patterns.dsl/pausable-inherits-but-no-exposure.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py pausable-inherits-but-no-exposure.yaml
Source: solodit-cluster/C0216
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PausableInheritsButNoExposure(AbstractDetector):
    ARGUMENT = "pausable-inherits-but-no-exposure"
    HELP = "Contract inherits Pausable/PausableUpgradeable but the inherited _pause()/_unpause() hooks are never invoked by any function on the contract — the whenNotPaused / whenPaused modifiers cannot flip state, so the emergency brake is not reachable on the live deployment."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/pausable-inherits-but-no-exposure.yaml"
    WIKI_TITLE = "Pausable inherited but no pause/unpause exposure"
    WIKI_DESCRIPTION = "OpenZeppelin's Pausable and PausableUpgradeable provide internal _pause() / _unpause() hooks plus whenNotPaused / whenPaused modifiers. Inheriting Pausable only imports the storage flag and modifiers; an external admin-gated pause() / unpause() function must ALSO be authored on the inheriting contract for the emergency brake to be reachable. Contracts that inherit Pausable without ever invoking _p"
    WIKI_EXPLOIT_SCENARIO = "Protocol Y inherits PausableUpgradeable and decorates withdraw() with whenNotPaused, intending this as an emergency brake. Admin never authors a public pause() function. Months later, a critical oracle dependency is compromised. The admin attempts to halt withdrawals but has no on-chain lever — _pause() is internal, paused() is always false, and whenNotPaused always allows the call through. User f"
    WIKI_RECOMMENDATION = "Either (a) add an admin-gated public `pause()` / `unpause()` pair that calls `_pause()` / `_unpause()`, (b) remove the Pausable inheritance if pausability is not intended, or (c) document explicitly in the contract header that pausability is delegated to an external controller and the whenNotPaused "

    _PRECONDITIONS = [{'contract.source_matches_regex': '(Pausable|whenNotPaused|whenPaused|_pause|_unpause)'}, {'contract.inherits_any': ['Pausable', 'PausableUpgradeable', 'PausableBase']}, {'contract.has_no_function_body_matching': '(_pause\\s*\\(|_unpause\\s*\\(|emergencyPause)'}]
    _MATCH = [{'function.is_constructor': True}, {'function.not_slither_synthetic': True}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(pauseController|IPauseController\\.pause|externalPauser|IEmergencyPause)'}]

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
                info = [f, f" — pausable-inherits-but-no-exposure: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
