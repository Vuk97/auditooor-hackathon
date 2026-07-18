"""
pause-not-enforced-at-token-core-bypassable-via-wrapper-role — generated from reference/patterns.dsl/pause-not-enforced-at-token-core-bypassable-via-wrapper-role.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py pause-not-enforced-at-token-core-bypassable-via-wrapper-role.yaml
Source: auditooor-R78-polymarket-CollateralToken
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PauseNotEnforcedAtTokenCoreBypassableViaWrapperRole(AbstractDetector):
    ARGUMENT = "pause-not-enforced-at-token-core-bypassable-via-wrapper-role"
    HELP = "Core token contract gates its wrap/unwrap/mint/burn by role but NOT by pause state. Wrappers gate pause externally, but any WRAPPER_ROLE holder that doesn't enforce pause (e.g., a CTF adapter) bypasses the system pause."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/pause-not-enforced-at-token-core-bypassable-via-wrapper-role.yaml"
    WIKI_TITLE = "Core token wrap/unwrap role-gated but not pause-gated — system pause bypassable via alt WRAPPER"
    WIKI_DESCRIPTION = "A token contract (e.g., Polymarket's CollateralToken) delegates its wrap/unwrap flow to multiple WRAPPER_ROLE holders. Some wrappers (user-facing ramps) enforce a per-asset pause; others (CTF adapters, automated converters) do NOT. When admin pauses the asset, only the ramp-gated flows stop — CTF redemptions / splits still mint and burn pUSD, drawing from the vault. Pause is scope-incomplete."
    WIKI_EXPLOIT_SCENARIO = "Operator detects USDC.e depeg, pauses on 3 of 5 wrappers. Attacker with pre-existing resolved CTF positions calls `CtfCollateralAdapter.redeemPositions` which does not enforce the pause, draining USDC.e from vault into attacker's pUSD during the emergency."
    WIKI_RECOMMENDATION = "Move the pause gate into the core token's wrap/unwrap functions (behind `onlyRoles(WRAPPER_ROLE)` so every WRAPPER pathway inherits the gate). Keep per-wrapper pause for UX but make the core gate load-bearing."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)WRAPPER_ROLE|MINTER_ROLE|onlyRoles'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)wrap|unwrap|mint|burn'}, {'function.has_modifier': '(?i)onlyRoles|onlyRole'}, {'function.body_not_contains_regex': '(?i)(whenNotPaused|onlyUnpaused|notPaused|require\\s*\\(\\s*!\\s*paused)'}, {'contract.has_function_matching': '(?i)pause|unpause'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — pause-not-enforced-at-token-core-bypassable-via-wrapper-role: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
