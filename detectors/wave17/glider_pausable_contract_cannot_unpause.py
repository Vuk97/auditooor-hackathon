"""
glider-pausable-contract-cannot-unpause — generated from reference/patterns.dsl/glider-pausable-contract-cannot-unpause.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-pausable-contract-cannot-unpause.yaml
Source: hexens-glider/pausable-contract-cant-be-unpaused
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderPausableContractCannotUnpause(AbstractDetector):
    ARGUMENT = "glider-pausable-contract-cannot-unpause"
    HELP = "Contract inherits Pausable and exposes a public wrapper around `_pause()` but NOT `_unpause()`. Once admin triggers a pause (even by mistake), the contract is permanently bricked for every `whenNotPaused` function."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-pausable-contract-cannot-unpause.yaml"
    WIKI_TITLE = "Pausable contract exposes _pause but not _unpause — permanent brick"
    WIKI_DESCRIPTION = "OZ Pausable provides internal `_pause` and `_unpause`. A contract must expose BOTH, both gated by admin access control. Exposing only `_pause` creates a one-way switch: the first pause (legitimate or accidental, such as the signer key being lost) bricks every `whenNotPaused` function permanently. This is a common oversight on forks that selectively expose one side."
    WIKI_EXPLOIT_SCENARIO = "Admin wallet is compromised but not yet aware. Attacker calls `pause()` to DoS the protocol while drafting a ransom message. Since `unpause` was never exposed, even recovering the admin key doesn't help — the contract is stuck paused and users cannot withdraw."
    WIKI_RECOMMENDATION = "Always expose BOTH `pause()` → `_pause()` AND `unpause()` → `_unpause()` behind the same admin modifier. If you truly want a one-way switch, make it an irreversible freeze flag — don't rely on OZ Pausable asymmetrically."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'whenNotPaused'}, {'contract.has_function_body_matching': '_pause\\s*\\('}, {'contract.has_no_function_body_matching': '_unpause\\s*\\('}]
    _MATCH = [{'function.kind': 'any'}, {'function.body_contains_regex': '_pause\\s*\\('}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-pausable-contract-cannot-unpause: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
