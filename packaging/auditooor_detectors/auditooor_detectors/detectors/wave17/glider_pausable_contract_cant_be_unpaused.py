"""
glider-pausable-contract-cant-be-unpaused — generated from reference/patterns.dsl/glider-pausable-contract-cant-be-unpaused.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-pausable-contract-cant-be-unpaused.yaml
Source: glider-query-db/pausable-contract-cant-be-unpaused
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderPausableContractCantBeUnpaused(AbstractDetector):
    ARGUMENT = "glider-pausable-contract-cant-be-unpaused"
    HELP = "Contract exposes `pause()` but no corresponding `unpause()` function. Once paused, the contract is permanently bricked — a griefer admin can kill the protocol forever."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-pausable-contract-cant-be-unpaused.yaml"
    WIKI_TITLE = "Pausable contract without unpause function"
    WIKI_DESCRIPTION = "Pausable pattern requires both directions. A contract that only wires `_pause()` and never exposes `_unpause()` can be permanently disabled by any party who can call pause."
    WIKI_EXPLOIT_SCENARIO = "Admin key compromise or rogue multisig member calls `pause()`. Protocol is permanently disabled; no code path can clear the flag; user funds stranded."
    WIKI_RECOMMENDATION = "Always pair `pause()` with `unpause()` — both access-controlled, ideally with different roles."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'Pausable|_pause\\(\\)|paused\\s*='}, {'contract.source_not_contains_regex': 'function\\s+unpause\\s*\\('}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(pause|_pause|emergencyPause|freeze)'}, {'function.body_contains_regex': '_pause\\s*\\(\\s*\\)|paused\\s*=\\s*true'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}]

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
                info = [f, f" — glider-pausable-contract-cant-be-unpaused: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
