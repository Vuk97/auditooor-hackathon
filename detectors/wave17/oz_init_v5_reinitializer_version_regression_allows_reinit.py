"""
oz-init-v5-reinitializer-version-regression-allows-reinit — generated from reference/patterns.dsl/oz-init-v5-reinitializer-version-regression-allows-reinit.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py oz-init-v5-reinitializer-version-regression-allows-reinit.yaml
Source: auditooor-R75-oz-initializable-v5-HIGH
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class OzInitV5ReinitializerVersionRegressionAllowsReinit(AbstractDetector):
    ARGUMENT = "oz-init-v5-reinitializer-version-regression-allows-reinit"
    HELP = "Contract overrides _getInitializedVersion in a way that returns a value lower than actually initialized, or exposes an admin path to reset it. Next reinitializer(v) call re-runs init logic, potentially re-granting admin or re-zeroing invariants."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/oz-init-v5-reinitializer-version-regression-allows-reinit.yaml"
    WIKI_TITLE = "Initializable v5 version getter override enables reinitializer replay"
    WIKI_DESCRIPTION = "In OZ Initializable v5, `reinitializer(version)` requires `_getInitializedVersion() < version` before running the init body. Normally this is monotonic — the internal counter only goes up. Contracts that override the getter for storage-migration reasons, OR that introduce a rescue function resetting `_initialized` to 0 for 'reinit support', break the monotonicity. Anyone who can call `reinitialize"
    WIKI_EXPLOIT_SCENARIO = "Upgradeable vault had `initialize(admin_A)` at version 1. v2 upgrade uses `reinitializer(2) initializeV2(admin_B)`. A 'fixV2' function later resets `_initialized = 1` via an assembly poke (to allow a re-run under version 2 for a bug fix). Attacker calls `reinitializer(2)` through `initializeV2(attackerAddr)` — passes the version check, re-runs init, writes attackerAddr as admin_B. The storage rese"
    WIKI_RECOMMENDATION = "Never expose a way to decrement `_initialized`. If an init needs to be re-run, advance the version (reinitializer(3)) rather than reset. Remove `assembly { sstore(_INITIALIZED_SLOT, 0) }` and equivalent admin functions. Audit any override of `_getInitializedVersion` — it should only forward to the r"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.inherits': 'Initializable|InitializableUpgradeable'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(_getInitializedVersion|getInitializedVersion|_setInitializedVersion)$'}, {'function.is_override': True}, {'function.body_contains_regex': 'return\\s+0|=\\s*0|_initialized\\s*=\\s*[0-9]+'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — oz-init-v5-reinitializer-version-regression-allows-reinit: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
