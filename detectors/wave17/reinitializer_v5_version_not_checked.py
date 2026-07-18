"""
reinitializer-v5-version-not-checked — generated from reference/patterns.dsl/reinitializer-v5-version-not-checked.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py reinitializer-v5-version-not-checked.yaml
Source: solodit-cluster/oz-v5-reinitializer
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ReinitializerV5VersionNotChecked(AbstractDetector):
    ARGUMENT = "reinitializer-v5-version-not-checked"
    HELP = "OZ v5 upgradeable function uses reinitializer(N) without asserting the expected initialized-version; silent no-ops on stale N, perma-revert on over-high N."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/reinitializer-v5-version-not-checked.yaml"
    WIKI_TITLE = "reinitializer(N) callsite does not verify _getInitializedVersion"
    WIKI_DESCRIPTION = "OpenZeppelin v5's reinitializer(N) modifier advances the contract's initialized-version to N, but only if N is strictly greater than the current version. If a redeployment script calls reinitializer(N) with an N equal to or below the already-committed version, the guarded initialization logic runs as a silent no-op — every `storage = newValue` inside the body is skipped because the modifier short-"
    WIKI_EXPLOIT_SCENARIO = "A v1 contract is upgraded to v2; v2 exposes `reinitV2()` guarded by `reinitializer(2)` that sets a critical new config field. A later v3 upgrade reuses `reinitializer(2)` in its own migration helper (copy-paste from v2). When the v3 upgrade script runs against the already-v2 instance, the modifier sees currentVersion(2) >= N(2) and no-ops the entire migration body silently; the new config stays at"
    WIKI_RECOMMENDATION = "Before entering the reinitializer body, assert `require(_getInitializedVersion() == expectedPrevVersion, \"wrong version\")` (or emit an event carrying the version). Use a fresh, strictly-increasing N per upgrade. Never reuse a reinitializer version across migrations. Consider OZ v5's `_checkInitial"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.inherits_any': ['Initializable', 'UUPSUpgradeable']}]
    _MATCH = [{'function.has_modifier': {'includes': ['reinitializer'], 'negate': False}}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*_getInitializedVersion|reinitVersion\\s*==|_reinitVersion'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — reinitializer-v5-version-not-checked: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
