"""
fx-balancer-factory-double-registration — generated from reference/patterns.dsl/fx-balancer-factory-double-registration.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fx-balancer-factory-double-registration.yaml
Source: github:balancer/balancer-v3-monorepo@509caa6
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FxBalancerFactoryDoubleRegistration(AbstractDetector):
    ARGUMENT = "fx-balancer-factory-double-registration"
    HELP = "Pool factory create() calls both vault.registerPool() (via _registerPoolWithVault) and _registerPoolWithFactory() separately. _registerPoolWithFactory is already called internally by _registerPoolWithVault in the base factory, causing a double-registration that reverts or corrupts the factory regist"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fx-balancer-factory-double-registration.yaml"
    WIKI_TITLE = "Pool factory create() calls _registerPoolWithFactory twice — double-registration reverts or corrupts registry"
    WIKI_DESCRIPTION = "Base pool factories that call _registerPoolWithVault already internally call _registerPoolWithFactory. Subclass create() functions that additionally call _registerPoolWithFactory explicitly trigger a double-registration: the pool is registered in the factory registry twice, which either reverts (if the registry enforces uniqueness) or stores duplicate entries."
    WIKI_EXPLOIT_SCENARIO = "Balancer Gyro pool factory (2024): Gyro2CLPPoolFactory.create() calls _registerPoolWithVault (which internally calls _registerPoolWithFactory) and then calls _registerPoolWithFactory again. The second call reverts on a mapping conflict or emits duplicate events, making pool creation fail."
    WIKI_RECOMMENDATION = "Remove the explicit _registerPoolWithFactory call from subclass create() functions. The base _registerPoolWithVault already handles factory registration. Only call _registerPoolWithVault from the create() function."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '^create$|^_create$'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^create$|^_create$|^deploy$'}, {'function.body_contains_regex': '_registerPoolWithFactory|registerPool|registerWithFactory'}, {'function.body_contains_regex': '_registerPoolWithVault|vault\\.registerPool'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fx-balancer-factory-double-registration: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
