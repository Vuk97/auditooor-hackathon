"""
r94-loop-aa-resource-lock-validator-missing-scope-bind — generated from reference/patterns.dsl/r94-loop-aa-resource-lock-validator-missing-scope-bind.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-aa-resource-lock-validator-missing-scope-bind.yaml
Source: solodit-61410-shieldify-etherspot-credibleaccountmodule
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopAaResourceLockValidatorMissingScopeBind(AbstractDetector):
    ARGUMENT = "r94-loop-aa-resource-lock-validator-missing-scope-bind"
    HELP = "r94-loop-aa-resource-lock-validator-missing-scope-bind"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-aa-resource-lock-validator-missing-scope-bind.yaml"
    WIKI_TITLE = "r94-loop-aa-resource-lock-validator-missing-scope-bind"
    WIKI_DESCRIPTION = "r94-loop-aa-resource-lock-validator-missing-scope-bind"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-aa-resource-lock-validator-missing-scope-bind"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(ResourceLock|SessionKey|SessionPermission|CredibleAccount|Validator)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(validateUserOp|validateSession|validateLock|verifyResourceLock|checkSessionPermission)'}, {'function.source_matches_regex': '(ResourceLock|resource_?lock|SessionKey|session_?key|SessionPermission|session_?permission|lockScope|permissionScope)'}, {'function.not_source_matches_regex': '(lock\\.target\\s*==|lock\\.selector\\s*==|lock\\.recipient\\s*==|lock\\.token\\s*==|lock\\.amount\\s*(>=|<=)|scope\\.target\\s*==|scope\\.selector\\s*==|callData\\[0:4\\]\\s*==)'}]

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
                info = [f, f" — r94-loop-aa-resource-lock-validator-missing-scope-bind: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
