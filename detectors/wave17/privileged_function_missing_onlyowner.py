"""
privileged-function-missing-onlyowner — generated from reference/patterns.dsl/privileged-function-missing-onlyowner.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py privileged-function-missing-onlyowner.yaml
Source: solodit/Zokyo-2021-04-29-ArGo
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PrivilegedFunctionMissingOnlyowner(AbstractDetector):
    ARGUMENT = "privileged-function-missing-onlyowner"
    HELP = "Fixture-smoke heuristic for privileged admin-shaped functions that stay public/external and mutating without a visible access-control modifier even though the contract uses `onlyOwner`-style guards elsewhere."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/privileged-function-missing-onlyowner.yaml"
    WIKI_TITLE = "Privileged function missing access-control modifier"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only: this row currently proves only that the owned fixture pair separates a public `set*` admin function with no visible access-control modifier from a local `onlyOwner` rewrite, even though the contract uses owner-style guards elsewhere. Keep this row NOT_SUBMIT_READY until evidence expands beyond the owned fixtures and source shape."
    WIKI_EXPLOIT_SCENARIO = "A contract protects some admin operations with `onlyOwner`, but leaves a public `setTreasury()` or `emergencyWithdraw()` path unguarded. An attacker calls the unprotected function directly and reroutes assets or rewrites privileged configuration."
    WIKI_RECOMMENDATION = "Apply the appropriate owner/admin/role guard to every privileged mutating function, and keep this row NOT_SUBMIT_READY until the detector has evidence beyond the owned fixture-smoke pair."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(onlyOwner|onlyAdmin|onlyRole|auth\\s*\\(|AccessControl|_grantRole|_checkRole|hasRole|_onlyOwner|_onlyAdmin|requireAuth)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': '(?i)^(emergencyWithdraw|emergencyRescue|addOperator|removeOperator|set[A-Z]\\w*|update[A-Z]\\w*|configure[A-Z]\\w*|rescue[A-Z]\\w*|sweep[A-Z]\\w*|pause|unpause|adminWithdraw|recoverTokens|withdrawStuck|change[A-Z]\\w*|modify[A-Z]\\w*|reset[A-Z]\\w*|revoke[A-Z]\\w*|grant[A-Z]\\w*|renounce[A-Z]\\w*|transferOwnership|upgradeTo|kill)$'}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyAdmin', 'onlyRole', 'auth', 'onlyGovernance', 'onlyManager', 'onlyPauser', 'onlyMinter', 'onlyPoolAdmin', 'onlyExecutor', 'onlyBridge', 'onlyProxyAdmin', 'onlyTimelock', 'requireAuth'], 'negate': True}}, {'function.body_not_contains_regex': 'msg\\.sender\\s*==\\s*\\w+|_?msgSender\\s*\\(\\s*\\)\\s*==\\s*\\w+|hasRole\\s*\\(|_checkRole\\s*\\(|_checkOwner\\s*\\(|require\\s*\\(\\s*_?(owner|admin|governor|manager|operator|controller|s_\\w+)\\s*==\\s*msg\\.sender|if\\s*\\(\\s*msg\\.sender\\s*!=\\s*\\w+\\s*\\)\\s*(revert|\\{)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — privileged-function-missing-onlyowner: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
