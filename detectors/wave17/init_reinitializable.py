"""
init-reinitializable — generated from reference/patterns.dsl/init-reinitializable.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py init-reinitializable.yaml
Source: auditooor-SKILL-223
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class InitReinitializable(AbstractDetector):
    ARGUMENT = "init-reinitializable"
    HELP = "init()/initialize() is external/public, named init/initialize, has no initializer/reinitializer modifier, has no already-initialized guard (initialized= or initialized!), and has no onlyOwner/onlyAdmin/onlyRole access control. Anyone can re-initialize the contract, replace logic or drain funds."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/init-reinitializable.yaml"
    WIKI_TITLE = "Unprotected init()/initialize() allows re-initialization and fund theft"
    WIKI_DESCRIPTION = "Contracts that expose a public init() or initialize() function without the OpenZeppelin initializer modifier and without any access control (onlyOwner, onlyAdmin, role check) can be re-initialized by anyone. This allows attackers to become contract owner, replace implementation logic in UUPS proxies, or directly drain funds by resetting ownership-dependent invariants."
    WIKI_EXPLOIT_SCENARIO = "Attacker calls init() on a deployed upgradeable contract. Since init() has no initializer modifier and no onlyOwner guard, the call succeeds. The attacker sets themselves as owner via the _owner state write inside init(). They then call withdraw() or upgradeTo() which require owner, draining the contract."
    WIKI_RECOMMENDATION = "Apply the OpenZeppelin initializer modifier (or reinitializer with version) to init(). Alternatively gate with onlyOwner. Always call _disableInitializers() in the constructor of the implementation contract so the implementation cannot be initialized separately."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(init|initialize)$'}, {'function.has_modifier': {'includes': ['initializer', 'reinitializer', 'init'], 'negate': True}}, {'function.body_not_contains_regex': 'initialized\\s*[=!]'}, {'function.body_not_contains_regex': 'only(Admin|Owner|Role)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — init-reinitializable: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
