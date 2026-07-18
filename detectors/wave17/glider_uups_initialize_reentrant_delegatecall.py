"""
glider-uups-initialize-reentrant-delegatecall — generated from reference/patterns.dsl/glider-uups-initialize-reentrant-delegatecall.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-uups-initialize-reentrant-delegatecall.yaml
Source: hexens-glider/untrusted-delegatecall-execution-during-initialization
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderUupsInitializeReentrantDelegatecall(AbstractDetector):
    ARGUMENT = "glider-uups-initialize-reentrant-delegatecall"
    HELP = "Initializer executes a delegatecall whose target is caller-controlled or attacker-reachable. Since initialize runs with initializer storage uninitialized, the delegatecall can bootstrap arbitrary implementation code into the proxy slot, hijacking the proxy."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-uups-initialize-reentrant-delegatecall.yaml"
    WIKI_TITLE = "initialize() performs untrusted delegatecall"
    WIKI_DESCRIPTION = "UUPS proxies expose initialize() as the only path to set admin state. If initialize contains a delegatecall to a parameter-supplied target, the attacker can call initialize on the freshly deployed implementation (or any unclaimed instance) and overwrite the implementation slot via the delegated code path. The contract becomes fully attacker-controlled."
    WIKI_EXPLOIT_SCENARIO = "Attacker calls initialize(attackerContract, attackerCalldata) on the un-initialized proxy. The delegatecall runs attacker bytecode against the proxy's storage, invoking upgradeTo(attackerImpl) and transferring ownership. Owner then drains all pools."
    WIKI_RECOMMENDATION = "Do not delegatecall arbitrary targets from initialize. If a post-init hook is required, restrict targets to a whitelist known at deploy time and never accept them as initialize parameters."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'initialize|__.*_init'}]
    _MATCH = [{'function.name_matches': '^(initialize|reinitialize|__[A-Za-z0-9_]*_init)$'}, {'function.kind': 'external_or_public'}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.body_contains_regex': '\\.delegatecall\\s*\\('}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-uups-initialize-reentrant-delegatecall: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
