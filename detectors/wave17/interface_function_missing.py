"""
interface-function-missing — generated from reference/patterns.dsl/interface-function-missing.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py interface-function-missing.yaml
Source: solodit-novel/slice_aa-Lido-LID-17
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class InterfaceFunctionMissing(AbstractDetector):
    ARGUMENT = "interface-function-missing"
    HELP = "Function casts a storage address to a declared interface and calls a method, with no try/catch or ERC-165 supportsInterface check. If the concrete contract does not expose the method (upgrade drift), every call reverts permanently."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/interface-function-missing.yaml"
    WIKI_TITLE = "Interface cast calls method missing on concrete contract"
    WIKI_DESCRIPTION = "Contracts that cast an address to `IX` and call `IX(addr).foo()` assume the deployed implementation at `addr` exposes `foo`. On upgrade mismatch, an older implementation may lack `foo`, causing every call to revert with no catch. Since the assumption is static, reverts become permanent — protocol deadlock."
    WIKI_EXPLOIT_SCENARIO = "Lido LID-17: `IStakingRouter(router).getStakingModuleSummary(moduleId)` is called from critical accounting. Router gets upgraded to a new impl that drops `getStakingModuleSummary` in favour of `getSummary`. Every accounting tick reverts, freezing balance updates and rewards. Non-malicious but unrecoverable without another upgrade."
    WIKI_RECOMMENDATION = "Either (a) pin interface compatibility with ERC-165 `supportsInterface` guard at the time of setting the address, or (b) wrap the call in `try/catch` with a fallback path, or (c) use a known-function-selector `staticcall(addr, abi.encodeWithSelector(...))` and check `success`."

    _PRECONDITIONS = [{'contract.has_function_body_matching': 'I[A-Z]\\w*\\s*\\(\\s*\\w+\\s*\\)\\s*\\.\\s*\\w+\\s*\\('}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.body_contains_regex': 'I[A-Z]\\w*\\s*\\(\\s*\\w+\\s*\\)\\s*\\.\\s*\\w+\\s*\\('}, {'function.body_not_contains_regex': 'try\\s+I[A-Z]\\w*\\s*\\(|staticcall|supportsInterface|ERC165'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — interface-function-missing: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
