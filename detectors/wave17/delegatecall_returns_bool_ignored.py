"""
delegatecall-returns-bool-ignored — generated from reference/patterns.dsl/delegatecall-returns-bool-ignored.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py delegatecall-returns-bool-ignored.yaml
Source: auditooor-seed
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DelegatecallReturnsBoolIgnored(AbstractDetector):
    ARGUMENT = "delegatecall-returns-bool-ignored"
    HELP = "delegatecall's success bool is captured but never checked — a reverting callee leaves the caller in a partial / inconsistent state."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/delegatecall-returns-bool-ignored.yaml"
    WIKI_TITLE = "delegatecall returns bool is ignored"
    WIKI_DESCRIPTION = "A function performs `(bool success, ...) = target.delegatecall(data)` (or the bare `bool ok = ...` form) and captures the success flag but neither reverts on failure nor propagates the revert reason. If the callee reverts — whether for a business reason, a gas OOG, an invariant failure, or a selector-miss — the caller continues execution as if the delegatecall succeeded. Any pre-call state mutatio"
    WIKI_EXPLOIT_SCENARIO = "A proxy exposes `execute(bytes data)` that does `(bool ok, ) = implementation.delegatecall(data);` but never `require(ok)`. A user submits a transaction that exercises a code path in the implementation whose require fails halfway through a two-step state update. The first-step write persists on the proxy's storage; the second-step write (inside the reverted delegatecall) is rolled back. The proxy "
    WIKI_RECOMMENDATION = "Always `require(success, 'delegatecall failed')` (or `if (!success) revert(...)`) immediately after capturing the delegatecall return. Prefer bubbling up the callee's revert reason via an `assembly { revert(add(ret, 0x20), mload(ret)) }` block so the caller sees the real failure cause rather than a "

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.body_contains_regex': '\\(bool\\s+\\w+\\s*,|\\(\\s*bool\\s*,|bool\\s+\\w+\\s*=\\s*\\w+\\.delegatecall'}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.body_contains_regex': '\\.delegatecall\\s*\\('}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*\\w+\\s*,|require\\s*\\(\\s*success|if\\s*\\(\\s*!\\s*\\w+\\s*\\)\\s*revert|assert\\s*\\(\\s*\\w+\\s*\\)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — delegatecall-returns-bool-ignored: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
