"""
r94-loop-stylus-cache-reentrant-drift — generated from reference/patterns.dsl/r94-loop-stylus-cache-reentrant-drift.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-stylus-cache-reentrant-drift.yaml
Source: loop-cycle-34-promotion-from-staged
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopStylusCacheReentrantDrift(AbstractDetector):
    ARGUMENT = "r94-loop-stylus-cache-reentrant-drift"
    HELP = "NOT_SUBMIT_READY detector-fixture-smoke-only: local SLOAD cache values that survive a delegatecall boundary without invalidation."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-stylus-cache-reentrant-drift.yaml"
    WIKI_TITLE = "Stylus-style cache drift across delegatecall"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. This row proves only the owned Solidity sibling shape where a function reads a local SLOAD cache, crosses a delegatecall boundary, and lacks explicit invalidation. It does not claim corpus-backed exploit evidence."
    WIKI_EXPLOIT_SCENARIO = "A contract caches a storage read in `localCache`, then delegatecalls into code that mutates the underlying slot. The outer function keeps using the stale cached value, so a later write or check is based on drifted state."
    WIKI_RECOMMENDATION = "Recompute after delegatecall, invalidate before crossing the boundary, or avoid caching any slot that the callee can mutate. Keep this row NOT_SUBMIT_READY until the owned fixture-smoke pair is the only proof available."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(delegatecall|storage|cache)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.source_matches_regex': 'delegatecall\\s*\\(|DelegateCall|assembly\\s*\\{\\s*[^}]*delegatecall'}, {'function.source_matches_regex': 'cache\\s*\\[|_cache|localCache|sloadCache'}, {'function.not_source_matches_regex': 'cache\\s*\\[[^\\]]+\\]\\s*=\\s*0\\s*;|_invalidateCache\\s*\\(|sstore\\s*\\(\\s*slot|refreshCache\\s*\\('}]

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
                info = [f, f" — r94-loop-stylus-cache-reentrant-drift: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
