"""
dh-mosca-unchecked-delegatecall-selector — generated from reference/patterns.dsl/dh-mosca-unchecked-delegatecall-selector.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py dh-mosca-unchecked-delegatecall-selector.yaml
Source: defihacklabs/Mosca-2025-01+Mosca2-2025-01
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DhMoscaUncheckedDelegatecallSelector(AbstractDetector):
    ARGUMENT = "dh-mosca-unchecked-delegatecall-selector"
    HELP = "Delegatecall dispatcher uses user-selected selector/target without an allowlist."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/dh-mosca-unchecked-delegatecall-selector.yaml"
    WIKI_TITLE = "Delegatecall dispatcher missing selector/facet allowlist"
    WIKI_DESCRIPTION = "Diamond-style proxies route calls to facets based on function selector. Without an explicit mapping enforcing `facetAddress(sel) != address(0)`, any selector — including ones intended only for internal/library use — can be delegatecalled, giving caller the ability to execute arbitrary logic in the proxy's storage context."
    WIKI_EXPLOIT_SCENARIO = "Mosca 2025-01 / Mosca2: proxy's fallback delegatecalled a configurable `impl`. Attacker replaced `impl` via a permissive setter, then invoked `initialize(newOwner)` → owner hijacked → liquidity drained."
    WIKI_RECOMMENDATION = "Maintain a `selector => facet` mapping and enforce `require(facet != address(0))` in the fallback. Prefer ERC-2535 Diamond Standard library which enforces this invariant."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'delegatecall|Diamond|Proxy'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.body_contains_regex': 'delegatecall\\s*\\('}, {'function.body_contains_regex': 'msg\\.data|selector'}, {'function.body_not_contains_regex': 'selectorAllowed|_checkSelector|whitelistedSelectors|facetAddress\\s*\\(\\s*(sel|selector)\\s*\\)\\s*!=\\s*address\\s*\\(\\s*0'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — dh-mosca-unchecked-delegatecall-selector: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
