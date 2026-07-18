"""
unbounded-order-list-iteration — generated from reference/patterns.dsl/unbounded-order-list-iteration.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py unbounded-order-list-iteration.yaml
Source: solodit-novel/slice_aa
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class UnboundedOrderListIteration(AbstractDetector):
    ARGUMENT = "unbounded-order-list-iteration"
    HELP = "Critical function iterates over an unbounded `orders[]` / `orderList[]` / `orderBook[]` array without a batch size or break condition. Attacker spams orders to push gas cost over block limit."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/unbounded-order-list-iteration.yaml"
    WIKI_TITLE = "Unbounded order-list iteration causes DoS"
    WIKI_DESCRIPTION = "Soft-delete order books keep entries forever and iterate linearly to skip deleted ones. As the array grows unboundedly, any function that must iterate the full set (match, settle, batch-cancel) reaches block gas limit and becomes permanently unusable. Attacker with small capital can push the list past the critical size by spamming tiny orders."
    WIKI_EXPLOIT_SCENARIO = "Protocol uses `Order[] public orders;` with `orders[i].isActive` flag to tombstone cancelled orders. `settleAll()` iterates the full array. Attacker places 10,000 dust orders ($0.01 each). `settleAll` now requires ~50M gas, exceeds Ethereum mainnet's 30M block limit, and every settlement fails. Protocol must be upgraded to paginate before normal flows resume."
    WIKI_RECOMMENDATION = "Paginate: accept a `(start, end)` range and process only `orders[start..end]`. Or use an off-chain indexer to compute the set of active order IDs and pass them in as calldata. Or hard-delete (swap-and-pop) on cancel to keep the array compact."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'orders\\b|orderList|orderBook|iterableMap|EnumerableSet'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.body_contains_regex': 'for\\s*\\(\\s*uint\\w*\\s+\\w+\\s*=\\s*0\\s*;\\s*\\w+\\s*<\\s*(orders|orderList|orderBook|orderIds)\\.length'}, {'function.body_not_contains_regex': 'MAX_ORDERS|maxIterations|limit\\s*\\*\\s*per|if\\s*\\(\\s*\\w+\\s*>=\\s*maxBatch|break\\s*;'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — unbounded-order-list-iteration: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
