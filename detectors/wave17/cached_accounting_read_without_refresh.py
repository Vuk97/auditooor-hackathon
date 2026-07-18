"""
cached-accounting-read-without-refresh - generated from reference/patterns.dsl/cached-accounting-read-without-refresh.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py cached-accounting-read-without-refresh.yaml
Source: auditooor/cache-coherence-capability-lift
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CachedAccountingReadWithoutRefresh(AbstractDetector):
    ARGUMENT = "cached-accounting-read-without-refresh"
    HELP = "Consumer reads cached capacity, credit, oracle, or accounting state without first refreshing it or proving freshness with an explicit guard."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/cached-accounting-read-without-refresh.yaml"
    WIKI_TITLE = "Cached accounting value consumed without refresh or freshness proof"
    WIKI_DESCRIPTION = "Many protocols cache derived state such as credit capacity, borrow headroom, oracle-backed pricing, accounting indexes, or checkpointed totals because recomputing them on every read is expensive. That optimization is only safe if every consumer either refreshes the cached value immediately before use or verifies freshness through a staleness guard tied to the last update. A quote, preview, maxWith"
    WIKI_EXPLOIT_SCENARIO = "(1) The protocol caches a derived accounting value such as cachedCreditCapacity or cachedOraclePrice. (2) A prior mutation changes the underlying collateral, utilization, or price inputs, but nobody refreshes the cache. (3) A user or downstream protocol calls quoteBorrowable(), previewRedeem(), maxWithdraw(), or a similar reader that consumes the cached values directly. (4) The function returns a "
    WIKI_RECOMMENDATION = "Refresh the cache inside every consumer before using it, or record a freshness cursor (`lastRefresh`, `updatedAt`, `checkpointBlock`) and require it to satisfy a bounded staleness rule before returning. If a read path must remain view-only, either derive the value live from canonical storage or stor"

    _PRECONDITIONS = [{'contract.has_state_var_matching': 'cache|cached|capacity|credit|oracle|price|accounting|index|rate|lastUpdate|lastUpdated|updatedAt|lastRefresh|checkpoint'}, {'contract.has_function_matching': 'refresh|sync|update|checkpoint|invalidate|recalc|accrue|settle|poke'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'quote|preview|max|available|capacity|credit|borrow|price|health|redeem|withdraw|convert'}, {'function.reads_storage_matching': 'cache|cached|capacity|credit|oracle|price|accounting|index|rate|lastUpdate|lastUpdated|updatedAt|lastRefresh|checkpoint'}, {'function.body_contains_regex': 'cache|cached|creditCapacity|oraclePrice|accountingIndex|lastUpdate|lastUpdated|updatedAt|lastRefresh'}, {'function.body_not_contains_regex': 'refresh|sync|update|checkpoint|invalidate|recalc|accrue|settle|poke'}, {'function.body_not_contains_regex': 'MAX_STALE|staleness|block\\.timestamp\\s*-\\s*(lastUpdate|lastUpdated|updatedAt|lastRefresh)|updatedAt\\s*[<>!=]|lastUpdate\\s*[<>!=]|lastRefresh\\s*[<>!=]'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" - cached-accounting-read-without-refresh: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
