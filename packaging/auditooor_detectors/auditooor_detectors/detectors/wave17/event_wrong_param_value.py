"""
event-wrong-param-value — generated from reference/patterns.dsl/event-wrong-param-value.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py event-wrong-param-value.yaml
Source: solodit-cluster-EVT01
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EventWrongParamValue(AbstractDetector):
    ARGUMENT = "event-wrong-param-value"
    HELP = "Function emits an event with an `amount` argument while also computing a fee adjustment in the same body. Likely emits the gross value instead of the post-fee net, which breaks off-chain indexers that reconcile event-derived balances."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/event-wrong-param-value.yaml"
    WIKI_TITLE = "Event emits gross amount when a fee adjustment was applied"
    WIKI_DESCRIPTION = "When a function deducts a fee from a user-supplied amount before performing the effective state change but emits an event carrying the pre-fee (gross) amount, off-chain indexers that reconstruct user balances from event logs will diverge from on-chain truth by the accumulated fee delta. The on-chain accounting remains consistent, but downstream analytics, subgraphs, UI balance displays, and reconc"
    WIKI_EXPLOIT_SCENARIO = "A user deposits 1,000 tokens. The contract debits a 1% fee, credits 990 to the vault, and emits `Deposit(user, 1000)` instead of `Deposit(user, 990)`. Over many deposits the subgraph shows a cumulative balance 1% higher than the vault actually holds; downstream integrators quoting off this data mis-price positions, and reconciliation tooling silently diverges."
    WIKI_RECOMMENDATION = "Emit the post-fee (net) amount that actually changed internal state, or emit both gross and net as separate event parameters so the indexer does not have to reconstruct the fee. Align the event schema with the variable that drives the state write."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': {'regex': 'emit\\s+\\w+\\s*\\(\\s*\\w*amount\\b'}}, {'function.body_contains_regex': 'fee\\s*=|fee\\s*-|discounted'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — event-wrong-param-value: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
