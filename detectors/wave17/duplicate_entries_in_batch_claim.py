"""
duplicate-entries-in-batch-claim — generated from reference/patterns.dsl/duplicate-entries-in-batch-claim.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py duplicate-entries-in-batch-claim.yaml
Source: auditooor-R75-code4rena-2024-01-curves-951
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DuplicateEntriesInBatchClaim(AbstractDetector):
    ARGUMENT = "duplicate-entries-in-batch-claim"
    HELP = "batchClaim iterates a caller-supplied token array with no dedup and no per-claim nullifier — attacker claims the same entitlement N times."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/duplicate-entries-in-batch-claim.yaml"
    WIKI_TITLE = "batchClaim does not dedup input array or nullify per-claim, enabling N× over-claim"
    WIKI_DESCRIPTION = "`FeeSplitter.batchClaim(tokenList[])` loops over `tokenList` and for each entry calls `_claim(tokenList[i])`. `_claim` computes `claimable = userBalance * (cumulativePerToken - lastCheckpoint[user][token])` and transfers, then writes `lastCheckpoint[user][token] = cumulativePerToken`. Within a single batch call, the first occurrence captures the full entitlement. But if `lastCheckpoint` is updated"
    WIKI_EXPLOIT_SCENARIO = "Alice owes 1 ETH in fees for Token X. She calls batchClaim([X, X, X]). Iteration 1 pays her 1 ETH, sets checkpoint. Iteration 2 should pay 0 but in a flawed impl (where checkpoint update is deferred or keyed differently) pays another 1 ETH. 3 ETH extracted for 1 ETH entitlement."
    WIKI_RECOMMENDATION = "At the top of batchClaim, build an in-memory set and require all entries unique: `require(!seen[tokenList[i]]); seen[tokenList[i]] = true;`. Or call `_claim` with a loop-local cache that mirrors the checkpoint update. Add a test claiming with duplicates and asserting total payout equals single-claim"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external'}, {'function.name_matches': '(?i)batchClaim|claimMultiple|claimBatch|multiClaim'}, {'function.body_contains_regex': '(?i)for\\s*\\([^)]*\\w+\\s*<\\s*\\w*\\.length'}, {'function.body_contains_regex': '(?i)claim\\s*\\(\\s*\\w+\\s*\\[\\s*i\\s*\\]|_claim\\('}, {'function.body_not_contains_regex': '(?i)claimed\\s*\\[[^\\]]*\\]\\s*=\\s*true|require\\s*\\([^)]*seen|EnumerableSet|unique|dedup'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — duplicate-entries-in-batch-claim: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
