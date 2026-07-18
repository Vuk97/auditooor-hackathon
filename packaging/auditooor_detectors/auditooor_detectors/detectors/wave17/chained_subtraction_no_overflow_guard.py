"""
chained-subtraction-no-overflow-guard — generated from reference/patterns.dsl/chained-subtraction-no-overflow-guard.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py chained-subtraction-no-overflow-guard.yaml
Source: auditooor-R107-thegraph-Trust-H-8
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ChainedSubtractionNoOverflowGuard(AbstractDetector):
    ARGUMENT = "chained-subtraction-no-overflow-guard"
    HELP = "A privileged action (slash, withdraw, liquidate, settle) computes `available = total - usedA - usedB` (chained subtraction) without first checking that `usedA + usedB <= total`. Under Solidity >= 0.8 checked arithmetic, the subtraction reverts whenever the two used amounts together exceed `total` — "
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/chained-subtraction-no-overflow-guard.yaml"
    WIKI_TITLE = "Chained subtraction without overflow guard — privileged action DoS"
    WIKI_DESCRIPTION = "Staking, lending, vesting and margin contracts often track a `total` balance and decompose it into multiple obligations (`allocated`, `locked`, `pending`, `usedAsCollateral`). The 'free' / 'available' / 'slashable' subset is computed as `total - obligationA - obligationB`. Under Solidity 0.8+ checked arithmetic, this expression reverts whenever `obligationA + obligationB > total`. In legacy upgrad"
    WIKI_EXPLOIT_SCENARIO = "A staking contract has `tokensAvailable = tokensStaked - tokensAllocated - tokensLocked`. Allocations may use delegation boost so `tokensAllocated + tokensLocked` can legitimately exceed `tokensStaked`. The `legacySlash` function tries to compute `tokensAvailable` first to enforce a cap; the chained subtraction underflows and reverts. Indexer who misbehaves cannot be slashed — the protocol cannot "
    WIKI_RECOMMENDATION = "Replace `available = total - usedA - usedB` with a guarded form: `uint256 used = usedA + usedB; available = used > total ? 0 : total - used;` — or `require(used <= total, Underflow()); available = total - used;` if reverting is still desired. Either form makes the overflow direction explicit and pre"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': '(?i)^_?(slash|legacySlash|withdraw|deprovision|liquidate|settle|seize|forceClose|sweep|claim)\\w*$'}, {'function.body_contains_regex': '\\b\\w+\\s*=\\s*\\w+(?:\\.\\w+)?\\s*-\\s*\\w+(?:\\.\\w+)?\\s*-\\s*\\w+(?:\\.\\w+)?\\s*;'}, {'function.body_not_contains_regex': '(?:require\\s*\\([^)]*\\+[^)]*<=|>\\s*\\w+(?:\\.\\w+)?\\s*\\?\\s*0\\s*:)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — chained-subtraction-no-overflow-guard: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
