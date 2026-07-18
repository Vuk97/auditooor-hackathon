"""
governance-slate-duplicate-proposal-ids — generated from reference/patterns.dsl/governance-slate-duplicate-proposal-ids.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py governance-slate-duplicate-proposal-ids.yaml
Source: solodit/sherlock/ajna-H6-6292
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GovernanceSlateDuplicateProposalIds(AbstractDetector):
    ARGUMENT = "governance-slate-duplicate-proposal-ids"
    HELP = "Function aggregates per-ID budget/weight by iterating a caller-supplied array without dedup. Attacker repeats the heaviest ID to maximize aggregate under any cap, locking out legitimate slates that include distinct IDs."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/governance-slate-duplicate-proposal-ids.yaml"
    WIKI_TITLE = "Caller-supplied ID array not deduplicated — single resource counted multiple times"
    WIKI_DESCRIPTION = "A governance or settlement function accepts an array of resource IDs (proposal IDs, bid IDs, epoch IDs) from the caller, iterates them, and sums a per-ID field (budget allocation, vote weight, collateral). There's no assertion that the IDs are distinct. An attacker submits the same heavy ID N times; the loop adds its value N times, maximizing the aggregate under a cap that was designed around dist"
    WIKI_EXPLOIT_SCENARIO = "Ajna StandardFunding: an attacker takes the highest-budget proposal P and submits slate `[P, P, P, P, P, P, P, P, P]`. `checkSlate` finds P in topTenProposals (true for all 9 iterations) and sums `9 * P.qvBudgetAllocated`, which stays under the 90% GBC cap because 9 * budget(P) happens to fit. This slate becomes the funded slate. `executeStandard(Q)` for a real, separately-funded Q reverts because"
    WIKI_RECOMMENDATION = "Before iterating, sort and deduplicate the input array, or use an in-memory bitmap / O(N) Set: `bytes32 h = keccak256(abi.encode(ids[i])); require(!seen[h], 'duplicate'); seen[h] = true;`. For large arrays, require the array is sorted strictly ascending."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_param_of_type': 'uint256\\[\\]|bytes32\\[\\]|address\\[\\]'}, {'function.body_contains_regex': 'for\\s*\\(.*i\\s*<\\s*.*(length|len)'}, {'function.body_contains_regex': '\\[\\s*[a-zA-Z_]*\\[\\s*i\\s*\\]\\s*\\]'}, {'function.body_contains_regex': '(sum|total|aggregate|budget|weight|allocated)\\s*\\+=|\\+\\s*='}, {'function.body_not_contains_regex': 'mapping\\s*\\([^)]*=>\\s*bool\\s*\\)|seen\\[|visited\\[|for\\s*\\(.*j\\s*<\\s*i\\s*;.*\\[j\\]\\s*!=\\s*\\[i\\]'}, {'function.body_contains_regex': '(execute|fund|mint|withdraw|allocate|distribute)\\s*\\(|(success|passed|valid)\\s*=\\s*true'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — governance-slate-duplicate-proposal-ids: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
