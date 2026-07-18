"""
enumerable-map-never-deletes-zero-entries — generated from reference/patterns.dsl/enumerable-map-never-deletes-zero-entries.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py enumerable-map-never-deletes-zero-entries.yaml
Source: auditooor-R75-code4rena-2024-08-phi-65
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EnumerableMapNeverDeletesZeroEntries(AbstractDetector):
    ARGUMENT = "enumerable-map-never-deletes-zero-entries"
    HELP = "Balance update writes `set(user, 0)` instead of `remove(user)` on full sell — EnumerableMap grows unbounded and eventually blocks rewards distribution by gas exhaustion."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/enumerable-map-never-deletes-zero-entries.yaml"
    WIKI_TITLE = "EnumerableMap bloat from zero-balance entries eventually gas-DOSes reward distribution"
    WIKI_DESCRIPTION = "`shareBalance[credId]` is an EnumerableMap. When a curator sells all shares, code path writes `shareBalance[credId].set(curator, 0)` (still an entry in the map). A separate `distribute` function later enumerates all entries in a loop to calculate per-curator rewards. On chains with ~30M gas blocks, about 3-4k historical entries is enough to exceed the block gas limit; once this threshold is passed"
    WIKI_EXPLOIT_SCENARIO = "Attacker uses 5000 throwaway addresses to buy 1 share each and immediately sell. Each sell writes set(addr, 0) — 5000 ghost entries. Next call to `distribute(credId)` runs out of gas. Protocol cannot distribute rewards to the 10 real holders until (expensive) admin migration."
    WIKI_RECOMMENDATION = "When new balance is 0, call `shareBalance[credId].remove(user)` not `set(user, 0)`. Add an assertion in tests that map length equals the number of non-zero holders after a full sell."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'internal'}, {'function.name_matches': '(?i)_updateBalance|_updateShare|_updateCurator|_stake|_unstake'}, {'function.body_contains_regex': '(?i)EnumerableMap|EnumerableSet|\\.set\\s*\\('}, {'function.body_contains_regex': '(?i)set\\s*\\([^)]*,\\s*0\\s*\\)|set\\s*\\([^)]*,\\s*currentNum\\s*-\\s*amount'}, {'function.body_not_contains_regex': '(?i)\\.remove\\s*\\(|\\.tryRemove'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — enumerable-map-never-deletes-zero-entries: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
