"""
w68-cached-swap-pop-set-forward-remove-skip - narrow wave68 sibling of the
existing swap-pop set recall pattern.
Derived from the confirmed corpus pattern:
reference/patterns.dsl/swap-pop-set-forward-remove-skip.yaml
"""

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class W68CachedSwapPopSetForwardRemoveSkip(AbstractDetector):
    ARGUMENT = "w68-cached-swap-pop-set-forward-remove-skip"
    HELP = (
        "Forward loops that either remove from a swap-pop set mid-iteration "
        "or iterate with <= against an array length can break the intended "
        "loop invariant."
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "swap-pop-set-forward-remove-skip.yaml"
    )
    WIKI_TITLE = "Cached-length swap-pop set forward remove skips validation"
    WIKI_DESCRIPTION = (
        "`EnumerableSet.remove` performs a swap-and-pop. When a forward `for` "
        "loop caches `len = set.length()` and then reads `set.at(i)` before "
        "removing from the same set, the tail element can be swapped into the "
        "current slot and never revisited because the cached bound is stale. "
        "The same attack class also appears when a forward loop uses "
        "`i <= items.length` and then indexes `items[i]`, crossing the array "
        "boundary at the final iteration."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "Governance sweep caches a set length, iterates from 0 upward, and "
        "removes members from the same set. After the first removal the tail "
        "member swaps into the current slot, but the loop increments past it, "
        "so the swapped-in element is not validated. A sibling shape uses "
        "`<=` against `array.length`, so the last iteration reads one slot "
        "past the valid range."
    )
    WIKI_RECOMMENDATION = (
        "Iterate swap-pop sets in reverse, defer removals to a second pass, "
        "keep the cursor on the same index after a removal, and use strict "
        "`<` bounds when indexing arrays."
    )

    _SWAP_POP_MATCH = [
        {"function.kind": "any"},
        {"function.name_matches": "(?i)(sweep|prune|validate|process|check|settle)"},
        {
            "function.body_contains_regex": "uint256\\s+[A-Za-z_][A-Za-z0-9_]*\\s*=\\s*[A-Za-z_][A-Za-z0-9_\\.]*\\.length\\s*\\(\\s*\\)\\s*;"
        },
        {
            "function.body_contains_regex": "for\\s*\\(\\s*uint256\\s+[A-Za-z_][A-Za-z0-9_]*\\s*=\\s*0\\s*;\\s*[A-Za-z_][A-Za-z0-9_]*\\s*<\\s*[A-Za-z_][A-Za-z0-9_]*\\s*;\\s*[A-Za-z_][A-Za-z0-9_]*\\+\\+\\s*\\)"
        },
        {"function.body_contains_regex": "\\.at\\s*\\(\\s*[A-Za-z_][A-Za-z0-9_]*\\s*\\)"},
        {"function.body_contains_regex": "\\.remove\\s*\\(\\s*[A-Za-z_][A-Za-z0-9_]*\\s*\\)"},
        {
            "function.body_not_contains_regex": "(?i)for\\s*\\([^;]*;[^;]*>\\s*0[^;]*;\\s*[A-Za-z_][A-Za-z0-9_]*\\s*--"
        },
        {
            "function.body_not_contains_regex": "(?i)(defer|removeLater|toRemove|collectThenRemove)"
        },
        {"function.not_in_skip_list": True},
        {"function.not_leaf_helper": True},
        {"function.not_source_matches_regex": "(?i)\\b(mock|test|fixture)\\b"},
    ]

    _INCLUDE_LEAF_HELPERS = False
    _INVERSE_CEI = False
    _SWAP_POP_PRECONDITION = re.compile(
        r"(?i)(EnumerableSet|AddressSet|UintSet|Bytes32Set|swap\s*[- ]?pop)"
    )
    _OFF_BY_ONE_LOOP = re.compile(
        r"for\s*\(\s*uint(?:256)?\s+(?P<idx>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*0\s*;"
        r"\s*(?P=idx)\s*<=\s*(?P<array>[A-Za-z_][A-Za-z0-9_.]*)\.length\s*;"
        r"\s*(?P=idx)\s*\+\+\s*\)",
        re.IGNORECASE | re.DOTALL,
    )

    def _matches_swap_pop_shape(self, contract_source: str, function) -> bool:
        if not self._SWAP_POP_PRECONDITION.search(contract_source):
            return False
        return eval_function_match(function, self._SWAP_POP_MATCH)

    def _matches_off_by_one_shape(self, function_source: str) -> bool:
        for match in self._OFF_BY_ONE_LOOP.finditer(function_source):
            idx = match.group("idx")
            array = re.escape(match.group("array"))
            index_read = re.compile(rf"\b{array}\s*\[\s*{idx}\s*\]")
            if index_read.search(function_source):
                return True
        return False

    def _detect(self):
        results = []
        for c in self.contracts:
            if is_vendored_or_test_contract(c):
                continue
            contract_source = c.source_mapping.content or ""
            for f in c.functions_and_modifiers_declared:
                function_source = f.source_mapping.content or ""
                off_by_one_shape = self._matches_off_by_one_shape(function_source)
                if (
                    not off_by_one_shape
                    and not self._INCLUDE_LEAF_HELPERS
                    and is_leaf_helper(f)
                ):
                    continue
                if not (self._matches_swap_pop_shape(contract_source, f) or off_by_one_shape):
                    continue
                info = [
                    f,
                    " - w68-cached-swap-pop-set-forward-remove-skip: pattern matched. See WIKI for details.",
                ]
                results.append(self.generate_result(info))
        return results
