"""
observer-list-update-rename-creates-silent-duplicate — generated from reference/patterns.dsl/observer-list-update-rename-creates-silent-duplicate.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py observer-list-update-rename-creates-silent-duplicate.yaml
Source: auditooor-R75-c4-mined-2023-11-zetachain-411
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ObserverListUpdateRenameCreatesSilentDuplicate(AbstractDetector):
    ARGUMENT = "observer-list-update-rename-creates-silent-duplicate"
    HELP = "An observer/validator-set rotation routine renames `oldAddress -> newAddress` by iterating the set and replacing the first (or all) occurrences. It never checks whether `newAddress` is already in the set. If `newAddress == anotherExistingObserver`, the set now contains duplicates. Voting rewards dil"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/observer-list-update-rename-creates-silent-duplicate.yaml"
    WIKI_TITLE = "Observer/validator rename creates silent duplicate entry, skews quorum and slashing"
    WIKI_DESCRIPTION = "`UpdateObserverList(list, old, new)` walks `list` and does `list[i] = new` when `list[i] == old`. The function does not check that `new` is not already in `list`. An observer (or a tombstoned observer whose msg is still accepted) submits a rename where `new` = some other legitimate observer's address. Now `list` has two copies of that address. Consequences: (1) ballot VoterList has duplicate entri"
    WIKI_EXPLOIT_SCENARIO = "Observer set: [A, B, C, D], threshold 75%. B is tombstoned. Zetachain allows tombstoned observers to call UpdateObserver(oldAddress=B, newAddress=A). List becomes [A, B, C, D] → [A, A, C, D]. Now ballots use VoterList [A, A, C, D]. When A votes, the ballot counts his vote once but expects two. Every ballot marks A as half-missing → A's reward is offset by slashing for the absent duplicate. Simulta"
    WIKI_RECOMMENDATION = "Before writing `list[i] = new`, check `contains(list, new)` and revert if true. For tombstoned observers, UpdateObserverAddress must be restricted to admin-only (not self-service). After every rename, dedupe-validate the full list. Invariant: `len(unique(ObserverList)) == len(ObserverList)` for ever"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'UpdateObserver|ObserverMapper|ObserverList|validatorSet'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(UpdateObserverAddress|UpdateObserverList|renameValidator|RotateSigner|replaceValidator|UpdateObserver)$'}, {'function.body_contains_regex': 'for\\s+\\w+,\\s*\\w+\\s*:?=\\s*range\\s+\\w+List|for\\s*\\(\\s*uint\\w*\\s+i\\s*=\\s*0;'}, {'function.body_contains_regex': 'if\\s+\\w+\\s*==\\s*old\\w+Address\\s*\\{?\\s*list\\[i\\]\\s*=\\s*new\\w+Address'}, {'function.body_not_contains_regex': '(contains\\s*\\(\\s*new\\w+Address\\s*\\)|indexOf\\s*\\(\\s*new\\w+|alreadyInSet|isDuplicate|seenSet\\[new)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — observer-list-update-rename-creates-silent-duplicate: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
