"""
no-mechanism-to-remove-backing-tokens — generated from reference/patterns.dsl/no-mechanism-to-remove-backing-tokens.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py no-mechanism-to-remove-backing-tokens.yaml
Source: zellic audit Blackhaven (Core Contracts) - Zellic Audit Report
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class NoMechanismToRemoveBackingTokens(AbstractDetector):
    ARGUMENT = "no-mechanism-to-remove-backing-tokens"
    HELP = "Fixture-smoke heuristic for owned `addBackingToken` paths that push into `backingTokens` and store `_oracle` without visible backing-token removal or oracle-update helpers."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/no-mechanism-to-remove-backing-tokens.yaml"
    WIKI_TITLE = "No mechanism to remove backing tokens"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only: this row proves only the owned `addBackingToken(address _token, address _oracle)` shape that pushes `_token` into `backingTokens` and stores `_oracle`, while the same contract lacks visible backing-token removal and oracle-update entry points. NOT_SUBMIT_READY."
    WIKI_EXPLOIT_SCENARIO = "An owner adds a backing token and binds its oracle, but the contract never provides a maintenance path to remove the token from the `backingTokens` array or rotate a stale oracle. A bad token or dead oracle can remain stuck in protocol configuration."
    WIKI_RECOMMENDATION = "Add explicit owner-only maintenance paths that remove a token from `backingTokens` and update `backingTokenDetailsForAddress[_token].oracle`, and keep this row NOT_SUBMIT_READY until validation expands beyond the owned fixture pair."

    _PRECONDITIONS = []
    _MATCH = [{'contract.source_contains': 'address[] public backingTokens;'}, {'contract.source_contains': 'mapping(address => BackingTokenDetails) public backingTokenDetailsForAddress;'}, {'function.name': 'addBackingToken'}, {'function.source_contains': 'backingTokens.push(_token);'}, {'contract.not_source_contains': 'function removeBackingToken(address _token)'}, {'contract.not_source_contains': 'function updateBackingTokenOracle(address _token, address _oracle)'}]

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
                info = [f, f" — no-mechanism-to-remove-backing-tokens: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
