"""
no-mechanism-to-remove-backing-tokens-30 — generated from reference/patterns.dsl/no-mechanism-to-remove-backing-tokens-30.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py no-mechanism-to-remove-backing-tokens-30.yaml
Source: zellic audit Blackhaven (Core Contracts) - Zellic Audit Report
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class NoMechanismToRemoveBackingTokens30(AbstractDetector):
    ARGUMENT = "no-mechanism-to-remove-backing-tokens-30"
    HELP = "addBackingToken appends to `backingTokens` and activates a backing token, but the contract shows no visible backing-token removal or oracle-update entrypoint."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/no-mechanism-to-remove-backing-tokens-30.yaml"
    WIKI_TITLE = "No mechanism to remove backing tokens 30"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only for the owned addBackingToken pattern: the contract appends to `backingTokens` and marks `backingTokenDetailsForAddress[token].isBackingToken = true`, but does not visibly expose a remove/update path for backing-token management. NOT_SUBMIT_READY."
    WIKI_EXPLOIT_SCENARIO = "Governance adds a backing token and stores it in the live `backingTokens` set. If the token later depegs, becomes unsupported, or its oracle must rotate, operators have no visible `removeBackingToken` or `updateBackingTokenOracle` path and remain pinned to stale backing-token configuration."
    WIKI_RECOMMENDATION = "Add explicit backing-token removal and oracle-update controls, and keep this row NOT_SUBMIT_READY until evidence expands beyond the owned fixture pair."

    _PRECONDITIONS = []
    _MATCH = [{'function.name': 'addBackingToken'}, {'function.body_contains_regex': '\\bbackingTokens\\s*\\.(push|append)\\s*\\('}, {'function.body_contains_regex': '\\bbackingTokenDetailsForAddress\\s*\\[[^\\]]+\\]\\s*\\.\\s*isBackingToken\\s*=\\s*true\\b'}, {'function.body_contains_regex': '\\bbackingTokenDetailsForAddress\\s*\\[[^\\]]+\\]\\s*\\.\\s*oracle\\s*='}, {'contract.body_not_contains_regex': '(?i)\\b(remove|delete|disable|unset)(Backing)?Token\\b|\\b(update|set|replace)(Backing)?Token(Oracle|Config)?\\b|\\b(update|set|replace)OracleForBackingToken\\b'}]

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
                info = [f, f" — no-mechanism-to-remove-backing-tokens-30: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
