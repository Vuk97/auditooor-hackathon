"""
incomplete-chain-comparison — generated from reference/patterns.dsl/incomplete-chain-comparison.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py incomplete-chain-comparison.yaml
Source: zellic audit SoSoValue - Zellic Audit Report
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class IncompleteChainComparison(AbstractDetector):
    ARGUMENT = "incomplete-chain-comparison"
    HELP = "checkTokenset compares token addresses from a token-set against an address list without a visible token-chain comparison guard."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/incomplete-chain-comparison.yaml"
    WIKI_TITLE = "Incomplete chain comparison"
    WIKI_DESCRIPTION = "A token-set validation routine that has chain data in scope but only compares token addresses can accept an entry from the wrong chain when the address matches."
    WIKI_EXPLOIT_SCENARIO = "A token on another chain shares the same token address as the expected token. Because checkTokenset validates only tokenAddress against addressList and omits a chain check, the mismatched chain entry passes the local validation shape."
    WIKI_RECOMMENDATION = "Validate both tokenAddress and chain identity for each token-set entry before accepting the set."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(checkTokenset|Token\\[\\]|tokenAddress|chain)'}]
    _MATCH = [{'function.name_matches': '^checkTokenset$'}, {'function.body_contains_regex': '\\.tokenAddress\\b.*(?:==|!=).*addressList|addressList.*(?:==|!=).*\\.tokenAddress\\b'}, {'function.body_not_contains_regex': '(?i)(require|assert|if)\\s*\\([^;{}]*(\\.chain\\b|\\bchain\\b)[^;{}]*(==|!=|keccak256|_same|equal|compare)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — incomplete-chain-comparison: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
