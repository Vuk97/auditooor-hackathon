"""
token-set-chain-field-not-validated — generated from reference/patterns.dsl/token-set-chain-field-not-validated.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py token-set-chain-field-not-validated.yaml
Source: zellic-sosovalue-audit-incomplete-chain-comparison-sibling-batch6
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class TokenSetChainFieldNotValidated(AbstractDetector):
    ARGUMENT = "token-set-chain-field-not-validated"
    HELP = "Token-set validation compares token addresses but ignores the chain field. Tokens from the wrong chain with the same address pass validation."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/token-set-chain-field-not-validated.yaml"
    WIKI_TITLE = "Token-set validation omits chain field check - cross-chain token accepted"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. Sibling of incomplete-chain-comparison. A token-set validation function iterates over structs with chain and address fields, validates only the token address, and ignores the chain identifier. A token on another chain sharing the same address passes validation."
    WIKI_EXPLOIT_SCENARIO = "checkTokenset iterates tokenset[] and requires tokenset[i].tokenAddress == addressList[i]. A token on another chain with the same contract address passes this check. The chain field is accessible but never validated in the predicate."
    WIKI_RECOMMENDATION = "Validate both the address and chain fields for every entry: require(tokenset[i].tokenAddress == addressList[i] and tokenset[i].chain == expectedChain). Use keccak256(bytes(tokenset[i].chain)) == expectedChainHash for string chains."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(tokenset|token_set|tokenList|tokenAddress|checkTokenset|checkTokenList)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.source_matches_regex': '(?i)(Token\\[\\]|tokenset|token_set|tokenList)[^)]*,\\s*(address\\[\\]|addressList|addrList)'}, {'contract.source_matches_regex': '(?i)struct\\s+\\w+\\s*\\{[^}]*(string|bytes32)\\s+(chain|chainId|chain_id)[^}]*address\\s+(tokenAddress|token_address|addr)'}, {'function.body_contains_regex': '(?i)require\\s*\\([^;{}]*\\.(tokenAddress|token_address|addr|address)\\s*==\\s*\\w+\\[i\\]'}, {'function.body_not_contains_regex': '(?i)(require|assert)\\s*\\([^;{}]*\\.(chain|chainId|chain_id)\\b[^;{}]*==[^;]{0,60}\\)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}, {'function.not_in_skip_list': True}]

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
                info = [f, f" — token-set-chain-field-not-validated: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
