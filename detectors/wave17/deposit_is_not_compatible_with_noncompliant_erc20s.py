"""
deposit-is-not-compatible-with-noncompliant-erc20s - generated from reference/patterns.dsl/deposit-is-not-compatible-with-noncompliant-erc20s.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py deposit-is-not-compatible-with-noncompliant-erc20s.yaml
Source: zellic audit ether.fi - Zellic Audit Report
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DepositIsNotCompatibleWithNoncompliantErc20s(AbstractDetector):
    ARGUMENT = "deposit-is-not-compatible-with-noncompliant-erc20s"
    HELP = "depositWithERC20 requires a bool return from IERC20.transferFrom, so no-return ERC20s such as legacy USDT-style tokens revert despite a successful transfer."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/deposit-is-not-compatible-with-noncompliant-erc20s.yaml"
    WIKI_TITLE = "Deposit is not compatible with noncompliant ERC20s"
    WIKI_DESCRIPTION = "A deposit path that binds `bool sent = IERC20(token).transferFrom(...)` and then `require(sent)` assumes the token returns a boolean. Some deployed ERC20s return no data on success. Solidity ABI decoding then reverts, making deposits incompatible with those tokens."
    WIKI_EXPLOIT_SCENARIO = "A supported deposit token follows the legacy no-return ERC20 behavior. `depositWithERC20` calls `IERC20(token).transferFrom(...)` as a typed bool-returning call and requires the decoded bool. The token transfer succeeds but returns empty data, so the deposit reverts and users cannot deposit that asset."
    WIKI_RECOMMENDATION = "Use OpenZeppelin SafeERC20.safeTransferFrom or an equivalent optional-return wrapper that treats empty return data as success and reverts only on false return data or failed low-level calls."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'depositWithERC20|transferFrom|SafeERC20'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^depositWithERC20$'}, {'function.body_contains_regex': 'bool\\s+\\w+\\s*=\\s*(?:IERC20\\s*\\([^)]*\\)|[A-Za-z_][A-Za-z0-9_]*)\\s*\\.\\s*transferFrom\\s*\\('}, {'function.body_contains_regex': 'require\\s*\\(\\s*[A-Za-z_][A-Za-z0-9_]*\\s*,'}, {'function.body_not_contains_regex': 'safeTransferFrom|SafeERC20|_callOptionalReturn|functionCall|abi\\.decode'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" - deposit-is-not-compatible-with-noncompliant-erc20s: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
