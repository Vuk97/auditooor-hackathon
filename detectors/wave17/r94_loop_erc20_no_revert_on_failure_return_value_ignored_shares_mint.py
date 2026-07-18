"""
r94-loop-erc20-no-revert-on-failure-return-value-ignored-shares-mint — generated from reference/patterns.dsl/r94-loop-erc20-no-revert-on-failure-return-value-ignored-shares-mint.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-erc20-no-revert-on-failure-return-value-ignored-shares-mint.yaml
Source: solodit-32370-sherlock-teller-finance
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopErc20NoRevertOnFailureReturnValueIgnoredSharesMint(AbstractDetector):
    ARGUMENT = "r94-loop-erc20-no-revert-on-failure-return-value-ignored-shares-mint"
    HELP = "r94-loop-erc20-no-revert-on-failure-return-value-ignored-shares-mint"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-erc20-no-revert-on-failure-return-value-ignored-shares-mint.yaml"
    WIKI_TITLE = "r94-loop-erc20-no-revert-on-failure-return-value-ignored-shares-mint"
    WIKI_DESCRIPTION = "r94-loop-erc20-no-revert-on-failure-return-value-ignored-shares-mint"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-erc20-no-revert-on-failure-return-value-ignored-shares-mint"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(Lender|LenderGroup|Vault|Pool|Deposit|Stake|Mint)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(deposit|joinPool|addToGroup|addLiquidity|stake|mintShares|supply|contribute|buyShares)'}, {'function.source_matches_regex': '(token\\.transferFrom\\s*\\([\\s\\S]{0,120}?\\)\\s*;[\\s\\S]{0,200}?_mint|IERC20\\s*\\(\\s*\\w+\\s*\\)\\s*\\.\\s*transferFrom\\s*\\([\\s\\S]{0,120}?\\)\\s*;[\\s\\S]{0,200}?_mint)'}, {'function.not_source_matches_regex': '(require\\s*\\(\\s*\\w*token\\s*\\.\\s*transferFrom|require\\s*\\(\\s*IERC20\\s*\\(\\s*\\w+\\s*\\)\\s*\\.\\s*transferFrom|SafeERC20|safeTransferFrom|bool\\s+success\\s*=\\s*\\w*token\\.transferFrom|assert\\s*\\(\\s*token\\.transferFrom)'}]

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
                info = [f, f" — r94-loop-erc20-no-revert-on-failure-return-value-ignored-shares-mint: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
