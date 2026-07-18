"""
glider-missing-transfer-return-validation — generated from reference/patterns.dsl/glider-missing-transfer-return-validation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-missing-transfer-return-validation.yaml
Source: glider-query-db/missing-transfer-return-validation
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderMissingTransferReturnValidation(AbstractDetector):
    ARGUMENT = "glider-missing-transfer-return-validation"
    HELP = "`IERC20(token).transfer(...)` return value is discarded. Non-reverting-on-failure tokens (ZRX, BAT-era) silently fail, corrupting protocol accounting."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-missing-transfer-return-validation.yaml"
    WIKI_TITLE = "ERC20 transfer/transferFrom return value not checked"
    WIKI_DESCRIPTION = "EIP-20 `transfer` may return `false` instead of reverting. Discarding the return value treats a failed transfer as a success. SafeERC20 or explicit `require(token.transfer(...))` is mandatory."
    WIKI_EXPLOIT_SCENARIO = "Contract pays reward `token.transfer(user, amount)` to a blacklisted user. ERC20 silently returns false; contract increments `paidOut` counter; user receives nothing, attacker accumulates a gap."
    WIKI_RECOMMENDATION = "Use OpenZeppelin SafeERC20's `safeTransfer` / `safeTransferFrom`, or wrap each call with `require(token.transfer(...), 'transfer fail')`."

    _PRECONDITIONS = [{'contract.source_matches_regex': '\\.transfer\\s*\\(|\\.transferFrom\\s*\\('}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '\\w+\\.transfer(From)?\\s*\\([^;]*;'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*\\w+\\.transfer|SafeERC20|safeTransfer|ok\\s*=\\s*.*transfer|success\\s*=\\s*.*transfer|bool\\s+\\w+\\s*=\\s*\\w+\\.transfer'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-missing-transfer-return-validation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
