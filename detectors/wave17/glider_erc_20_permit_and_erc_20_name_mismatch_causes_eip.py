"""
glider-erc-20-permit-and-erc-20-name-mismatch-causes-eip — generated from reference/patterns.dsl/glider-erc-20-permit-and-erc-20-name-mismatch-causes-eip.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-erc-20-permit-and-erc-20-name-mismatch-causes-eip.yaml
Source: hexens-glider/erc-20-permit-and-erc-20-name-mismatch-causes-eip
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderErc20PermitAndErc20NameMismatchCausesEip(AbstractDetector):
    ARGUMENT = "glider-erc-20-permit-and-erc-20-name-mismatch-causes-eip"
    HELP = "ERC20Permit and ERC20 Name Mismatch Causes EIP712 Signature Failure"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-erc-20-permit-and-erc-20-name-mismatch-causes-eip.yaml"
    WIKI_TITLE = "ERC20Permit and ERC20 Name Mismatch Causes EIP712 Signature Failure"
    WIKI_DESCRIPTION = "ERC20Permit relies on EIP712 domain construction, which includes the token’s `name()` value. If a contract inherits both `ERC20` and `ERC20Permit` but uses **different name arguments** for each (e.g., `ERC20(\"TokenA\", \"TKA\")` and `ERC20Permit(\"TokenB\")`), the generated EIP712 domain will not match what off-chain signers expect based on `ERC20.name()`. This mismatch causes all `permit()` sign"
    WIKI_EXPLOIT_SCENARIO = "Transpiled from Hexens Glider query erc-20-permit-and-erc-20-name-mismatch-causes-eip. Tags: ERC20, ERC20Permit."
    WIKI_RECOMMENDATION = "Apply the check implied by the original Glider query — see hexens-glider source for context."

    _PRECONDITIONS = [{'function.is_constructor': True}, {'contract.source_matches_regex': '(ERC20Permit|EIP712|ERC20Votes|IERC20Permit|Permit\\s*\\(|is\\s+ERC20Permit|is\\s+ERC20.*Permit)'}]
    _MATCH = [{'function.is_constructor': True}, {'function.body_contains_regex': 'ERC20\\s*\\(\\s*"[^"]+"\\s*,\\s*"[^"]+"\\s*\\)'}, {'function.body_contains_regex': 'ERC20Permit\\s*\\(\\s*"[^"]+"\\s*\\)'}, {'function.body_not_contains_regex': 'ERC20\\s*\\(\\s*(\\w+)\\s*,[^)]*\\)[^{}]*ERC20Permit\\s*\\(\\s*\\1\\s*\\)|ERC20\\s*\\(\\s*"([^"]+)"\\s*,[^)]*\\)[^{}]*ERC20Permit\\s*\\(\\s*"\\2"\\s*\\)|ERC20Permit\\s*\\(\\s*name\\s*\\(\\s*\\)\\s*\\)|ERC20Permit\\s*\\(\\s*_name\\s*\\)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)(abstract\\s+contract|contract\\s+\\w*Test\\w*\\s*is|contract\\s+Mock|contract\\s+Fake|//\\s*intentional\\s+mismatch|internal\\s+pure\\s+returns)'}]

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
                info = [f, f" — glider-erc-20-permit-and-erc-20-name-mismatch-causes-eip: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
