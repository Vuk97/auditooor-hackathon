"""
pancakeswap-v3-flashloan-callback-pancakev3swapcallback-lacks-sender-v — generated from reference/patterns.dsl/pancakeswap-v3-flashloan-callback-pancakev3swapcallback-lacks-sender-v.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py pancakeswap-v3-flashloan-callback-pancakev3swapcallback-lacks-sender-v.yaml
Source: hexens-glider/pancake-swap-v3-flashloan-callback-pancake-v3swap
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PancakeswapV3FlashloanCallbackPancakev3swapcallbackLacksSenderV(AbstractDetector):
    ARGUMENT = "pancakeswap-v3-flashloan-callback-pancakev3swapcallback-lacks-sender-v"
    HELP = "PancakeSwap V3 `pancakeV3SwapCallback` performs callback effects without visible sender validation."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/pancakeswap-v3-flashloan-callback-pancakev3swapcallback-lacks-sender-v.yaml"
    WIKI_TITLE = "PancakeSwap V3 pancakeV3SwapCallback missing sender validation"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. This row proves only the checked-in callback shape where an externally callable `pancakeV3SwapCallback` decodes callback data, writes callback state, and transfers token0 without a visible `msg.sender` guard or verifyCallback-style pool validation. NOT_SUBMIT_READY."
    WIKI_EXPLOIT_SCENARIO = "The local positive fixture models a receiver callback that transfers token0 to `msg.sender` during `pancakeV3SwapCallback` after decoding calldata, but without checking that the caller is the expected PancakeSwap V3 pool. This is not corpus-backed exploit evidence."
    WIKI_RECOMMENDATION = "Validate the callback caller before any token movement or privileged state transition, either with `require(msg.sender == expectedPool)` or a PancakeSwap V3 verifyCallback helper. Do not promote this row from fixture smoke alone."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'pancakeV3SwapCallback\\s*\\('}]
    _MATCH = [{'function.name_matches': '^pancakeV3SwapCallback$'}, {'function.kind': 'external_or_public'}, {'function.body_contains_regex': 'transfer|transferFrom|safeTransfer|approve|call|delegatecall|swap'}, {'function.body_not_contains_regex': 'verifyCallback|validateCallback|CallbackValidation|msg\\.sender\\s*(==|!=)|(?:==|!=)\\s*msg\\.sender'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}]

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
                info = [f, f" — pancakeswap-v3-flashloan-callback-pancakev3swapcallback-lacks-sender-v: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
