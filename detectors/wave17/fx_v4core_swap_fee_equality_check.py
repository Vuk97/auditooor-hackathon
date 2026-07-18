"""
fx-v4core-swap-fee-equality-check — generated from reference/patterns.dsl/fx-v4core-swap-fee-equality-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fx-v4core-swap-fee-equality-check.yaml
Source: github:Uniswap/v4-core@1755bfc
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FxV4coreSwapFeeEqualityCheck(AbstractDetector):
    ARGUMENT = "fx-v4core-swap-fee-equality-check"
    HELP = "swap() guards exact-output path with swapFee == MAX_SWAP_FEE instead of swapFee >= MAX_SWAP_FEE. A combined LP+protocol fee that exceeds MAX_SWAP_FEE by even 1 pip bypasses the guard, causing the swap loop to consume all input without producing output."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fx-v4core-swap-fee-equality-check.yaml"
    WIKI_TITLE = "Swap fee boundary check uses == instead of >= — exact-output bypass when fee exceeds max"
    WIKI_DESCRIPTION = "AMM swap functions that reject exact-output swaps when the pool fee equals 100% must use >= rather than == for the comparison. A hook-set dynamic LP fee combined with a protocol fee can sum to a value strictly greater than MAX_SWAP_FEE; the == guard passes silently, executing a swap that tries to fill an output amount from zero remaining input."
    WIKI_EXPLOIT_SCENARIO = "Uniswap v4 Trail of Bits i01 / Spearbit M01 (2023): hook sets lpFee to MAX_LP_FEE and protocol adds a non-zero protocolFee. Combined swapFee = 1_000_001. The guard `if (swapFee == 1_000_000)` is bypassed; an exact-output swap with amountOut > 0 loops until gas exhaustion."
    WIKI_RECOMMENDATION = "Use `swapFee >= MAX_SWAP_FEE` for the exact-output guard. Apply the same >= pattern to any fee-cap enforcement inside swap math libraries."

    _PRECONDITIONS = [{'contract.has_function_matching': '^(swap|_swap|swapExact)$'}, {'contract.source_matches_regex': 'MAX_SWAP_FEE|MAX_LP_FEE|swapFee'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(swap|_swap|swapExact)$'}, {'function.body_contains_regex': 'swapFee\\s*==\\s*MAX_|fee\\s*==\\s*MAX_SWAP_FEE|lpFee\\s*==\\s*MAX_'}, {'function.body_contains_regex': 'exactInput|exactOutput|amountSpecified'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fx-v4core-swap-fee-equality-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
