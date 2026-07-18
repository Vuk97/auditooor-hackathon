"""
reentrancy-swap-executor-callback-permit2 — generated from reference/patterns.dsl/reentrancy-swap-executor-callback-permit2.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py reentrancy-swap-executor-callback-permit2.yaml
Source: solodit-novel/slice_aa
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ReentrancySwapExecutorCallbackPermit2(AbstractDetector):
    ARGUMENT = "reentrancy-swap-executor-callback-permit2"
    HELP = "Function invokes SwapExecutor.executeSwap with Permit2 pulls in scope but has no nonReentrant. Executor callback can reenter and drain user allowance."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/reentrancy-swap-executor-callback-permit2.yaml"
    WIKI_TITLE = "Swap executor callback allows Permit2 drain via reentry"
    WIKI_DESCRIPTION = "Functions that pair an external `swapExecutor.executeSwap(data)` call with Permit2 `permitTransferFrom` flows expose a reentrancy window. A malicious or compromised swap executor can reenter the same contract (or a sibling) during the callback while the user's Permit2 allowance is still live, pulling additional funds beyond the intended swap amount."
    WIKI_EXPLOIT_SCENARIO = "Router calls `permit2.permitTransferFrom(sig, ...)` for 100 USDC, then `swapExecutor.executeSwap(data)`. Attacker-controlled executor reenters the router (no nonReentrant) and calls the same swap path with the same (still-valid) permit signature — second transfer of 100 USDC for only one legitimate swap. Universal pattern on any router that trusts its executor."
    WIKI_RECOMMENDATION = "Apply `nonReentrant` to every router/executor entry-point that pairs Permit2 with external-call swap execution. Use ERC-7683 / single-use permit IDs so double-spend is impossible even on reentry. Validate the executor is in an immutable allowlist."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'ISwapExecutor|SWAP_EXECUTOR|Permit2|permit2|IPermit2|executeSwap'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.body_contains_regex': 'executeSwap|SWAP_EXECUTOR\\.|ISwapExecutor\\s*\\('}, {'function.body_contains_regex': 'permit2|Permit2|permitTransferFrom'}, {'function.has_modifier': {'includes': ['nonReentrant', 'reentrancyGuard', 'lock'], 'negate': True}}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — reentrancy-swap-executor-callback-permit2: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
