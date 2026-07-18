"""
hook-return-data-length-not-validated — generated from reference/patterns.dsl/hook-return-data-length-not-validated.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py hook-return-data-length-not-validated.yaml
Source: auditooor-R71-fixdiff-mined-uniswap-v4-f350d10a
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class HookReturnDataLengthNotValidated(AbstractDetector):
    ARGUMENT = "hook-return-data-length-not-validated"
    HELP = "Function decodes hook return data at fixed memory offsets (0x40 / 0x60) without first checking `result.length`. A short return lets garbage memory be parsed as the returned delta or fee."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/hook-return-data-length-not-validated.yaml"
    WIKI_TITLE = "Hook return-data parsed at fixed offsets without length check — garbage-memory delta"
    WIKI_DESCRIPTION = "AMMs that invoke a user-provided hook and expect an ABI-encoded (bytes4 selector, int256 delta[, uint24 fee]) tuple often read those fields directly via assembly at offsets 0x20/0x40/0x60 of the `bytes memory result`. Without a prior `require(result.length == expected)` check, a hook that returns fewer bytes leaves the offsets pointing into unrelated heap memory (the Solidity free-memory region)."
    WIKI_EXPLOIT_SCENARIO = "Uniswap v4 ABDK CVF-44 (2024): a hook returned only `bytes4(selector)` (32 bytes) from afterSwap. The caller's parseReturnDelta read `mload(add(result, 0x40))` which returned whatever was sitting in memory at that offset (tail of the hookData calldata or FMP bookkeeping), and credited the caller with that value as a delta."
    WIKI_RECOMMENDATION = "Before any assembly offset-read on hook-returned bytes, validate the length: `if (result.length != 64) revert InvalidHookResponse()` for (selector, int256), `!= 96` for (selector, int256, uint24). Apply the check inside the shared callHook helper so every permissioned hook path inherits the guard."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'internal'}, {'function.name_matches': 'callHook|callHookWith|_callHook|callCallback|afterSwap|afterModify|beforeSwap'}, {'function.body_contains_regex': 'parseSelector|parseReturnDelta|parseFee|mload\\s*\\(\\s*add\\s*\\(\\s*result\\s*,\\s*0x(40|60|80)'}, {'function.body_not_contains_regex': 'result\\.length\\s*(<|!=|==)\\s*(32|64|96)|require\\s*\\(\\s*result\\.length'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — hook-return-data-length-not-validated: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
