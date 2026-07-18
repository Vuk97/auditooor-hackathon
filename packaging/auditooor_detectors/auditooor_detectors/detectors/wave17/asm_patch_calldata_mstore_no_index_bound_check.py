"""
asm-patch-calldata-mstore-no-index-bound-check — generated from reference/patterns.dsl/asm-patch-calldata-mstore-no-index-bound-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py asm-patch-calldata-mstore-no-index-bound-check.yaml
Source: lisa-mine-r99-case-01111-c4-aera-2024
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AsmPatchCalldataMstoreNoIndexBoundCheck(AbstractDetector):
    ARGUMENT = "asm-patch-calldata-mstore-no-index-bound-check"
    HELP = "External-call patcher computes a calldata offset via inline assembly `mstore(add(ptr + 0x24, mul(userIndex, 0x20)), userValue)` without first bounding `userIndex` against `data.length / 0x20`. For sufficiently large `userIndex`, the multiplication overflows uint256 and the resulting offset wraps to "
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/asm-patch-calldata-mstore-no-index-bound-check.yaml"
    WIKI_TITLE = "Calldata-patch helper: mstore offset uses unchecked `mul(index, 0x20)` — selector overwrite"
    WIKI_DESCRIPTION = "Pattern fires on `_patchAmountAndCall`-style helpers that splice a single user-provided `swapAmount` value into a generic forwarded calldata via inline assembly. The bug shape: `mstore(add(add(ptr, 0x24), mul(swapAmountInDataIndex, 0x20)), swapAmountInDataValue)` runs INSIDE an `assembly { }` block where Solidity's overflow checks DO NOT apply. A caller can set `swapAmountInDataIndex` to a value s"
    WIKI_EXPLOIT_SCENARIO = "Aera vault uses `ExternalCall._patchAmountAndCall` to forward a user-supplied trade through an aggregator. The aggregator's calldata selector is `0x18b6a93b` (e.g. `swap`). An attacker computes an `index` such that `index * 32` overflows to land at offset 0; sets `swapAmountInDataValue` to `0x70a08231...` (the `balanceOf(address)` selector with a calldata-formed argument). The call now reads as `a"
    WIKI_RECOMMENDATION = "Bound `swapAmountInDataIndex` BEFORE the assembly block: `require(swapAmountInDataIndex * 32 + 32 <= data.length - 4, 'idx out of range');`. Equivalently, validate inside the assembly using `lt(mul(idx, 0x20), data.length)` and `gt(idx, lt(idx, MAX_INT))`. Add a fuzz test that sweeps `index` over th"

    _PRECONDITIONS = [{'contract.has_function_matching': '_patchAmount|_patchCall|_patchData|patchCalldata'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '_patchAmount|_patchCall|_patchData|patchCalldata|_patchAndCall'}, {'function.body_contains_regex': 'mstore\\s*\\(\\s*add\\s*\\([^)]*\\)\\s*,\\s*mul\\s*\\(\\s*[A-Za-z_]\\w*\\s*,\\s*0x20|mstore\\s*\\([^)]*mul\\s*\\(\\s*[A-Za-z_]\\w*\\s*,\\s*0x20\\s*\\)'}, {'function.body_not_contains_regex': 'require\\s*\\([^)]*Index\\s*\\*\\s*(0x20|32)|require\\s*\\([^)]*Index\\s*<\\s*data\\.length|require\\s*\\([^)]*[Ii]ndex\\s*<\\s*\\(\\s*data\\.length|assert\\s*\\([^)]*Index\\s*<|require\\s*\\([^)]*\\bidx\\s*<'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" — asm-patch-calldata-mstore-no-index-bound-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
