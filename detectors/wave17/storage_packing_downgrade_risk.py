"""
storage-packing-downgrade-risk — generated from reference/patterns.dsl/storage-packing-downgrade-risk.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py storage-packing-downgrade-risk.yaml
Source: auditooor/round-29/polymarket-D14
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class StoragePackingDowngradeRisk(AbstractDetector):
    ARGUMENT = "storage-packing-downgrade-risk"
    HELP = "Inline-assembly packed-struct write uses `shl`/`shr` on a caller-controlled value without bounding it to the destination sub-word width; solc masks the high bits, silently truncating oversized inputs and corrupting the packed field."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/storage-packing-downgrade-risk.yaml"
    WIKI_TITLE = "Packed-struct assembly write silently truncates unbounded input"
    WIKI_DESCRIPTION = "A function pack-encodes a caller-influenced value into a storage slot via inline assembly using `shl(N, v)` or `shr(N, v)` combined with `or(...)` — e.g. `sstore(slot, or(shl(8, remaining), rest))`. No prior `require` bounds the input against the destination sub-word (`uint8`, `uint16`, `uint32`, etc.) width. When an oversized value is passed, the compiler-inserted / programmer-inserted mask drops"
    WIKI_EXPLOIT_SCENARIO = "A bookkeeping struct packs `uint8 remaining` into the high byte of a 256-bit slot via `sstore(slot, or(shl(248, remaining), ...))`. A caller passes `remaining = 300`. The `shl(248, 300)` operation produces `300 mod 256 = 44` in the high byte. The sstore completes, the function returns, but `remaining` is now 44 — not 300. Downstream accounting that reads `remaining` diverges from the intended stat"
    WIKI_RECOMMENDATION = "Before any sub-word pack, `require(value <= type(uintN).max)` (or the equivalent numeric bound) for every input that flows into a shifted pack site. Prefer high-level Solidity struct assignment over inline-assembly packing so the compiler can emit a full-width revert on overflow rather than a silent"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'any'}, {'function.body_contains_regex': 'shl\\s*\\(\\s*\\d+\\s*,\\s*\\w+\\s*\\)|shr\\s*\\(\\s*\\d+\\s*,\\s*\\w+\\s*\\)'}, {'function.body_not_contains_regex': 'require\\s*\\([^;]*(<|<=)\\s*type\\s*\\(\\s*uint\\d+\\s*\\)\\.max|require\\s*\\([^;]*(<|<=)\\s*(255|65535|4294967295|2\\*\\*\\d+)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — storage-packing-downgrade-risk: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
