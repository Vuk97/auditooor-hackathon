"""
glider-yul-assembly-unchecked-arith — generated from reference/patterns.dsl/glider-yul-assembly-unchecked-arith.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-yul-assembly-unchecked-arith.yaml
Source: hexens-glider/integer-overflowunderflow-in-yul-assembly
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderYulAssemblyUncheckedArith(AbstractDetector):
    ARGUMENT = "glider-yul-assembly-unchecked-arith"
    HELP = "Inline Yul uses `add` / `sub` / `mul` without an overflow/underflow guard. Unlike Solidity 0.8+, Yul arithmetic wraps silently — a computation that would revert in Solidity quietly produces garbage in assembly."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-yul-assembly-unchecked-arith.yaml"
    WIKI_TITLE = "Unchecked overflow / underflow in inline Yul arithmetic"
    WIKI_DESCRIPTION = "Developers often drop into `assembly { ... }` for gas or bit-packing and unconsciously lose 0.8's checked arithmetic. `add(MAX, 1) = 0`, `sub(0, 1) = MAX`, `mul(large, large) = low128(product)`. Wherever the result feeds pricing, accounting, or access control, this produces silent corruption."
    WIKI_EXPLOIT_SCENARIO = "Gas-golfed balance update: `assembly { sstore(slot, add(sload(slot), delta)) }` with user-controlled `delta`. Attacker crafts delta such that add overflows and the slot is set to a small residue — balance check elsewhere succeeds, but the invariant (supply == sum balances) silently breaks."
    WIKI_RECOMMENDATION = "Either do the arithmetic in Solidity (let 0.8 check) or explicitly add a Yul overflow guard: `if lt(sum, a) { revert(0,0) }` before committing. For multiplication, compare the high 256 bits via `mulmod`."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'assembly\\s*\\{'}]
    _MATCH = [{'function.kind': 'any'}, {'function.assembly_block_matches': '\\b(add|sub|mul)\\s*\\('}, {'function.body_not_contains_regex': 'require\\s*\\([^)]*(<=|>=|<|>)[^)]*(type\\s*\\(\\s*uint|max|MAX|cap|CAP)|assembly\\s*\\{[^}]*(lt|gt|iszero)[^}]*revert'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-yul-assembly-unchecked-arith: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
