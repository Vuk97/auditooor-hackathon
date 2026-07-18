"""
unsafe-downcast-uint-truncation — generated from reference/patterns.dsl/unsafe-downcast-uint-truncation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py unsafe-downcast-uint-truncation.yaml
Source: auto-mined-from-diffs/downsize-uint-cluster
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class UnsafeDowncastUintTruncation(AbstractDetector):
    ARGUMENT = "unsafe-downcast-uint-truncation"
    HELP = "External/public function narrows a uint to a smaller uintN (uint96/uint112/uint128) via bare cast; Solidity 0.8 does not check conversions, so values above 2**N-1 are silently truncated. Corrupts ERC20Votes checkpoints, staking balances, and packed-storage fields."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/unsafe-downcast-uint-truncation.yaml"
    WIKI_TITLE = "Unsafe uint downcast: narrowing to uintN silently truncates high bits"
    WIKI_DESCRIPTION = "Solidity's `uintN(uintM)` narrowing conversion is a bit-level truncation — the top `M-N` bits are discarded without range check. Solidity 0.8+ overflow guards only protect arithmetic operations, not conversions, so no revert fires. The bug is common in ERC20Votes / checkpointed balance systems that pack votes into uint96 to co-locate with a uint32 timestamp in a single storage slot, in staking con"
    WIKI_EXPLOIT_SCENARIO = "A governance token inherits ERC20Votes; checkpoints pack `uint96 votes` alongside a `uint32 fromBlock` in one storage slot. The contract's custom `mint` path casts the minted amount to uint96 with `uint96(amount)` before writing the checkpoint. An attacker with DAO minter role mints `2**96 + 1` tokens to their own address; the cast truncates to `1`, the checkpoint records 1 vote, but the ERC-20 `_"
    WIKI_RECOMMENDATION = "Import `@openzeppelin/contracts/utils/math/SafeCast.sol` and route every narrowing conversion through `SafeCast.toUint128(x)` / `toUint96(x)` / `toUint64(x)`, which reverts when the source value exceeds the target's capacity. For home-rolled code use `require(x <= type(uintN).max, 'downcast overflow"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.not_slither_synthetic': True}, {'function.body_contains_regex': 'uint(8|16|24|32|40|48|56|64|72|88|96|112|128|160|192|224)\\s*\\('}, {'function.body_not_contains_regex': 'SafeCast\\.toUint|\\.toUint(8|16|32|64|96|112|128|160)\\s*\\(|require\\s*\\([^;]*<=\\s*type\\s*\\(\\s*uint(8|16|32|64|96|112|128|160)\\s*\\)\\.max|require\\s*\\([^;]*<\\s*2\\s*\\*\\*\\s*(8|16|32|64|96|112|128|160)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}]

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
                info = [f, f" — unsafe-downcast-uint-truncation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
