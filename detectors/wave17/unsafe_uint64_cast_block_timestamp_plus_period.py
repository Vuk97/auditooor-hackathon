"""
unsafe-uint64-cast-block-timestamp-plus-period — generated from reference/patterns.dsl/unsafe-uint64-cast-block-timestamp-plus-period.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py unsafe-uint64-cast-block-timestamp-plus-period.yaml
Source: auditooor-R107-thegraph-OZ-M-01
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class UnsafeUint64CastBlockTimestampPlusPeriod(AbstractDetector):
    ARGUMENT = "unsafe-uint64-cast-block-timestamp-plus-period"
    HELP = "A future-time variable (`unlockAt`, `thawingUntil`, `expiry`) is computed as `uintN(block.timestamp + period)` with N narrower than 256, but the protocol does not check that `block.timestamp + period <= type(uintN).max`. A user-supplied (or governance-supplied) `period` near `uintN.max` causes the c"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/unsafe-uint64-cast-block-timestamp-plus-period.yaml"
    WIKI_TITLE = "Unsafe narrowing cast on `block.timestamp + period` enables instant maturity bypass"
    WIKI_DESCRIPTION = "Many staking, vesting and dispute contracts pack future timestamps into uint64 (or uint32 / uint40 / uint48) slots to save gas. The dangerous shape is `uint64(block.timestamp + period)` where `period` is settable by a user or by governance and is not pre-bounded against `type(uint64).max - block.timestamp`. The Solidity narrowing cast is *non-checked* (it silently truncates the high bits), so a `p"
    WIKI_EXPLOIT_SCENARIO = "Service provider misbehaves and sees a slashing dispute incoming. Atomically: (a) `setProvisionParameters(thawingPeriod = type(uint64).max)`, (b) `acceptProvisionPendingParameters()`, (c) `thaw(allTokens)` — the implementation computes `uint64(block.timestamp + uint256(prov.thawingPeriod))` which wraps to `block.timestamp - 1`, (d) `deprovision(allTokens)` succeeds because `now >= thawingUntil` is"
    WIKI_RECOMMENDATION = "Either (1) use OpenZeppelin `SafeCast.toUint64(block.timestamp + period)` which reverts on overflow, or (2) require an explicit upper bound: `require(block.timestamp + period <= type(uint64).max, Overflow());` before the cast, or (3) cap `period` at a protocol-safe maximum (e.g. 56 days) using a har"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.body_contains_regex': '\\b(?:uint64|uint40|uint48|uint32)\\s*\\(\\s*block\\.timestamp\\s*\\+\\s*(?:uint256\\s*\\(\\s*)?[A-Za-z_]'}, {'function.body_not_contains_regex': 'require\\s*\\([^;]*?block\\.timestamp\\s*\\+[^;]*?<=\\s*type\\s*\\(\\s*uint(?:64|40|48|32)\\s*\\)\\s*\\.\\s*max'}, {'function.body_not_contains_regex': '(?i)SafeCast\\.toUint(?:64|40|48|32)\\s*\\(\\s*block\\.timestamp\\s*\\+'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — unsafe-uint64-cast-block-timestamp-plus-period: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
