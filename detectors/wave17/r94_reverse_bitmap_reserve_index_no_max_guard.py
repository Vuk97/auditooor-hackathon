"""
r94-reverse-bitmap-reserve-index-no-max-guard — generated from reference/patterns.dsl/r94-reverse-bitmap-reserve-index-no-max-guard.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-reverse-bitmap-reserve-index-no-max-guard.yaml
Source: reverse-port-from-rust_wave1
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94ReverseBitmapReserveIndexNoMaxGuard(AbstractDetector):
    ARGUMENT = "r94-reverse-bitmap-reserve-index-no-max-guard"
    HELP = "NOT_SUBMIT_READY detector-fixture-smoke-only: reserve bitmap shifts `reserveIndex * 2` into a packed two-bits-per-reserve layout without a visible MAX_RESERVES guard."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-reverse-bitmap-reserve-index-no-max-guard.yaml"
    WIKI_TITLE = "Bitmap reserve-index shift missing MAX_RESERVES guard"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. This row proves only the owned Solidity sibling shape where a UserConfiguration-style bitmap computes bit positions from `reserveIndex * 2` / `(reserveIndex << 1)` but exposes no visible `< MAX_RESERVES` guard in the same function. It does not claim corpus-backed exploitability beyond the local fixture pair."
    WIKI_EXPLOIT_SCENARIO = "A pool configuration helper exposes `setUsingAsCollateral(uint256 reserveIndex, bool enabled)` and directly computes `uint256(1) << (reserveIndex << 1)` into a packed bitmap. A caller can supply an index that exceeds the intended 64-reserve layout; the bit math no longer targets a valid reserve slot, so collateral/borrowing flags are updated using an out-of-layout exponent instead of reverting. This row remains fixture-smoke only."
    WIKI_RECOMMENDATION = "Add an explicit `require(reserveIndex < MAX_RESERVES, 'invalid reserve')` or equivalent helper before every bitmap read/write, and keep the row NOT_SUBMIT_READY until evidence extends beyond the checked-in fixture pair."

    SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
    COVERAGE_CLAIM = "detector_fixture_smoke_only"
    PROMOTION_ALLOWED = False

    _PRECONDITIONS = [{'contract.source_matches_regex': '(UserConfiguration|reserveIndex|reservesList|assetId|PoolStorage|reserveId|BorrowingFlags|CollateralFlags)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '(?i)^(setUsingAsCollateral|setBorrowing|isUsingAsCollateral|isBorrowing|_setUsingAsCollateral|_setBorrowing|configureBit|setAssetUsed|setAssetBorrowed)$'}, {'function.body_contains_regex': '(1\\s*<<\\s*\\(\\s*\\w+\\s*\\*\\s*2|<<\\s*\\(\\s*\\w+\\s*<<\\s*1|\\w+\\s*\\*\\s*2\\s*\\+\\s*1|setBit|_setBit)'}, {'function.body_not_contains_regex': '(require\\s*\\([^)]*<\\s*(?:128|64|MAX_RESERVES|MAX_NUMBER_RESERVES|MAX_ASSETS|maxReserves|RESERVE_COUNT)|assert\\s*\\([^)]*<\\s*(?:128|64|MAX_RESERVES))'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — r94-reverse-bitmap-reserve-index-no-max-guard: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
