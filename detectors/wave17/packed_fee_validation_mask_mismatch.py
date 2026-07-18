"""
packed-fee-validation-mask-mismatch

Fixture-smoke/source-shape detector for a packed directional-fee helper that
extracts the low 12-bit fee from `self` with a container-width assembly mask
such as `0xffff`. That shape lets adjacent packed bits bleed into the current
fee calculation.

Submission posture: NOT_SUBMIT_READY. This row is intentionally narrow and is
backed only by the checked-in fixture pair.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


_FUNCTION_NAME_RE = re.compile(r"(?i)^(?:calculateSwapFee|computeFee|applyFee|_packedFee)$")
_PACKED_FEE_CONTEXT_RE = re.compile(
    r"(?i)\b(?:uint24|protocolFee|lpFee|zeroForOne|fee0to1|fee1to0|directional fee)\b"
)
_SELF_PARAM_RE = re.compile(r"(?i)\buint(?:24|32|256)\s+self\b")
_MEMORY_SAFE_ASSEMBLY_RE = re.compile(r'assembly\s*\("memory-safe"\)', re.IGNORECASE)
_TOO_WIDE_SELF_MASK_RE = re.compile(
    r"and\s*\(\s*self\s*,\s*0x(?:ffff|ffffff|ffffffff)\s*\)",
    re.IGNORECASE,
)
_PACKED_DIRECTION_SPLIT_RE = re.compile(
    r"(?is)(?:\bzeroForOne\b.*?\bshr\s*\(\s*12\s*,\s*self\s*\)|\bshr\s*\(\s*12\s*,\s*self\s*\).*\bzeroForOne\b)"
)


def _source(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


def _has_packed_fee_validation_mask_mismatch_shape(src: str) -> bool:
    if not _SELF_PARAM_RE.search(src):
        return False
    if not _MEMORY_SAFE_ASSEMBLY_RE.search(src):
        return False
    if not _TOO_WIDE_SELF_MASK_RE.search(src):
        return False
    return bool(_PACKED_DIRECTION_SPLIT_RE.search(src))


class PackedFeeValidationMaskMismatch(AbstractDetector):
    ARGUMENT = "packed-fee-validation-mask-mismatch"
    HELP = (
        "Internal packed-fee helper uses an assembly container-width mask "
        "such as 0xffff on the low 12-bit fee sub-field, allowing adjacent "
        "packed fee bits to bleed into the current swap-fee calculation."
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "packed-fee-validation-mask-mismatch.yaml"
    )
    WIKI_TITLE = "Packed fee-field mask uses container width instead of field width"
    WIKI_DESCRIPTION = (
        "A packed directional-fee helper stores two 12-bit fees in one word. "
        "If inline assembly extracts the low fee with `and(self, 0xffff)` or "
        "another container-width mask, bits from the adjacent packed field can "
        "contaminate the current fee calculation."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A swap-fee helper adds `and(self, 0xffff)` for the zero-for-one path. "
        "When the opposite direction's fee occupies the adjacent packed bits, "
        "the extracted fee is inflated and downstream accounting diverges."
    )
    WIKI_RECOMMENDATION = (
        "Mask packed fee sub-fields at their exact width. For a 12-bit fee use "
        "`and(self, 0xfff)` for the low direction and shift before masking the "
        "high direction."
    )

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            contract_src = _source(contract)
            if not _PACKED_FEE_CONTEXT_RE.search(contract_src):
                continue

            for function in contract.functions_and_modifiers_declared:
                if getattr(function, "visibility", "") != "internal":
                    continue
                if is_leaf_helper(function):
                    continue
                if not _FUNCTION_NAME_RE.search(function.name or ""):
                    continue

                function_src = _source(function)
                if not _PACKED_FEE_CONTEXT_RE.search(function_src):
                    continue
                if not _has_packed_fee_validation_mask_mismatch_shape(function_src):
                    continue

                info = [
                    function,
                    (
                        " — packed-fee-validation-mask-mismatch: low packed fee "
                        "uses a container-width assembly mask and can absorb "
                        "adjacent directional-fee bits."
                    ),
                ]
                results.append(self.generate_result(info))
        return results
