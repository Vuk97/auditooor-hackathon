"""
yul_calldataload_no_bounds_check.py - Custom Slither detector.

Pattern (W8-8 - 1inch Fusion V1 $4.5M): inline assembly block contains a
`calldataload(p)` without a preceding `calldatasize()` bounds check. Attacker
supplies malformed calldata that reads zero/garbage past the end, which
decodes as attacker-chosen fields (e.g. order maker = attacker).

Detection strategy:
  1. Walk function.nodes; filter NodeType.ASSEMBLY nodes.
  2. Read node.source_mapping.content (raw Yul source).
  3. If `calldataload` is present but `calldatasize` is NOT present in the
     same assembly block, flag.

Simple, conservative - may produce false positives when a Solidity-side check
is done before the assembly. Documented as an over-approximation trade-off.
"""

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.core.cfg.node import NodeType
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.utils.output import Output


SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")


class YulCalldataloadNoBoundsCheck(AbstractDetector):
    """
    Inline assembly uses calldataload without a calldatasize bounds check.
    """

    ARGUMENT = "yul-calldataload-no-bounds-check"
    HELP = (
        "Inline assembly calldataload() without preceding calldatasize() "
        "bounds guard - past-end read decodes as zero"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Yul calldataload Without Bounds Check"
    WIKI_DESCRIPTION = (
        "Inline assembly that calls `calldataload(offset)` without first "
        "verifying `offset + 0x20 <= calldatasize()` silently returns zero "
        "(or stale stack bytes on some clients) when `offset` is past the "
        "end of the user-supplied calldata. Attackers can truncate their "
        "calldata so that decoded fields default to attacker-chosen values - "
        "this was the root cause of the 1inch Fusion V1 $4.5M loss, where a "
        "malformed order let the attacker become the `maker` of every filled "
        "order without supplying a valid signature."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function parse(uint256 offset) external pure returns (uint256 x) {
    assembly {
        x := calldataload(offset)   // no calldatasize check
    }
}
```
Attacker calls parse with a truncated calldata where offset lies past the
end. calldataload returns 0, and the function reports the out-of-bounds
word as a legitimate parsed value, bypassing downstream signature / ACL
checks that expected a non-zero field."""
    WIKI_RECOMMENDATION = (
        "Before every `calldataload(p)` in assembly, verify "
        "`if gt(add(p, 0x20), calldatasize()) { revert(0, 0) }` - or, "
        "better, use high-level Solidity `abi.decode(msg.data[p:p+32], "
        "(uint256))` which bounds-checks automatically."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if any(k in contract.name.lower() for k in SKIP_KEYWORDS):
                continue
            if is_vendored_or_test_contract(contract):
                continue

            for function in contract.functions_and_modifiers_declared:
                for node in function.nodes:
                    if node.type != NodeType.ASSEMBLY:
                        continue
                    if node.source_mapping is None:
                        continue
                    src = node.source_mapping.content
                    if not src:
                        continue
                    if "calldataload" not in src:
                        continue
                    if "calldatasize" in src:
                        continue
                    info: DETECTOR_INFO = [
                        function,
                        " contains inline assembly that calls "
                        "`calldataload` without a `calldatasize` bounds "
                        "check at ",
                        node,
                        " - past-end reads decode as zero, enabling "
                        "attacker-truncated calldata bypasses.\n",
                    ]
                    results.append(self.generate_result(info))
                    break

        return results
