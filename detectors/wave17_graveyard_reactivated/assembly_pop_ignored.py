"""
assembly_pop_ignored.py - Custom Slither detector.

Pattern: inline assembly block containing pop(call(...)), pop(staticcall(...)),
or pop(delegatecall(...)). The `pop` opcode discards the success/failure return
value of an external call, making partial-commit failures silent.

Detection strategy:
    Walk function.nodes for NodeType.ASSEMBLY nodes.
    Inspect node.source_mapping.content (raw Yul source) with a regex for
    pop\\s*\\(\\s*(call|staticcall|delegatecall). Slither does not parse Yul
    deeply enough to inspect opcode-level IR; regex on the source string is the
    canonical approach (same as Slither's own `assembly` informational detector).

Modelled after:
    slither/detectors/statements/assembly.py  (NodeType.ASSEMBLY pattern)
    slither/detectors/statements/tx_origin.py (node iteration + generate_result)

Dedup check (slither --list-detectors | grep -i "pop\\|unchecked.low"):
    unchecked-lowlevel (#54) flags LowLevelCall IR without a success check -
    but does NOT cover assembly blocks (Slither doesn't emit LowLevelCall IR
    for Yul `call` opcodes, only for Solidity-level `.call{}`). NOVEL.
"""

import re
import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.core.cfg.node import NodeType
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.utils.output import Output

# Matches: pop(call(...)), pop(staticcall(...)), pop(delegatecall(...))
# Tolerates arbitrary whitespace between pop and the opening paren.
_POP_CALL_RE = re.compile(
    r"\bpop\s*\(\s*(call|staticcall|delegatecall)\b",
    re.IGNORECASE,
)

SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup")


class AssemblyPopIgnored(AbstractDetector):
    """
    Detect pop(call(...)) / pop(staticcall(...)) / pop(delegatecall(...)) in
    inline assembly blocks - success return value silently discarded.
    """

    ARGUMENT = "assembly-pop-ignored"
    HELP = "Assembly call return value discarded via pop() - success ignored"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Assembly pop(call(...)) Ignores Return Value"
    WIKI_DESCRIPTION = (
        "Inline assembly that uses pop(call(...)), pop(staticcall(...)), or "
        "pop(delegatecall(...)) discards the Boolean success/failure value "
        "returned by the opcode. If the external call fails (out-of-gas, "
        "revert, empty account), execution silently continues, creating a "
        "partial-commit vector where state updates proceed despite a failed "
        "external operation. This pattern is iter-20 C18 from the Polymarket "
        "audit taxonomy."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract Vault {
    function withdraw(address to, uint256 amt) external {
        assembly {
            // BUG: if call reverts, success = 0 is silently discarded
            pop(call(gas(), to, amt, 0, 0, 0, 0))
        }
        // state updates here still execute even if the ETH transfer failed
    }
}
```
An attacker supplies a `to` address that always reverts. The outer function
treats the call as successful, advancing internal accounting while funds are
not actually transferred - enabling double-spend on the next attempt."""
    WIKI_RECOMMENDATION = (
        "Replace pop(call(...)) with an explicit success check: "
        "`let ok := call(...) if iszero(ok) { revert(0, 0) }`. "
        "For high-level Solidity calls use `.call{...}()` with the return "
        "value checked or use OpenZeppelin's Address.sendValue / safeCall helpers."
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

                    match = _POP_CALL_RE.search(src)
                    if match:
                        call_type = match.group(1).lower()
                        info: DETECTOR_INFO = [
                            function,
                            f" contains assembly `pop({call_type}(...))` - "
                            "success return value is discarded: ",
                            node,
                            "\n",
                        ]
                        results.append(self.generate_result(info))

        return results
