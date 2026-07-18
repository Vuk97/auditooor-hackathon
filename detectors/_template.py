"""
_template.py — canonical skeleton for auditooor custom Slither detectors.

Copy to wave<N>/<short_name>.py and edit. Follow the patterns below EXACTLY —
they are lifted from Slither's own builtin detectors (tx_origin, encode_packed,
divide_before_multiply, unchecked_transfer) and verified to work.

═══════════════════════════════════════════════════════════════════════════
CANONICAL PATTERNS FROM SLITHER BUILTINS
═══════════════════════════════════════════════════════════════════════════

DO NOT reinvent. These idioms come directly from slither/detectors/ source:

1. Iterate contracts:
     for c in self.contracts:                   # NOT contracts_derived
         for f in c.functions_and_modifiers_declared:  # skip inherited

2. Match a solidity builtin call by signature (not string prefix):
     from slither.core.declarations import SolidityFunction
     for ir in f.solidity_calls:                # pre-built, no walk needed
         if ir.function == SolidityFunction("ecrecover(bytes32,uint8,bytes32,bytes32)"):
             ...

3. Match a high-level (external contract) call by canonical signature:
     from slither.slithir.operations import HighLevelCall
     from slither.core.declarations import Function
     for n in f.nodes:
         for ir in n.irs:
             if isinstance(ir, HighLevelCall) and isinstance(ir.function, Function):
                 if ir.function.solidity_signature == "transfer(address,uint256)":
                     ...

4. Inspect node properties (prefer over walking IR):
     node.contains_if()                          # has if/ternary
     node.contains_require_or_assert()           # has require/assert
     node.solidity_variables_read                # tx.origin, msg.sender, etc
     node.state_variables_read / _written        # state var accesses
     node.local_variables_read / _written        # local var accesses
     node.internal_calls                         # list of InternalCall IRs

5. Binary operators: use BinaryType enum, not string compare:
     from slither.slithir.operations import Binary, BinaryType
     if isinstance(ir, Binary) and ir.type == BinaryType.DIVISION: ...
     # Enum values: ADDITION, SUBTRACTION, MULTIPLICATION, DIVISION,
     # MODULO, POWER, LESS, GREATER, LESS_EQUAL, GREATER_EQUAL, EQUAL,
     # NOT_EQUAL, ANDAND, OROR, AND, OR, XOR, SHIFT_LEFT, SHIFT_RIGHT

6. Taint / data-flow: use Slither's helper, not custom walking:
     from slither.analyses.data_dependency.data_dependency import is_tainted
     if is_tainted(variable, contract): ...

7. generate_result info list — ONLY put source-mapped objects:
     info = [function, " calls ", node, " — description"]
     # OK: Function, Contract, Node (real ones, not ENTRYPOINT), Variable
     # NOT OK: TemporaryVariable, SolidityFunction, raw strings as first item
     results.append(self.generate_result(info))

8. Get the node back-reference from any IR:
     ir.node        # every IR has a .node property — put in info directly

═══════════════════════════════════════════════════════════════════════════
DETECTOR AUTHORING CHECKLIST
═══════════════════════════════════════════════════════════════════════════

FIXTURES FIRST:
  1. Write test_fixtures/<short_name>_vulnerable.sol (minimal, 1 bug)
  2. Write test_fixtures/<short_name>_clean.sol (fixed, no bug) if applicable
  3. Run: slither <fixture.sol> --print human-summary
  4. Run: python3 -c "from slither import Slither; s=Slither('<fixture>'); ..."
     to inspect actual IR produced — don't guess.

WRITE THE DETECTOR:
  5. Copy this template to wave<N>/<short_name>.py
  6. Fill ARGUMENT, HELP, IMPACT, CONFIDENCE, WIKI_*
  7. Implement _detect() — model on the closest existing slither/detectors/ file
  8. NEVER use string-prefix matching for solidity function names.
     ALWAYS compare to SolidityFunction("name(sig)") or use .solidity_signature.

REGRESSION:
  9. Add run_test + run_clean_test lines to test_fixtures/run_tests.sh
 10. Run: make test
 11. MUST PASS before committing. 0 hits on vulnerable = detector is broken.
 12. Add a row to detectors/_taxonomy.md.

═══════════════════════════════════════════════════════════════════════════
DEDUP BEFORE YOU WRITE
═══════════════════════════════════════════════════════════════════════════

Before writing any new detector, run:
    slither --list-detectors | grep -i <keyword>

If a builtin exists (e.g. tx-origin, unchecked-transfer, divide-before-multiply,
encode-packed-collision, suicidal, controlled-delegatecall, missing-zero-check,
timestamp, reentrancy-*), DO NOT write a duplicate. Use the builtin instead.

Write custom detectors ONLY for patterns NOT covered by the 100+ builtins.
Our target domain: EIP-712 order systems, operator-gated settlement,
deploy-state role grants, fee caps, CTF/ERC1155-specific patterns.
"""

from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
# Common imports — uncomment as needed:
# from slither.core.declarations import Contract, Function, SolidityFunction
# from slither.core.cfg.node import Node
# from slither.core.variables import Variable
# from slither.core.variables.state_variable import StateVariable
# from slither.slithir.operations import (
#     HighLevelCall, LowLevelCall, SolidityCall, InternalCall,
#     Binary, BinaryType, Assignment, TypeConversion, LibraryCall,
# )
# from slither.slithir.variables import Constant, TemporaryVariable
# from slither.analyses.data_dependency.data_dependency import is_tainted
from slither.utils.output import Output


class TemplateDetector(AbstractDetector):
    """<One-line description of the pattern you're detecting.>"""

    ARGUMENT = "template-detector"  # CHANGE: kebab-case unique identifier
    HELP = "<One-line description shown in slither --list-detectors>"
    IMPACT = DetectorClassification.MEDIUM    # LOW / MEDIUM / HIGH / INFORMATIONAL
    CONFIDENCE = DetectorClassification.MEDIUM  # LOW / MEDIUM / HIGH

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "<Title>"
    WIKI_DESCRIPTION = (
        "<Why this pattern is a vulnerability. 2-4 sentences. Reference the "
        "source query or bug pattern if there's a direct ancestor.>"
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
// Minimal Solidity snippet showing the vulnerable pattern.
// Match the style of Slither builtins — short, self-contained,
// one bug per example.
```
<Step-by-step exploitation: attacker does X, triggers Y, drains Z.>"""
    WIKI_RECOMMENDATION = (
        "<How to fix. One actionable sentence. Reference a canonical library "
        "(OpenZeppelin SafeERC20, Solady, etc) if relevant.>"
    )

    def _detect(self) -> list[Output]:
        """
        Canonical structure — mirror tx_origin.py / encode_packed.py:
        1. Iterate self.contracts (NOT contracts_derived)
        2. Iterate contract.functions_and_modifiers_declared (skip inherited)
        3. For each function, use pre-built IR lists (solidity_calls,
           high_level_calls) OR walk nodes selectively
        4. Use node-level helpers (contains_if, solidity_variables_read) first
        5. Fall back to IR inspection for complex patterns
        6. generate_result with source-mapped objects in info list
        """
        results: list[Output] = []

        for contract in self.contracts:
            for function in contract.functions_and_modifiers_declared:
                # <YOUR DETECTION LOGIC HERE — model on a Slither builtin>
                #
                # Example (tx-origin style):
                # for node in function.nodes:
                #     if not (node.contains_if() or node.contains_require_or_assert()):
                #         continue
                #     solidity_vars = node.solidity_variables_read
                #     if any(v.name == "tx.origin" for v in solidity_vars):
                #         info: DETECTOR_INFO = [
                #             function, " uses tx.origin: ", node, "\n",
                #         ]
                #         results.append(self.generate_result(info))

                pass  # REMOVE when you fill in the body

        return results
