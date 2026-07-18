"""
eip712_type_string_field_omission.py - Custom Slither detector.

Pattern: a contract declares an EIP-712 typehash constant as
`keccak256("StructName(field1 type,field2 type,...)")` but the struct
definition in the same contract contains MORE fields than the typehash
string names. Off-chain signers sign over all struct fields; on-chain
verification validates a subset - any two orders differing only in the
omitted field(s) produce the same digest, enabling replay.

Strategy:
    1. For each contract, collect all struct definitions → name → field-name list.
    2. For each state variable (constant bytes32) whose initializer is
       keccak256("..."), parse the string literal to extract (struct_name, [fields])
       via regex on the source.
    3. Match struct_name against contract structs.
    4. If any struct field is missing from the typehash's field list → flag.

IR inspection:
    The initializer `keccak256("Order(address maker,...)")` appears inside
    `slitherConstructorConstantVariables` function as a SolidityCall, but
    reading the Constant's raw string is cleaner via source-level regex on
    the state variable's source_mapping.content.

Dedup check: no Slither builtin for EIP-712 typehash field consistency.

@author auditooor
@pattern iter20 - EIP-712 field omission (1inch OIN9-10 analog)
"""

import re
import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.utils.output import Output


SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")

# Slither renders the source `keccak256("Struct(type field,...)")` as the
# unquoted string `keccak256(bytes)(Struct(type field,...))` in expression form.
# Match the outer keccak256(bytes)( ... ) wrapper and extract the Struct(...).
_TYPEHASH_RE = re.compile(
    r'keccak256\s*\(bytes\)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\(([^)]*)\)\s*\)',
    re.DOTALL,
)


def _parse_typehash_fields(expr: str):
    """
    Given a source expression containing a typehash keccak256 call,
    return (struct_name, [field_name, ...]) or None if unparseable.
    """
    m = _TYPEHASH_RE.search(expr)
    if not m:
        return None
    struct_name = m.group(1)
    fields_blob = m.group(2).strip()
    if not fields_blob:
        return struct_name, []
    # Split on commas. Each item is `type name`. Field name is the second token.
    fields = []
    for item in fields_blob.split(","):
        item = item.strip()
        parts = item.split()
        if len(parts) >= 2:
            fields.append(parts[-1])
    return struct_name, fields


class Eip712TypeStringFieldOmission(AbstractDetector):
    """Detect EIP-712 typehash strings that omit struct fields."""

    ARGUMENT = "eip712-type-string-omission"
    HELP = "EIP-712 TYPEHASH string omits a struct field - signature replay risk"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "EIP-712 typehash field omission"
    WIKI_DESCRIPTION = (
        "A contract's EIP-712 typehash constant is declared as "
        "`keccak256(\"Struct(type field,...)\")` but the struct definition "
        "contains fields not mentioned in the type string. The off-chain "
        "signer signs all fields; the on-chain verification uses only the "
        "listed subset. Two different orders that differ only in the omitted "
        "field(s) produce the same digest - signature replay."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
struct Order {
    address maker;
    address taker;
    uint256 amount;
    uint256 price;
    uint256 expiry;   // <-- not in typehash below
}

bytes32 constant ORDER_TYPEHASH =
    keccak256("Order(address maker,address taker,uint256 amount,uint256 price)");
```
A signed Order A with expiry=block.timestamp+1 is valid for 1 second. The
attacker submits the identical order with expiry=block.timestamp+1000000 -
same signature, same typehash digest, now valid for 12 days."""
    WIKI_RECOMMENDATION = (
        "Keep the TYPEHASH string EXACTLY in sync with the struct definition. "
        "Every struct field must appear in the type string. Prefer generating "
        "the typehash via a template/macro or a `view` helper that enumerates "
        "struct fields via AST tooling to prevent drift."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []
        for contract in self.contracts:
            if any(k in contract.name.lower() for k in SKIP_KEYWORDS):
                continue
            if is_vendored_or_test_contract(contract):
                continue

            # Build {struct_name: [field_name, ...]} from contract structs
            struct_map = {}
            for st in getattr(contract, "structures", []) or []:
                fields = [f.name for f in getattr(st, "elems_ordered", [])]
                struct_map[st.name] = fields

            if not struct_map:
                continue

            # Walk state variables; check expression for keccak256("Struct(...)")
            for sv in contract.state_variables_declared:
                expr = getattr(sv, "expression", None)
                if expr is None:
                    continue
                expr_str = str(expr)
                parsed = _parse_typehash_fields(expr_str)
                if parsed is None:
                    continue
                struct_name, hash_fields = parsed
                if struct_name not in struct_map:
                    continue
                actual_fields = struct_map[struct_name]
                missing = [f for f in actual_fields if f not in hash_fields]
                if not missing:
                    continue
                info: DETECTOR_INFO = [
                    "State variable ",
                    sv,
                    f" declares a typehash for struct {struct_name} but the "
                    f"type string omits field(s): {', '.join(missing)}. "
                    "Signers sign over all struct fields; the contract "
                    "validates only the listed ones - signature replay risk.",
                ]
                results.append(self.generate_result(info))
        return results
