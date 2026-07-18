"""
interface_auto_gen_getter_array_mismatch.py — Custom Slither detector.

Pattern (Hybra M-07 / slice_ad):
    A contract declares `mapping(K => V[]) public X;` where V is a struct
    or other complex type. Solidity auto-generates a getter that requires
    TWO indices (`X(key, arrayIndex)`), but external integrators commonly
    declare an interface with a SINGLE-argument getter (`function X(K) ->
    V`). The ABI silently mismatches and integrations break — or worse,
    decode garbage when consumed via low-level calls.

Detection strategy (intentionally simple, false-positive-prone — flagged
as a code smell):
    1. For each non-vendored, non-test contract.
    2. For each public state variable whose type is
       `mapping(... => T[])` (where T is any type — value type is an
       ArrayType wrapping anything), flag it.

@author auditooor wave9
@pattern Hybra M-07 / slice_ad
"""

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.core.solidity_types import MappingType, ArrayType
from slither.core.variables.state_variable import StateVariable
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")


def _is_public_mapping_to_array(sv: StateVariable) -> bool:
    if getattr(sv, "visibility", None) != "public":
        return False
    t = getattr(sv, "type", None)
    seen = 0
    while isinstance(t, MappingType) and seen < 4:
        t = t.type_to
        seen += 1
        if isinstance(t, ArrayType):
            return True
    return False


class InterfaceAutoGenGetterArrayMismatch(AbstractDetector):
    """Public mapping(K => V[]) auto-getter requires 2 indices — interface mismatch foot-gun."""

    ARGUMENT = "interface-auto-gen-getter-array-mismatch"
    HELP = (
        "public mapping(K => V[]) auto-generates a 2-argument getter — "
        "external interfaces commonly mismatch the ABI"
    )
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Interface Auto-Gen Getter Array Mismatch"
    WIKI_DESCRIPTION = (
        "Solidity auto-generates a getter for a public state variable. "
        "For `mapping(K => V[]) public X`, the generated getter has the "
        "signature `X(K, uint256) returns (V)` — TWO indices, not one. "
        "External integrators routinely declare interfaces with a "
        "single-index getter (`function X(K) returns (V)`), causing a "
        "silent ABI mismatch. Reported in Hybra M-07."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
struct Pool { uint256 amount; }
mapping(uint256 => Pool[]) public pools;
// Auto-generated: pools(uint256, uint256) -> (uint256)

interface IHybra { function pools(uint256) external view returns (Pool); }
// Mismatch — every call to IHybra(h).pools(id) reverts or returns garbage.
```"""
    WIKI_RECOMMENDATION = (
        "Either expose an explicit getter that returns the full array "
        "(`function getPools(uint256) external view returns (Pool[] memory)`)"
        ", or restructure storage so each key maps to a single struct, not "
        "an array. Never rely on auto-generated getters for "
        "mapping-to-array layouts in cross-contract integrations."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            for sv in contract.state_variables_declared:
                if not isinstance(sv, StateVariable):
                    continue
                if not _is_public_mapping_to_array(sv):
                    continue

                info: DETECTOR_INFO = [
                    contract,
                    " declares public state variable ",
                    sv,
                    " of type mapping(... => T[]) — Solidity auto-generates "
                    "a 2-argument getter (key, arrayIndex). External "
                    "interfaces declaring a single-argument getter will "
                    "ABI-mismatch and break integrations.\n",
                ]
                results.append(self.generate_result(info))

        return results
