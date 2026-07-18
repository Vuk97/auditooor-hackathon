"""
occupancy_check_missing_on_rent.py - Custom Slither detector.

Pattern (Munchables H-01 plot-multi-renter - slice_aa body finding):
    A rent / reserve / claim function writes an "occupant" field (owner,
    renter, tenant, user, claimer) into a per-slot storage mapping without
    first checking that the slot is currently empty. Two callers can rent
    the same slot back-to-back, silently overwriting the previous occupant
    and stealing whatever value the first rental represented.

Detection strategy:
    1. Walk non-vendored contracts.
    2. For each declared public/external non-view function whose name
       matches a rent/claim/reserve allow-list, check whether it writes a
       state variable - mapping(... => struct{}) OR mapping(... => address)
       - whose NAME hints at occupancy (plots, slots, rentals, tenants,
       occupancy, bookings, reservations, claims).
    3. For such functions, verify there is at least one require/assert node
       that READS the same state variable (proxy for the check
       `require(plot.renter == address(0))` or `require(!occupied[id])`).
    4. If no such guard → flag.

Confidence: MEDIUM. We only inspect functions with explicit rent/claim
names, and we only flag when a guard is missing on the specific mapping
being written.

@author auditooor wave11
@pattern slice_aa body finding / Munchables H-01 plot-multi-renter
"""

import re as _re
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.core.solidity_types.mapping_type import MappingType
from slither.core.variables.state_variable import StateVariable
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_RENT_FUNC_RE = _re.compile(
    r"^(rent|reserve|claim|book|lease|occupy|stake\w*plot|farm\w*plot|assignplot)",
    _re.IGNORECASE,
)

_OCCUPANCY_NAME_HINTS = (
    "plot", "slot", "rental", "tenant", "occupan", "booking",
    "reservation", "claim", "landlord", "renter", "stall",
)


def _is_occupancy_mapping(sv) -> bool:
    if not isinstance(sv, StateVariable):
        return False
    t = sv.type
    if not isinstance(t, MappingType):
        return False
    nm = (sv.name or "").lower()
    return any(h in nm for h in _OCCUPANCY_NAME_HINTS)


class OccupancyCheckMissingOnRent(AbstractDetector):
    """Detect rent/reserve/claim functions that don't check prior occupancy."""

    ARGUMENT = "occupancy-check-missing-on-rent"
    HELP = (
        "Rent/reserve/claim function writes an occupancy-style mapping "
        "without first requiring the slot is empty - second renter overwrites first"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Missing Occupancy Check on Rent/Claim"
    WIKI_DESCRIPTION = (
        "A rent-style function writes into a per-slot storage mapping "
        "(plots, rentals, bookings, reservations) without first verifying "
        "the slot is empty. Two callers can rent the same slot back-to-back; "
        "the second write silently overwrites the first occupant, wiping "
        "whatever value they had committed. Reported in Munchables "
        "(H-01 plot-multi-renter)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
struct Plot { address renter; uint256 rentEnds; }
mapping(uint256 => Plot) public plots;

function rentPlot(uint256 id, uint256 duration) external payable {
    // BUG: no `require(plots[id].renter == address(0))`.
    plots[id] = Plot({renter: msg.sender, rentEnds: block.timestamp + duration});
}
```
1. Alice rents plot #7 for 30 days and pays the fee.
2. Bob calls `rentPlot(7, 1)`; `plots[7].renter` is now Bob, Alice is
   silently evicted and the funds she locked are lost."""
    WIKI_RECOMMENDATION = (
        "Require the slot is empty (or expired) before writing: "
        "`require(plots[id].renter == address(0) || plots[id].rentEnds < block.timestamp);`. "
        "Alternatively, emit a refund to the previous occupant inside the same transaction."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            occ_maps = [
                sv for sv in contract.state_variables
                if _is_occupancy_mapping(sv)
            ]
            if not occ_maps:
                continue

            for function in contract.functions_and_modifiers_declared:
                if function.is_constructor:
                    continue
                if function.view or function.pure:
                    continue
                if function.visibility not in ("public", "external"):
                    continue
                if not (function.name and _RENT_FUNC_RE.search(function.name)):
                    continue

                written = set(function.state_variables_written)
                for occ_sv in occ_maps:
                    if occ_sv not in written:
                        continue

                    has_guard = False
                    for node in function.nodes:
                        if not node.contains_require_or_assert():
                            continue
                        if occ_sv in node.state_variables_read:
                            has_guard = True
                            break
                    if has_guard:
                        continue

                    info: DETECTOR_INFO = [
                        function,
                        " writes occupancy mapping ",
                        occ_sv,
                        " without first requiring the slot is empty - a "
                        "second caller can silently overwrite the first occupant.\n",
                    ]
                    results.append(self.generate_result(info))
                    break  # one finding per function

        return results
