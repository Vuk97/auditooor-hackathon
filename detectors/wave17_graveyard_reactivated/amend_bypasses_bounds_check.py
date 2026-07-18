"""
amend_bypasses_bounds_check.py - Custom Slither detector.

Pattern (Zellic slice_ae GTE CLOB, MEDIUM): An order-book contract enforces
price/tick-spacing rules in `placeOrder`/`createPosition` via an internal
helper (e.g. `_assertLimitPriceInBounds`), but a sibling `amendOrder`/
`modifyPosition`/`updatePrice` function writes the same price field without
calling that helper. Users skirt the tick rules by placing a valid order and
immediately amending it to an out-of-bounds price.

Detection strategy:
    1. Find functions whose names start with `place|create|open|submit` ("creator")
       and sibling functions whose names start with `amend|modify|update|edit`
       ("amender") in the same contract.
    2. A creator "gates" a bounds check if it makes an InternalCall to a
       function whose name matches `(?i)(assert|check|validate).*(price|tick|
       bound|limit)` OR vice-versa.
    3. The creator and amender must both write to a struct field named
       matching `price|tick|limit` (via Member IR).
    4. If the creator calls the gate helper but the amender does not, flag
       the amender.

@author auditooor wave8
@pattern slice_ae GTE CLOB
"""

import re
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.slithir.operations import InternalCall, Member
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_CREATOR_PREFIXES = ("place", "create", "open", "submit", "post")
_AMENDER_PREFIXES = ("amend", "modify", "update", "edit", "change", "replace")

_GATE_RE = re.compile(
    r"(assert|check|validate|require|ensure).*"
    r"(price|tick|bound|limit|spacing)",
    re.IGNORECASE,
)
_PRICE_FIELD_RE = re.compile(r"price|tick|limit", re.IGNORECASE)


def _name_matches_prefix(name: str, prefixes) -> bool:
    lo = (name or "").lower()
    return any(lo.startswith(p) for p in prefixes)


def _has_price_param(function) -> bool:
    """True if the function takes a parameter whose name matches price/tick/limit."""
    for p in function.parameters or []:
        nm = (getattr(p, "name", "") or "")
        if _PRICE_FIELD_RE.search(nm):
            return True
    return False


def _writes_price_field_or_struct(function):
    """
    Return a set of state variables the function writes. We count either:
      - A direct `Member` IR with field name matching price/tick/limit
        (field-level write: `orders[id].price = ...`)
      - Any state-var write where the function takes a price-named parameter
        (struct assignment: `orders[id] = Order(price, size);`)
    """
    wrote_price_member = False
    state_writes = set()
    for node in function.nodes:
        for sv in node.state_variables_written:
            state_writes.add(sv)
        for ir in node.irs:
            if isinstance(ir, Member):
                field = getattr(ir.variable_right, "value", None)
                if isinstance(field, str) and _PRICE_FIELD_RE.search(field):
                    wrote_price_member = True

    if wrote_price_member:
        return state_writes
    if _has_price_param(function) and state_writes:
        return state_writes
    return set()


def _calls_gate(function) -> bool:
    """True if the function makes an InternalCall to a function/modifier
    whose name matches the gate regex."""
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, InternalCall):
                callee = ir.function
                nm = getattr(callee, "name", "") or ""
                if _GATE_RE.search(nm):
                    return True
        # Also check modifiers applied to the function:
    for mod in getattr(function, "modifiers", []) or []:
        nm = getattr(mod, "name", "") or ""
        if _GATE_RE.search(nm):
            return True
    return False


class AmendBypassesBoundsCheck(AbstractDetector):
    """Detect amend/modify functions that bypass create-time bounds checks."""

    ARGUMENT = "amend-bypasses-bounds-check"
    HELP = (
        "amend/modify function writes price/tick field without calling the "
        "same bounds/tick-spacing helper invoked by the create function"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Amend Function Skips Bounds Check Enforced By Create"
    WIKI_DESCRIPTION = (
        "Order-book, perps, and position contracts commonly validate a newly "
        "supplied price/tick in the create/place function via an internal "
        "helper. A sibling amend/modify function that writes the same price "
        "field must call the same helper - otherwise users can skirt tick "
        "spacing or price-band rules by placing a valid order and immediately "
        "amending it out of bounds."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function _assertLimitPriceInBounds(uint256 p) internal pure {
    require(p % TICK == 0, "tick");
}
function placeOrder(uint256 id, uint256 price) external {
    _assertLimitPriceInBounds(price);         // enforced
    orders[id].price = price;
}
function amendOrder(uint256 id, uint256 price) external {
    orders[id].price = price;                 // BUG: not enforced
}
```
A user places an in-bounds order then calls `amendOrder` with an off-tick
price to gain queue priority or hit a privileged price band."""
    WIKI_RECOMMENDATION = (
        "Add the same bounds/tick-spacing check to every function that writes "
        "the price field, or route all price writes through a single internal "
        "setter that always runs the validation."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            creators = []
            amenders = []
            for function in contract.functions_and_modifiers_declared:
                if function.is_constructor:
                    continue
                name = function.name or ""
                if _name_matches_prefix(name, _CREATOR_PREFIXES):
                    creators.append(function)
                elif _name_matches_prefix(name, _AMENDER_PREFIXES):
                    amenders.append(function)

            if not creators or not amenders:
                continue

            # Creator(s) that write a price field AND call the gate helper.
            gated_creator_writes: dict = {}  # creator -> set(state vars)
            for f in creators:
                writes = _writes_price_field_or_struct(f)
                if writes and _calls_gate(f):
                    gated_creator_writes[f] = writes
            if not gated_creator_writes:
                continue

            for amender in amenders:
                amender_writes = _writes_price_field_or_struct(amender)
                if not amender_writes:
                    continue
                if _calls_gate(amender):
                    continue
                # Amender must share at least one state var with some
                # gated creator (same order book / mapping).
                overlapping_creator = None
                for creator_fn, creator_writes in gated_creator_writes.items():
                    if creator_writes & amender_writes:
                        overlapping_creator = creator_fn
                        break
                if overlapping_creator is None:
                    continue

                info: DETECTOR_INFO = [
                    amender,
                    " writes a price/tick/limit field on ",
                    contract,
                    " without calling the bounds-check helper invoked by ",
                    overlapping_creator,
                    " - amend path bypasses tick/price validation enforced "
                    "during create.\n",
                ]
                results.append(self.generate_result(info))

        return results
