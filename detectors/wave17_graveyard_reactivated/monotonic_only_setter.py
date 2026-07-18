"""
monotonic_only_setter.py - Custom Slither detector.

Pattern (Kleidi M-03, slice_ab): A governance setter for a time / period /
duration parameter uses a STRICT-greater comparison against its own live
state variable, e.g. `require(newPeriod > expirationPeriod)`. Once the
parameter is raised, governance can never lower it again - shrinking is
unreachable. Distinct from wave9 `governance-setter-revert-on-current-gt-cap`
(which matches `newCap >= liveAccounting` on a DIFFERENT variable - i.e. a
live total counter). Here the RHS is the SAME variable the setter writes,
so the bug is "monotonic-only ratchet", not "cap vs. live total".

Detection strategy:
    1. Find external/public setter functions whose name matches
       `(set|update)(period|duration|delay|cooldown|expiration|window|timeout)`.
    2. Setter must write exactly one state variable (the tracked value).
    3. Setter must contain `require(newParam > <sameStateVar>)` - i.e. a
       Binary of type GREATER (strict) where the left operand is a function
       parameter and the right operand is the very state variable being
       written.
    4. Skip if the same function also contains a `<` or `<=` compare on
       the same variable (an explicit upper bound - means monotonicity is
       intentional, not a bug).

@author auditooor wave11
@pattern slice_ab Kleidi M-03 updateExpirationPeriod cannot shrink
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
from slither.core.declarations import SolidityFunction
from slither.core.variables.local_variable import LocalVariable
from slither.core.variables.state_variable import StateVariable
from slither.slithir.operations import Binary, BinaryType, SolidityCall
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")
_SETTER_RE = re.compile(
    r"(set|update).*(period|duration|delay|cooldown|expiration|window|timeout)",
    re.IGNORECASE,
)
_REQUIRE_FNS = {
    SolidityFunction("require(bool,string)"),
    SolidityFunction("require(bool)"),
    SolidityFunction("require(bool,error)"),
}


class MonotonicOnlySetter(AbstractDetector):
    """Period/duration setter that blocks shrinking via strict >."""

    ARGUMENT = "monotonic-only-setter"
    HELP = (
        "setPeriod/updateExpiration uses `require(new > current)` against "
        "its own state var - parameter can be ratcheted up but never reduced"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Monotonic-Only Setter Blocks Shrinking"
    WIKI_DESCRIPTION = (
        "A governance setter for an expiration / cooldown / delay parameter "
        "uses `require(newValue > currentValue)` where `currentValue` is the "
        "very state variable being written. The check allows governance to "
        "raise the parameter but silently forbids lowering it - a one-way "
        "ratchet. If the parameter is accidentally set too high, it can "
        "never be reduced. Reported in Kleidi M-03 `updateExpirationPeriod`."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
uint256 public expirationPeriod;
function updateExpirationPeriod(uint256 newPeriod) external onlyOwner {
    require(newPeriod > expirationPeriod, "must increase"); // BUG
    expirationPeriod = newPeriod;
}
```
1. Admin sets `expirationPeriod = 365 days` by mistake.
2. Every future call reverts because `newPeriod > 365 days` fails.
3. Protocol is permanently locked into the excessive period; governance
   has no remediation path short of upgrading / redeploying."""
    WIKI_RECOMMENDATION = (
        "Replace the self-referential strict-greater check with absolute "
        "lower/upper bounds (e.g. `require(newPeriod >= MIN && newPeriod "
        "<= MAX)`). Never compare a setter's input against the same state "
        "variable it is about to overwrite."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            for setter in contract.functions_and_modifiers_declared:
                if setter.is_constructor:
                    continue
                if setter.visibility not in ("public", "external"):
                    continue
                if not setter.name or not _SETTER_RE.search(setter.name):
                    continue

                params = list(setter.parameters or [])
                if not params:
                    continue
                param_set = set(params)

                writes = [
                    v for v in (setter.state_variables_written or [])
                    if isinstance(v, StateVariable)
                    and not getattr(v, "is_constant", False)
                    and not getattr(v, "is_immutable", False)
                ]
                if len(writes) != 1:
                    continue
                tracked = writes[0]

                # Look for require(param > tracked)
                bad_node = None
                for node in setter.nodes:
                    if not node.contains_require_or_assert():
                        continue
                    require_found = any(
                        isinstance(ir, SolidityCall) and ir.function in _REQUIRE_FNS
                        for ir in node.irs
                    )
                    if not require_found:
                        continue
                    for ir in node.irs:
                        if not (isinstance(ir, Binary) and ir.type == BinaryType.GREATER):
                            continue
                        left = ir.variable_left
                        right = ir.variable_right
                        if not (isinstance(left, LocalVariable) and left in param_set):
                            continue
                        if right is not tracked:
                            continue
                        bad_node = node
                        break
                    if bad_node:
                        break
                if bad_node is None:
                    continue

                # Skip if the setter ALSO contains an upper bound
                # (< or <=) on the same tracked var - means the author
                # intentionally ratchets within a band.
                has_upper_bound = False
                for node in setter.nodes:
                    for ir in node.irs:
                        if not isinstance(ir, Binary):
                            continue
                        if ir.type not in (BinaryType.LESS, BinaryType.LESS_EQUAL):
                            continue
                        l2, r2 = ir.variable_left, ir.variable_right
                        if tracked in (l2, r2):
                            has_upper_bound = True
                            break
                    if has_upper_bound:
                        break
                if has_upper_bound:
                    continue

                info: DETECTOR_INFO = [
                    setter,
                    " uses `require(new > ",
                    tracked.name or "?",
                    ")` on its own tracked variable at ",
                    bad_node,
                    " - the parameter can be ratcheted up but never "
                    "reduced, creating a one-way monotonic setter.\n",
                ]
                results.append(self.generate_result(info))

        return results
