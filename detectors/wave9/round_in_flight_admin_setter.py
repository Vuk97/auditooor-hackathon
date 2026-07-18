"""
round_in_flight_admin_setter.py — Custom Slither detector.

Pattern (Megapot M-01/06/07/08, slice_ad round-in-flight admin setter):
An admin setter mutates a critical config (VRF provider, oracle address,
payout recipient, fee recipient) while a round / draw / request is
currently in-flight. The new value silently corrupts accounting of the
pending round (existing requests get the new VRF provider, existing fee
calculations switch recipient mid-flight, etc).

Detection strategy:
    1. Contract must declare BOTH:
       - a state variable whose name matches `(round|draw|request|epoch|period)`
       - a state variable whose name matches `(provider|oracle|vrf|payout|fee)`
    2. Walk every declared function whose name starts with `set` or `update`
       AND that writes to one of the provider-named state variables.
    3. Flag the function if its body does NOT read the round-named state
       variable inside any guard (require/if). That signals the setter
       has no in-flight check.

@author auditooor wave9
@pattern slice_ad Megapot M-01/06/07/08
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
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_ROUND_RE = re.compile(r"(round|draw|request|epoch|period)", re.IGNORECASE)
_PROVIDER_RE = re.compile(r"(provider|oracle|vrf|payout|fee)", re.IGNORECASE)


def _matches(name: str, regex) -> bool:
    return bool(regex.search(name or ""))


class RoundInFlightAdminSetter(AbstractDetector):
    """Flag admin setters that mutate critical config without checking
    that the contract is between rounds."""

    ARGUMENT = "round-in-flight-admin-setter"
    HELP = (
        "Admin setter mutates VRF/oracle/fee provider while a round/draw is "
        "in-flight — pending requests are corrupted"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Admin Setter Mutates Provider While Round Is In-Flight"
    WIKI_DESCRIPTION = (
        "When a contract operates in rounds / draws / epochs and exposes admin "
        "setters that point at external services (VRF coordinator, price "
        "oracle, payout recipient, fee recipient), mutating those addresses "
        "while a round is still in-flight strands or corrupts the pending "
        "round. The owner can — accidentally or maliciously — change the VRF "
        "callback target between request and fulfillment, swap the fee "
        "recipient mid-payout, or move the oracle source after a price has "
        "been observed but before settlement. Megapot's M-01/06/07/08 audit "
        "findings all stem from this missing in-flight guard."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
uint256 public currentRound = 1;
address public vrfProvider;

function setVrfProvider(address p) external onlyOwner {
    vrfProvider = p; // BUG: no `require(currentRound == 0)`
}
```
1. Round 5 is in-flight; randomness has been requested from the original VRF.
2. Owner calls `setVrfProvider(attackerVRF)` — pending request is now
   answered by attacker-controlled VRF.
3. Attacker biases the draw and walks away with the prize."""
    WIKI_RECOMMENDATION = (
        "Guard provider setters with an in-flight check, e.g. "
        "`require(currentRound == 0, \"round active\")` or "
        "`require(!roundActive, \"in-flight\")`."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            round_vars = [
                sv for sv in contract.state_variables if _matches(sv.name, _ROUND_RE)
            ]
            provider_vars = [
                sv for sv in contract.state_variables if _matches(sv.name, _PROVIDER_RE)
            ]
            if not round_vars or not provider_vars:
                continue
            provider_names = {sv.name for sv in provider_vars}
            round_names = {sv.name for sv in round_vars}

            for function in contract.functions_declared:
                fname = (function.name or "").lower()
                if not (fname.startswith("set") or fname.startswith("update")):
                    continue

                # Function must write to one of the provider-named state vars.
                writes = {sv.name for sv in function.state_variables_written}
                touched = writes & provider_names
                if not touched:
                    continue

                # Function must NOT read any round-named state variable inside
                # a require/if guard.
                guarded = False
                for node in function.nodes:
                    if not (node.contains_if() or node.contains_require_or_assert()):
                        continue
                    reads = {sv.name for sv in node.state_variables_read}
                    if reads & round_names:
                        guarded = True
                        break
                if guarded:
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " writes provider-like state (",
                    ", ".join(sorted(touched)),
                    ") without checking a round/draw guard. Pending rounds may "
                    "be corrupted — add require(currentRound == 0) or similar.\n",
                ]
                results.append(self.generate_result(info))

        return results
