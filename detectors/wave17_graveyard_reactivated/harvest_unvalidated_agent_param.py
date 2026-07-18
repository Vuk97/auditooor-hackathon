"""
harvest_unvalidated_agent_param.py - Custom Slither detector.

Pattern: A `harvest` / `collect` / `claim` function takes an arbitrary `address`
parameter (typically named agent / strategy / operator) and passes it to a
token transfer as the recipient, WITHOUT first validating it against a
registry such as `AgentFactory.isAgent(agent)` / `registry.isValid(strategy)`.

Source: Zellic slice_aa glif-12 (CRITICAL).

Detection strategy:
    1. Functions named harvest / collect / claim* that take an `address`
       parameter.
    2. Function makes a HighLevelCall to `transfer(address,uint256)` or
       `transferFrom(address,address,uint256)` whose recipient argument is
       one of the function's address parameters.
    3. Function has no prior HighLevelCall whose callee name contains
       isAgent / isValid / isStrategy / isRegistered / whitelisted
       (the validation oracle).
    4. Also accept a preceding `require` that includes any such validation
       call - captured in step 3 because require() still compiles to a
       HighLevelCall on the registry.

Confidence: MEDIUM. We match on function-name + param-type + missing
validation call - the name regex keeps noise down; the address-param
recipient check prevents flagging fixed-recipient withdraws.
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
from slither.core.declarations import Function
from slither.slithir.operations import HighLevelCall
from slither.utils.output import Output


SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")

_HARVEST_FN_RE = re.compile(r'(harvest|collect|claim)', re.IGNORECASE)

_VALIDATION_RE = re.compile(
    r'(isagent|isvalid|isstrategy|isregistered|whitelisted|isapproved)',
    re.IGNORECASE,
)

_TRANSFER_SIGS = frozenset({
    "transfer(address,uint256)",
    "transferFrom(address,address,uint256)",
})


def _address_params(function) -> set:
    """Return set of parameter names (str) that have address type."""
    names = set()
    for p in function.parameters:
        t = str(p.type)
        if "address" in t and "[]" not in t:
            if p.name:
                names.add(p.name)
    return names


def _get_validation_call_nodes(function) -> list:
    """Return a list of node indices where a HighLevelCall to a validation-named fn occurs."""
    indices = []
    for i, node in enumerate(function.nodes):
        for ir in node.irs:
            if not isinstance(ir, HighLevelCall):
                continue
            callee = getattr(ir, "function", None)
            if callee is None:
                continue
            nm = getattr(callee, "name", "") or ""
            if _VALIDATION_RE.search(nm):
                indices.append(i)
                break
    return indices


def _find_unvalidated_transfer(function, addr_params: set):
    """
    Walk function nodes in order. For each HighLevelCall that is a transfer /
    transferFrom whose recipient argument name is one of `addr_params`, check
    if any prior node in the function contains a validation HighLevelCall.

    Return the (node, ir) of the first unvalidated offending transfer, or None.
    """
    validation_indices = set(_get_validation_call_nodes(function))
    for i, node in enumerate(function.nodes):
        for ir in node.irs:
            if not isinstance(ir, HighLevelCall):
                continue
            callee = getattr(ir, "function", None)
            if not isinstance(callee, Function):
                continue
            sig = getattr(callee, "solidity_signature", None)
            if sig not in _TRANSFER_SIGS:
                continue
            args = getattr(ir, "arguments", []) or []
            # For transfer(address,uint256): recipient is arg 0
            # For transferFrom(address,address,uint256): recipient is arg 1
            if sig == "transfer(address,uint256)":
                recip = args[0] if len(args) >= 1 else None
            else:
                recip = args[1] if len(args) >= 2 else None
            recip_name = getattr(recip, "name", None)
            if recip_name not in addr_params:
                continue
            # Any prior validation call?
            prior_validation = any(vi < i for vi in validation_indices)
            if prior_validation:
                continue
            return node, ir
    return None


class HarvestUnvalidatedAgentParam(AbstractDetector):
    """Detect harvest/claim functions that pay out to an unvalidated address parameter."""

    ARGUMENT = "harvest-unvalidated-agent-param"
    HELP = (
        "harvest/claim/collect transfers rewards to an address parameter "
        "without validating it against an agent/strategy registry"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Harvest Pays Unvalidated Agent Parameter"
    WIKI_DESCRIPTION = (
        "A reward harvest / claim function accepts an arbitrary `agent` or "
        "`strategy` address parameter and uses it as the recipient of a token "
        "transfer without first checking it against an `AgentFactory.isAgent()` "
        "or similar registry. An attacker calls the function with their own "
        "address and receives rewards that belong to a legitimately registered "
        "agent. Source: Zellic GLIF-12 (CRITICAL)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function harvest(address agent) external {
    uint256 rewards = getRewards(agent);
    // BUG: no factory.isAgent(agent) check
    reward.transfer(agent, rewards);
}
```
1. Legitimate agent accumulates 1000 tokens of rewards in the pool.
2. Attacker calls `harvest(attacker)` - contract fetches rewards
   attributed to that address (or to the pool) and transfers them out.
3. Because `agent` is never validated, the attacker walks away with funds
   meant for the registered strategy."""
    WIKI_RECOMMENDATION = (
        "Require `factory.isAgent(agent)` (or the equivalent registry check) "
        "at the top of the function before computing or transferring rewards."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in SKIP_KEYWORDS):
                continue

            for function in contract.functions_and_modifiers_declared:
                if function.is_constructor:
                    continue
                if function.visibility not in ("public", "external"):
                    continue
                if not _HARVEST_FN_RE.search(function.name or ""):
                    continue
                addr_params = _address_params(function)
                if not addr_params:
                    continue

                hit = _find_unvalidated_transfer(function, addr_params)
                if hit is None:
                    continue
                node, _ir = hit

                info: DETECTOR_INFO = [
                    function,
                    " transfers rewards to an unvalidated address parameter at ",
                    node,
                    ". Add a registry check (e.g. require(factory.isAgent(agent))) "
                    "before computing or sending rewards.\n",
                ]
                results.append(self.generate_result(info))

        return results
