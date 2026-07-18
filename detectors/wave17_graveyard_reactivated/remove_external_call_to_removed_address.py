"""
remove_external_call_to_removed_address.py - Custom Slither detector.

Pattern (Zellic slice_ag Polyhedra DVN, MEDIUM): a remove*/disable*/revoke*
admin function calls a method on the very address being removed BEFORE it
marks the target as removed in state. Because the external call happens on
attacker-controlled code, the malicious target can revert in the callback and
block its own removal - admin is permanently unable to clean the registry.

Detection strategy:
    1. Walk functions whose name contains remove/disable/revoke/uninstall
       and which take an `address` parameter.
    2. In the function body, find a HighLevelCall whose destination resolves
       (through TypeConversion IRs) back to that address parameter.
    3. Find the FIRST node after the function entry that writes a mapping
       state variable using the same address parameter as the key (the
       registry "cleanup" write).
    4. If the HighLevelCall node index < cleanup write node index → flag.

Slither represents `IModule(m).shutdown()` as a TypeConversion (m → TMP_0)
followed by a HighLevelCall whose destination is TMP_0. We track the
TMP_{n} → m mapping inside a function to resolve the original parameter.

@author auditooor wave8
@pattern slice_ag Polyhedra DVN
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
from slither.slithir.operations import HighLevelCall, TypeConversion
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_NAME_RE = re.compile(r"(?i)(remove|disable|revoke|uninstall)")


def _address_params(function):
    out = []
    for p in function.parameters:
        if str(getattr(p, "type", "") or "") == "address":
            out.append(p)
    return out


class RemoveExternalCallToRemovedAddress(AbstractDetector):
    """Detect remove/disable functions that call the target address before marking it removed."""

    ARGUMENT = "remove-external-call-to-removed-address"
    HELP = (
        "remove/disable/revoke function calls a method on the target address "
        "BEFORE writing the state that marks it removed - target can block cleanup"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Remove Function Calls Target Before State Cleanup"
    WIKI_DESCRIPTION = (
        "A `remove*`/`disable*`/`revoke*`/`uninstall*` admin function that makes "
        "an external call on the address being removed before it writes the "
        "registry-cleanup state lets a malicious target revert inside the call "
        "and permanently block its own removal. Admin loses the ability to "
        "clean up the contract. This is the Polyhedra DVN class - mark removed "
        "first, then call the target best-effort."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
mapping(address => bool) public modules;
function removeModule(address m) external onlyOwner {
    IModule(m).shutdown();           // BUG: malicious m reverts here
    modules[m] = false;              // never reached
}
```
Attacker registers a module whose `shutdown()` always reverts. Admin can
never remove it - the registry is permanently polluted."""
    WIKI_RECOMMENDATION = (
        "Write the removal state first, then make the external call inside a "
        "`try/catch` so a malicious target cannot block its own removal."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            for function in contract.functions_and_modifiers_declared:
                if function.is_constructor:
                    continue
                name = function.name or ""
                if not _NAME_RE.search(name):
                    continue
                addr_params = _address_params(function)
                if not addr_params:
                    continue

                # Build tmp -> origin-variable map by walking IR in order.
                # For each TypeConversion, remember its lvalue as aliasing
                # its `variable` source.
                for param in addr_params:
                    alias: dict[str, object] = {}
                    call_idx = None
                    call_node = None
                    write_idx = None
                    write_node = None

                    for idx, node in enumerate(function.nodes):
                        for ir in node.irs:
                            if isinstance(ir, TypeConversion):
                                src = getattr(ir, "variable", None)
                                lv = getattr(ir, "lvalue", None)
                                if src is not None and lv is not None:
                                    src_name = getattr(src, "name", None)
                                    lv_name = getattr(lv, "name", None)
                                    # Resolve chained conversions
                                    origin = src
                                    if src_name in alias:
                                        origin = alias[src_name]
                                    alias[lv_name] = origin
                            if isinstance(ir, HighLevelCall):
                                dest = getattr(ir, "destination", None)
                                if dest is None:
                                    continue
                                dest_name = getattr(dest, "name", None)
                                resolved = alias.get(dest_name, dest)
                                if resolved is param or dest is param:
                                    if call_idx is None:
                                        call_idx = idx
                                        call_node = node

                        # Cleanup write: a state var write where param is
                        # among the local variables read (mapping key).
                        if write_idx is None and node.state_variables_written:
                            if param in node.local_variables_read:
                                write_idx = idx
                                write_node = node

                    if call_idx is None or write_idx is None:
                        continue
                    if not (call_idx < write_idx):
                        continue

                    info: DETECTOR_INFO = [
                        function,
                        " calls the target address at ",
                        call_node,
                        " BEFORE writing the removal state at ",
                        write_node,
                        ". A malicious target can revert in the callback and "
                        "block its own removal. Mark removed first, then call.\n",
                    ]
                    results.append(self.generate_result(info))

        return results
