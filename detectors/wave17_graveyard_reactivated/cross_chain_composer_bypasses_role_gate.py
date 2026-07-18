"""
cross_chain_composer_bypasses_role_gate.py - Custom Slither detector.

Pattern (Brix Money M-01, slice_ad): A contract enforces a role / allowlist
gate on its on-chain staking entry function (e.g. `stake()` with
`onlyRole(SOFT_RESTRICTED_STAKER)` or `require(!restricted[msg.sender])`).
However the LayerZero compose / OApp receive callback (`lzCompose`,
`_lzReceive`, `onOFTReceived`) performs the same state mutation WITHOUT
re-applying the gate - restricted users can stake from another chain.

Detection strategy:
    1. Identify contracts that declare BOTH:
       a) A gated function: one that reads a state variable whose name
          matches `(restricted|blacklist|whitelist|banned|allowed|kyc|role)`
          inside a require/assert, AND writes at least one "stake-like"
          state variable (mapping or scalar) whose name matches
          `(staked|balance|deposit|position)`.
       b) A cross-chain callback whose name matches `lzCompose|lzReceive|
          _lzReceive|onOFTReceived|receiveMessage|composeReceive`.
    2. The callback must WRITE one of the same stake-like state variables
       touched by the gated function.
    3. The callback must NOT read any of the gate state variables.
    4. Flag the callback.

@author auditooor wave11
@pattern slice_ad Brix M-01
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

_CALLBACK_NAMES = (
    "lzcompose", "lzreceive", "_lzreceive",
    "onoftreceived", "oftreceived",
    "receivemessage", "composereceive", "onreceive",
)
_STAKE_STATE_RE = re.compile(
    r"(staked|stakedbalance|deposit|position|balance|locked|shares)",
    re.IGNORECASE,
)
_GATE_STATE_RE = re.compile(
    r"(restricted|blacklist|blocklist|whitelist|banned|allowed|kyc|role|frozen)",
    re.IGNORECASE,
)


def _function_gates_on(function, gate_names):
    """Return True if any require/assert node in `function` reads any of
    the gate state variable names."""
    for node in function.nodes:
        if not node.contains_require_or_assert():
            continue
        if any(sv.name in gate_names for sv in node.state_variables_read):
            return True
    # Also check modifier bodies.
    for mod in function.modifiers:
        for node in mod.nodes:
            if not node.contains_require_or_assert():
                continue
            if any(sv.name in gate_names for sv in node.state_variables_read):
                return True
    return False


class CrossChainComposerBypassesRoleGate(AbstractDetector):
    """Flag LayerZero compose callbacks that bypass a role/allowlist gate."""

    ARGUMENT = "cross-chain-composer-bypasses-role-gate"
    HELP = (
        "LayerZero compose / OApp receive callback mutates stake state "
        "without re-applying the role/allowlist gate enforced on the "
        "on-chain stake() entry - restricted users bypass the gate cross-chain"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Cross-Chain Composer Bypasses Role Gate"
    WIKI_DESCRIPTION = (
        "The on-chain entry point (e.g. `stake`) enforces a role / allowlist "
        "gate via `require(!restricted[user])` or `onlyRole(...)`, but the "
        "LayerZero compose / OApp receive callback performs the same state "
        "mutation WITHOUT re-applying the gate. A restricted user can relay "
        "the action through the cross-chain path and bypass the policy. "
        "Source: Brix Money M-01 (slice_ad)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
mapping(address => bool) public restricted;
mapping(address => uint256) public stakedBalance;

function stake(uint256 amount) external {
    require(!restricted[msg.sender], "restricted");
    stakedBalance[msg.sender] += amount;
}

function lzCompose(address, bytes32, bytes calldata msg_, address, bytes calldata)
    external payable
{
    (address user, uint256 amount) = abi.decode(msg_, (address, uint256));
    stakedBalance[user] += amount;   // BUG: restricted check skipped
}
```
1. Restricted user calls `stake` on another chain → LZ compose delivers
   message to this contract.
2. `lzCompose` decodes user and credits stake without the restriction check.
3. Policy bypassed - restricted user is now staked."""
    WIKI_RECOMMENDATION = (
        "Re-apply the same role / allowlist check inside every "
        "cross-chain callback (lzCompose / _lzReceive / onOFTReceived) "
        "before mutating stake state. Extract the gate into an internal "
        "helper used by both the on-chain and cross-chain paths."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            # Gate state vars
            gate_svs = [
                sv for sv in contract.state_variables
                if _GATE_STATE_RE.search(sv.name or "")
            ]
            stake_svs = [
                sv for sv in contract.state_variables
                if _STAKE_STATE_RE.search(sv.name or "")
            ]
            if not gate_svs or not stake_svs:
                continue
            gate_names = {sv.name for sv in gate_svs}
            stake_names = {sv.name for sv in stake_svs}

            # Find gated entry function(s): writes a stake var AND has a
            # require reading a gate var (directly or in a modifier).
            gated_stake_writes = set()
            gated_entry = None
            for f in contract.functions_and_modifiers_declared:
                if f.is_constructor:
                    continue
                written = {sv.name for sv in f.state_variables_written}
                touched_stake = written & stake_names
                if not touched_stake:
                    continue
                if _function_gates_on(f, gate_names):
                    gated_stake_writes |= touched_stake
                    gated_entry = gated_entry or f
            if not gated_stake_writes:
                continue

            # Find cross-chain callbacks.
            for f in contract.functions_and_modifiers_declared:
                if f.is_constructor:
                    continue
                if (f.name or "").lower() not in _CALLBACK_NAMES:
                    continue
                written = {sv.name for sv in f.state_variables_written}
                if not (written & gated_stake_writes):
                    continue
                # Must NOT already apply the gate (directly or via modifier).
                if _function_gates_on(f, gate_names):
                    continue

                info: DETECTOR_INFO = [
                    f,
                    " writes stake state (",
                    ", ".join(sorted(written & gated_stake_writes)),
                    ") without the gate check enforced by ",
                    gated_entry,
                    ". Cross-chain path bypasses the allowlist - re-apply "
                    "the check.\n",
                ]
                results.append(self.generate_result(info))

        return results
