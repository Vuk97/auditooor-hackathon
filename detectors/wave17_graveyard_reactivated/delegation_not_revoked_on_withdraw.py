"""
delegation_not_revoked_on_withdraw.py - Custom Slither detector.

Pattern (Virtuals Protocol slice_ac MED - Delegation-Not-Revoked-On-Withdraw):
A veToken / staking contract maintains a `delegates[user] => address` mapping
that gives voting weight to another address. The `stake()` path writes to
this mapping, but the paired `withdraw()` / `unstake()` / `exit()` path does
NOT reset the delegation. After withdrawal the user has zero stake but their
delegate continues to carry historical voting weight / rewards, letting a
malicious user inflate voting power.

Detection strategy:
    1. Find contracts that declare a state-var mapping whose name matches
       `delegates?` (i.e. `delegate` or `delegates`).
    2. Confirm at least one function writes to that mapping (usually
       `stake`/`delegate`/`_delegate`).
    3. Find functions whose name matches `withdraw|unstake|exit|redeem`
       declared locally on the same contract.
    4. If any such withdraw function does NOT write to the delegates mapping
       AND touches balance/stake state (writes a mapping whose name matches
       `balance|stake|locked`), flag it.

Distinction from existing detectors:
    - `one_wei_stake_delegate_hijack` (wave9): stake() path hijack.
    - `checkpoint_cleared_on_transfer_erc721` (wave9): clears checkpoints on
      ERC-721 transfer.
This fires on the withdraw side, a different class.

@author auditooor wave11
@pattern slice_ac Virtuals Protocol - Delegation-Not-Revoked-On-Withdraw
"""

import re
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.core.solidity_types import MappingType
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_DELEGATE_RE = re.compile(r"^_?delegates?$", re.IGNORECASE)
_BAL_RE = re.compile(r"balance|stake|locked|bond|deposit", re.IGNORECASE)
_WITHDRAW_RE = re.compile(
    r"^(withdraw|unstake|exit|unlock|unbond|redeem)",
    re.IGNORECASE,
)
_STAKE_RE = re.compile(r"^(stake|lock|deposit|delegate)", re.IGNORECASE)


def _delegate_vars(contract):
    out = []
    for sv in contract.state_variables:
        if not isinstance(sv.type, MappingType):
            continue
        nm = (sv.name or "")
        if _DELEGATE_RE.match(nm):
            out.append(sv)
    return out


def _balance_vars(contract):
    out = []
    for sv in contract.state_variables:
        if not isinstance(sv.type, MappingType):
            continue
        nm = (sv.name or "")
        if _BAL_RE.search(nm):
            out.append(sv)
    return out


def _writes_any(function, svs) -> bool:
    written = set()
    for node in function.nodes:
        written.update(node.state_variables_written)
    return any(sv in written for sv in svs)


class DelegationNotRevokedOnWithdraw(AbstractDetector):
    """Flag withdraw/unstake paths that leave delegation pointing at the old user."""

    ARGUMENT = "delegation-not-revoked-on-withdraw"
    HELP = (
        "withdraw/unstake/exit path does not clear delegates[user] - "
        "delegated voting weight persists after withdrawal"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Delegation Not Revoked On Withdraw"
    WIKI_DESCRIPTION = (
        "A staking / veToken contract writes `delegates[user]` when the user "
        "stakes or explicitly delegates, but the `withdraw` / `unstake` / "
        "`exit` path does not reset that mapping entry. Voting weight and "
        "reward boosts derived from the delegation continue to apply after "
        "the user has fully withdrawn. Reported in Virtuals Protocol."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
mapping(address => address) public delegates;
mapping(address => uint256) public stakedOf;

function stake(uint256 a, address d) external {
    stakedOf[msg.sender] += a;
    delegates[msg.sender] = d;
}

function withdraw(uint256 a) external {
    stakedOf[msg.sender] -= a; // BUG: delegates[msg.sender] not cleared
}
```
After full withdrawal, `delegates[msg.sender]` still points to the attacker's
delegate, who keeps inflated voting weight."""
    WIKI_RECOMMENDATION = (
        "On full withdrawal, also clear the delegation: "
        "`delete delegates[msg.sender];` or reset the per-user checkpoint."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            dvars = _delegate_vars(contract)
            if not dvars:
                continue
            bvars = _balance_vars(contract)
            if not bvars:
                continue

            # Confirm there is a stake function that writes a delegate var.
            stake_writes_delegate = False
            for f in contract.functions_and_modifiers_declared:
                if f.is_constructor:
                    continue
                nm = f.name or ""
                if not _STAKE_RE.search(nm):
                    continue
                if _writes_any(f, dvars):
                    stake_writes_delegate = True
                    break
            if not stake_writes_delegate:
                continue

            for f in contract.functions_and_modifiers_declared:
                if f.is_constructor:
                    continue
                nm = f.name or ""
                if not _WITHDRAW_RE.search(nm):
                    continue
                if not _writes_any(f, bvars):
                    continue
                if _writes_any(f, dvars):
                    continue
                info: DETECTOR_INFO = [
                    f,
                    " mutates stake/balance but does not clear delegates[user]"
                    " - delegation persists after withdrawal.\n",
                ]
                results.append(self.generate_result(info))

        return results
